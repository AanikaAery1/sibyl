"""Approval timeouts (API.md §6.5; D13, D22).

A pending approval past ``expires_at`` is resolved by its ``timeout_policy``:

* ``hold`` → approval ``expired``, saga ``cancelled``, routing ``awaiting_approval → degraded``
  (trigger ``approval_timeout``, actor ``system``);
* ``fail_safe`` → approval ``expired``, saga back to ``running`` at ``write_routing`` and driven
  on: routing ``awaiting_approval → failed_over`` (trigger ``approval_timeout``).

D22 layer (b): the worker re-evaluates at timeout and forces ``hold`` for a tier-1 agent with
PII/residency exposure regardless of the stored value (``timeout_policy_applied:
hold_forced_d22``). A human-requested approval (four-eyes from ``active``) has no timeout edge
into ``failed_over``, so it always ends as ``hold`` without a routing change.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord
from ...core.outbox import OutboxMessage
from ..saga import engine, routing
from ..saga.model import SYSTEM, Env

log = logging.getLogger("sibyl.approvals")
_DUE_SQL = """
SELECT a.id FROM sibyl.approval a
 WHERE a.tenant_id = $1 AND a.state = 'pending' AND a.expires_at <= now()
 ORDER BY a.expires_at LIMIT $2
"""
_LOCK_SQL = """
SELECT a.*, sibyl.agent_pii_exposed(a.tenant_id, a.agent_id) AS pii
  FROM sibyl.approval a
 WHERE a.tenant_id = $1 AND a.id = $2 AND a.state = 'pending' AND a.expires_at <= now()
 FOR UPDATE SKIP LOCKED
"""


@dataclass(frozen=True)
class Expired:
    approval_id: UUID
    policy_applied: str


def applied_policy(approval: Any) -> str:
    """``hold``, ``fail_safe`` or ``hold_forced_d22`` (forced at insert or re-evaluated now)."""
    evidence = approval["evidence"] or {}
    if evidence.get("timeout_policy_applied") == "hold_forced_d22":
        return "hold_forced_d22"
    stored = str(approval["timeout_policy"])
    if stored == "fail_safe" and int(approval["tier"]) == 1 and approval["pii"]:
        return "hold_forced_d22"
    return stored


async def expire_one(conn: Any, env: Env, tenant: UUID, approval_id: UUID) -> Expired | None:
    approval = await conn.fetchrow(_LOCK_SQL, tenant, approval_id)
    if approval is None:
        return None
    saga = await engine.load(conn, tenant, approval["failover_id"])
    state = await routing.state_of(conn, tenant, approval["agent_id"])
    policy = applied_policy(approval)
    awaiting = state is not None and state["state"] == "awaiting_approval"
    if policy == "fail_safe" and not awaiting:
        policy = "hold"
    await conn.execute(
        "UPDATE sibyl.approval SET state = 'expired', resolved_by_timeout = true"
        " WHERE tenant_id = $1 AND id = $2",
        tenant,
        approval_id,
    )
    if policy == "fail_safe" and saga is not None and saga["state"] == "waiting_approval":
        saga = await engine.save(
            conn,
            env,
            tenant,
            saga,
            state="running",
            step="write_routing",
            claimed_by=env.worker_id,
            claim_lock_until=await engine.claim_lock(conn),
            step_results=engine.with_result(saga, "approval_timeout", {"policy": "fail_safe"}),
        )
        for _ in range(4):
            saga, progress = await engine.advance(conn, env, tenant, saga)
            if progress.status != "continue":
                break
    else:
        if awaiting:
            await routing.apply(
                conn,
                tenant,
                approval["agent_id"],
                expected_from="awaiting_approval",
                to_state="degraded",
                trigger="approval_timeout",
                actor=SYSTEM,
                idempotency_key=f"approval:{approval_id}:timeout",
                audit_action="route.changed",
                failover_id=approval["failover_id"],
                approval_id=approval_id,
                reason=f"approval timed out ({policy})",
            )
        if saga is not None and saga["state"] in ("pending", "running", "waiting_approval"):
            saga = await engine.save(
                conn,
                env,
                tenant,
                saga,
                step_results=engine.with_result(saga, "approval_timeout", {"policy": policy}),
            )
            await engine.finish(conn, env, tenant, saga, "cancelled", "approval_timeout")
    await env.audit.append(
        conn,
        tenant,
        AuditRecord(
            action="approval.expired",
            actor_type="system",
            resource_type="approval",
            resource_id=approval_id,
            detail={
                "approval_id": str(approval_id),
                "timeout_policy_applied": policy,
                "incident_id": str(approval["failover_id"]),
            },
        ),
    )
    await env.outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "approval.expired",
            "approval",
            approval_id,
            {
                "approval_id": str(approval_id),
                "incident_id": str(approval["failover_id"]),
                "timeout_policy_applied": policy,
            },
        ),
    )
    return Expired(approval_id, policy)


async def run_tenant(db: Any, env: Env, tenant: UUID, *, limit: int = 50) -> list[Expired]:
    async with db.tenant_tx(tenant, readonly=True) as conn:
        due = [r["id"] for r in await conn.fetch(_DUE_SQL, tenant, limit)]
    out: list[Expired] = []
    for approval_id in due:
        try:
            async with db.tenant_tx(tenant) as conn:
                await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
                done = await expire_one(conn, env, tenant, approval_id)
        except Exception:
            log.exception("approval %s timeout could not be applied", approval_id)
            continue
        if done is not None:
            out.append(done)
    return out
