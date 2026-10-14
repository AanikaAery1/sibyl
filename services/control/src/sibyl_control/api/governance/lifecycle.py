"""Erasure / legal-hold rules shared by the erasure and hold routes (API.md §10.4, D17, D26).

* Subject identifiers are taken once and hashed ``sha256(SIBYL_SUBJECT_SALT ‖ identifier)``;
  only the hash is stored or compared, never echoed (security-auditor §7.6).
* Which holds block a request is decided by ``sibyl.erasure_blocking_holds`` (the same
  predicate the worker's phases re-check), so the api and the database cannot disagree.
* Placing a hold moves intersecting ``requested`` / ``approved`` requests to ``hold_blocked``
  (``erasure.blocked_by_hold``, actor ``system``: the automatic hold check); releasing one
  re-evaluates every ``hold_blocked`` request at once and returns those no longer blocked to
  ``requested`` (a fresh four-eyes approval is needed; there is no ``hold_blocked → approved``
  edge without a successful re-check, §10.4 rule 2). Neither triggers a retention sweep.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord
from ...core.outbox import OutboxMessage
from ...core.problems import ProblemError
from ..deps import AuthContext
from ..registry._kit import services_of

TERMINAL = ("completed", "rejected", "cancelled")
_BLOCKING_SQL = "SELECT sibyl.erasure_blocking_holds($1, $2, $3, $4::uuid[])"
_retained: list[str] = []


def subject_hash(ctx: AuthContext, identifier: str) -> str:
    settings = services_of(ctx).settings
    salt = settings.subject_salt if settings is not None else None
    if salt is None or not salt.get_secret_value():
        raise ProblemError("service_unavailable", "SIBYL_SUBJECT_SALT is not configured")
    material = salt.get_secret_value().encode() + identifier.encode()
    return "subject:" + hashlib.sha256(material).hexdigest()


def request_agents(row: Any) -> list[UUID]:
    if row["scope_kind"] == "agent":
        return [UUID(row["scope_ref"])]
    if row["scope_kind"] == "subject":
        affected = row["affected_objects"] or {}
        if isinstance(affected, str):
            affected = json.loads(affected)
        subject_set = affected.get("subject_set") or {}
        return [UUID(a) for a in subject_set.get("agent_ids", [])]
    return []


async def blocking_holds(
    conn: Any, tenant: UUID, scope_kind: str, scope_ref: str | None, agents: list[UUID]
) -> list[UUID]:
    found = await conn.fetchval(_BLOCKING_SQL, tenant, scope_kind, scope_ref, agents)
    return list(found or [])


async def retained_tables(conn: Any) -> list[str]:
    if not _retained:
        rows = await conn.fetch(
            "SELECT table_name FROM sibyl.erasure_cascade() WHERE action = 'keep' ORDER BY ord"
        )
        _retained.extend([r["table_name"] for r in rows] + ["tenant"])
    return list(_retained)


async def step_event(ctx: AuthContext, conn: Any, request_id: UUID, state: str) -> None:
    message = OutboxMessage.for_event(
        "erasure.step",
        "erasure",
        request_id,
        {"tenant_id": str(ctx.tenant_id), "request_id": str(request_id), "state": state},
    )
    await services_of(ctx).outbox.emit(conn, ctx.tenant_id, message)


async def system_audit(
    ctx: AuthContext, conn: Any, action: str, resource_id: UUID, detail: dict[str, Any]
) -> None:
    record = AuditRecord(
        action=action,
        actor_type="system",
        resource_type="erasure_request",
        resource_id=resource_id,
        detail=detail,
    )
    await services_of(ctx).audit.append(conn, ctx.tenant_id, record)


async def block_on_new_hold(ctx: AuthContext, conn: Any) -> list[UUID]:
    """After a hold is placed: requested/approved requests it intersects become hold_blocked."""
    tenant = ctx.tenant_id
    blocked: list[UUID] = []
    rows = await conn.fetch(
        "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1"
        " AND state IN ('requested', 'approved') ORDER BY created_at FOR UPDATE",
        tenant,
    )
    for row in rows:
        holds = await blocking_holds(
            conn, tenant, row["scope_kind"], row["scope_ref"], request_agents(row)
        )
        if not holds:
            continue
        await conn.execute(
            "UPDATE sibyl.erasure_request SET state = 'hold_blocked', blocking_hold_ids = $3,"
            " hold_check_at = now() WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
            holds,
        )
        await system_audit(
            ctx,
            conn,
            "erasure.blocked_by_hold",
            row["id"],
            {"request_id": str(row["id"]), "hold_ids": [str(h) for h in holds]},
        )
        await step_event(ctx, conn, row["id"], "hold_blocked")
        blocked.append(row["id"])
    return blocked


async def unblock_on_release(ctx: AuthContext, conn: Any) -> list[UUID]:
    """After a hold is released: re-check every hold_blocked request immediately."""
    tenant = ctx.tenant_id
    reopened: list[UUID] = []
    rows = await conn.fetch(
        "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1 AND state = 'hold_blocked'"
        " ORDER BY created_at FOR UPDATE",
        tenant,
    )
    for row in rows:
        holds = await blocking_holds(
            conn, tenant, row["scope_kind"], row["scope_ref"], request_agents(row)
        )
        if holds:
            await conn.execute(
                "UPDATE sibyl.erasure_request SET blocking_hold_ids = $3, hold_check_at = now()"
                " WHERE tenant_id = $1 AND id = $2",
                tenant,
                row["id"],
                holds,
            )
            continue
        await conn.execute(
            "UPDATE sibyl.erasure_request SET state = 'requested', blocking_hold_ids = '{}',"
            " hold_check_at = now(), approved_by = NULL, approved_at = NULL"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
        )
        await step_event(ctx, conn, row["id"], "requested")
        reopened.append(row["id"])
    return reopened
