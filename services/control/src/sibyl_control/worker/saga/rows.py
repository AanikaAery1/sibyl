"""Saga row plumbing shared by the steps and the driver: load/save the ``failover`` row, read
its ``step_results``, the saga actor, audit and the terminal ``finish`` transition."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord
from ...core.outbox import OutboxMessage
from .model import Actor, Env, SagaError

FAILOVER_FROM = ("active", "degraded")
OPERATOR_FROM = ("active", "degraded", "failed_over")  # an operator may re-target or hand off
Row = dict[str, Any]


def allowed_from(row: Mapping[str, Any]) -> tuple[str, ...]:
    return OPERATOR_FROM if row["actor_kind"] == "human" else FAILOVER_FROM


@dataclass(frozen=True)
class Progress:
    """What happened to the saga in one step."""

    status: str  # continue | waiting | yield | done | failed | cancelled | retry | delayed
    step: str
    error: str | None = None


# --- row plumbing -----------------------------------------------------------------------------

_LOAD_SQL = "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND id = $2"


async def load(conn: Any, tenant: UUID, failover_id: UUID, *, lock: bool = True) -> Row | None:
    row = await conn.fetchrow(_LOAD_SQL + (" FOR UPDATE" if lock else ""), tenant, failover_id)
    return dict(row) if row is not None else None


def results(row: Mapping[str, Any]) -> dict[str, Any]:
    return dict(row.get("step_results") or {})


def opened(row: Mapping[str, Any]) -> dict[str, Any]:
    return dict(results(row).get("open") or {})


def saga_actor(row: Mapping[str, Any]) -> Actor:
    info = opened(row)
    return Actor(
        kind=row["actor_kind"],
        user_id=row.get("requested_by_user_id"),
        rule_id=_uuid(info.get("actor_rule_id")),
        key_id=row.get("actor_key_id"),
        session_id=_uuid(info.get("actor_session_id")),
    )


def _uuid(value: Any) -> UUID | None:
    return None if value in (None, "") else UUID(str(value))


async def save(conn: Any, env: Env, tenant: UUID, row: Row, **changes: Any) -> Row:
    """Persist ``changes`` on the saga row; emits ``incident.updated`` when the state moves."""
    if not changes:
        return row
    columns = list(changes)
    sets = ", ".join(f"{c} = ${i + 3}" for i, c in enumerate(columns))
    updated = await conn.fetchrow(
        f"UPDATE sibyl.failover SET {sets} WHERE tenant_id = $1 AND id = $2 RETURNING *",  # noqa: S608
        tenant,
        row["id"],
        *[changes[c] for c in columns],
    )
    new = dict(updated)
    if new["state"] != row["state"] or new["step"] != row["step"]:
        await env.outbox.emit(
            conn,
            tenant,
            OutboxMessage.for_event(
                "incident.updated",
                "failover",
                new["id"],
                {
                    "incident_id": str(new["id"]),
                    "agent_id": str(new["agent_id"]),
                    "state": new["state"],
                    "step": new["step"],
                },
            ),
        )
    return new


def with_result(row: Mapping[str, Any], step: str, value: Any) -> dict[str, Any]:
    out = results(row)
    out[step] = value
    return out


async def _audit(
    conn: Any,
    env: Env,
    tenant: UUID,
    action: str,
    actor: Actor,
    *,
    resource_type: str,
    resource_id: UUID | None,
    detail: Mapping[str, Any],
    reason: str | None = None,
) -> None:
    await env.audit.append(
        conn,
        tenant,
        AuditRecord(
            action=action,
            **actor.audit_fields(),
            resource_type=resource_type,
            resource_id=resource_id,
            reason=reason,
            detail=detail,
            request_id=env.request_id,
        ),
    )


# --- terminal transitions ---------------------------------------------------------------------


async def cancel_approval(conn: Any, tenant: UUID, approval_id: UUID | None) -> None:
    if approval_id is None:
        return
    await conn.execute(
        "UPDATE sibyl.approval SET state = 'cancelled' WHERE tenant_id = $1 AND id = $2"
        " AND state = 'pending'",
        tenant,
        approval_id,
    )


async def finish(
    conn: Any, env: Env, tenant: UUID, row: Row, state: str, error: str | None = None
) -> Row:
    await cancel_approval(conn, tenant, row.get("approval_id"))
    return await save(
        conn,
        env,
        tenant,
        row,
        state=state,
        error=error,
        finished_at=await conn.fetchval("SELECT now()"),
        claim_lock_until=None,
    )


async def _agent(conn: Any, tenant: UUID, agent_id: UUID) -> Row:
    row = await conn.fetchrow(
        "SELECT * FROM sibyl.agent WHERE tenant_id = $1 AND id = $2", tenant, agent_id
    )
    if row is None:
        raise SagaError("not_found", "agent is gone")
    return dict(row)


def _alerts(row: Mapping[str, Any]) -> list[UUID]:
    out = [UUID(a) for a in opened(row).get("alert_ids") or ()]
    alert = row.get("trigger_alert_id")
    if alert is not None and alert not in out:
        out.insert(0, alert)
    return out
