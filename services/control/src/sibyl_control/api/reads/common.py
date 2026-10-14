"""Read-route helpers: agent-scoped object rules, time windows, row views (lane V).

Every per-agent read loads the agent first and runs ``ctx.check`` with its group (and, where the
contract declares ``bound_agent``, its id), so an out-of-group agent or another agent than a key
is bound to is 404, never 403, and unknown ids are indistinguishable from foreign ones.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.authz import NOT_APPLICABLE
from ...core.problems import ProblemError
from ..auth.common import iso
from ..deps import AuthContext


async def agent_in_scope(conn: Any, ctx: AuthContext, agent_id: UUID) -> Any:
    """The agent row after the ``group`` (and ``bound_agent``) object rules; 404 otherwise."""
    row = await conn.fetchrow(
        "SELECT id, slug, agent_group_id, tier FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
        ctx.tenant_id,
        agent_id,
    )
    if row is None:
        raise ProblemError("not_found")
    bound = "bound_agent" in ctx.op.object_rules
    ctx.check(
        resource_group_id=row["agent_group_id"], resource_agent_id=row["id"] if bound else None
    )
    return row


def group_scope(ctx: AuthContext) -> list[UUID] | None:
    """SQL filter for list reads: ``None`` = tenant-wide, else the caller's groups."""
    groups = ctx.group_filter()
    return None if groups is None else list(groups)


def mark_group_not_applicable(ctx: AuthContext) -> None:
    ctx.check(resource_group_id=NOT_APPLICABLE)


def window(
    start: datetime | None,
    end: datetime | None,
    *,
    now: datetime,
    default: timedelta,
    maximum: timedelta,
    code: str = "range_too_wide",
) -> tuple[datetime, datetime]:
    end = end or now
    start = start or end - default
    if start >= end:
        raise ProblemError("validation_failed", "from must be before to")
    if end - start > maximum:
        raise ProblemError(code, f"the window may span at most {maximum}")
    return start, end


def s(value: Any) -> str | None:
    return str(value) if value is not None else None


def transition_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "failover_id": s(row["failover_id"]),
        "from_state": row["from_state"],
        "to_state": row["to_state"],
        "from_target": row["from_target"],
        "to_target": row["to_target"],
        "trigger": row["trigger"],
        "actor_kind": row["actor_kind"],
        "actor_user_id": s(row["actor_user_id"]),
        "rule_codes": list(row["rule_codes"] or []),
        "alert_ids": [str(a) for a in row["alert_ids"] or []],
        "health_snapshot_id": s(row["health_snapshot_id"]),
        "approval_id": s(row["approval_id"]),
        "inverse_of": s(row["inverse_of"]),
        "undone_by": s(row["undone_by"]),
        "operator_hold_until": iso(row["operator_hold_until"]),
        "routing_version": row["routing_version"],
        "reason": row["reason"],
        "audit_seq": row["audit_seq"],
        "created_at": iso(row["created_at"]),
    }


def approval_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "incident_id": s(row["failover_id"]),
        "agent_id": str(row["agent_id"]),
        "requested_action": row["requested_action"],
        "tier": row["tier"],
        "requested_by_kind": row["requested_by_kind"],
        "requested_by_user_id": s(row["requested_by_user_id"]),
        "alert_id": s(row["alert_id"]),
        "evidence": row["evidence"] or {},
        "risk": row["risk"],
        "expires_at": iso(row["expires_at"]),
        "timeout_policy": row["timeout_policy"],
        "state": row["state"],
        "decided_by_user_id": s(row["decided_by_user_id"]),
        "decided_at": iso(row["decided_at"]),
        "created_at": iso(row["created_at"]),
    }


def trace_hex(value: Any) -> str | None:
    return value.hex if isinstance(value, UUID) else None


def event_view(row: Any) -> dict[str, Any]:
    payload = None
    if row["payload_ref_id"] is not None:
        payload = {
            "id": str(row["payload_ref_id"]),
            "kind": row["pr_kind"],
            "sha256": bytes(row["payload_sha256"]).hex() if row["payload_sha256"] else None,
            "size_bytes": row["payload_bytes"],
            "state": row["pr_state"],
        }
    return {
        "event_id": str(row["event_id"]),
        "event_type": row["event_type"],
        "ts": iso(row["ts"]),
        "agent_id": s(row["agent_id"]),
        "status": row["status"],
        "trace_id": trace_hex(row["trace_id"]),
        "span_id": bytes(row["span_id"]).hex() if row["span_id"] is not None else None,
        "task_id": s(row["task_id"]),
        "call_id": s(row["call_id"]),
        "provider": row["provider"],
        "model": row["model"],
        "attrs": row["attrs"] or {},
        "payload_ref": payload,
    }


def public_factors(stored: Any) -> list[dict[str, Any]]:
    """The stored factors without the engine's ``_``-prefixed bookkeeping rows (``_hysteresis``,
    ``_clamp``): they ride in ``health_snapshot.factors`` for restart resume and are stripped
    from the API (ML.md §3.6, B-04). The clamp stays derivable: ``max(0, Σ penalty - 100)``."""
    return [
        f
        for f in stored or ()
        if isinstance(f, dict) and not str(f.get("rule", "")).startswith("_")
    ]
