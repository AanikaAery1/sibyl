"""``sibyl.routing_apply()`` (R1, the only writer of routing state) and the reads around it.

Every routing change lane S makes goes through ``apply``: it carries the idempotency key, the
actor columns, the evidence and the audit action, and ``routing_apply`` appends the audit row in
the same transaction. Database refusals become ``SagaError`` with the problem code
(``invalid_transition``, ``stale_precondition``, ``operator_hold``, ``idempotency_key_reuse``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import asyncpg

from ...core.db import is_retryable
from ...core.problems import problem_from_db_error
from .model import Actor, SagaError

_APPLY_SQL = (
    "SELECT transition_id, routing_version, audit_seq FROM sibyl.routing_apply("
    "$1::uuid, $2::uuid, $3::uuid, $4::text, $5::text, $6::jsonb, $7::text, $8::text, $9::uuid,"
    " $10::uuid, $11::text[], $12::uuid[], $13::uuid, $14::uuid, $15::uuid, $16::timestamptz,"
    " $17::smallint, $18::text, $19::text, $20::text, $21::jsonb, NULL::bytea, $22::uuid,"
    " $23::uuid, $24::uuid)"
)
STATE_SQL = "SELECT * FROM sibyl.routing_state WHERE tenant_id = $1 AND agent_id = $2"


@dataclass(frozen=True)
class Applied:
    transition_id: UUID
    routing_version: int
    audit_seq: int


def target_json(
    kind: str,
    *,
    provider_id: UUID | None = None,
    model_id: UUID | None = None,
    agent_id: UUID | None = None,
    step_id: UUID | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "provider_id": None if provider_id is None else str(provider_id),
        "model_id": None if model_id is None else str(model_id),
        "agent_id": None if agent_id is None else str(agent_id),
        "step_id": None if step_id is None else str(step_id),
    }


def db_code(exc: BaseException) -> str:
    return problem_from_db_error(exc).code


async def apply(
    conn: Any,
    tenant: UUID,
    agent: UUID,
    *,
    expected_from: str | None,
    to_state: str,
    trigger: str,
    actor: Actor,
    idempotency_key: str,
    audit_action: str,
    failover_id: UUID | None = None,
    target: Mapping[str, Any] | None = None,
    rule_codes: Sequence[str] = (),
    alert_ids: Sequence[UUID] = (),
    health_snapshot_id: UUID | None = None,
    approval_id: UUID | None = None,
    inverse_of: UUID | None = None,
    operator_hold_until: datetime | None = None,
    canary_pct: int | None = None,
    reason: str | None = None,
    audit_detail: Mapping[str, Any] | None = None,
    request_id: UUID | None = None,
) -> Applied:
    """One ``routing_apply`` call inside a savepoint, so a refusal leaves the caller's
    transaction usable (the saga records the failure instead of aborting). Transient errors
    (40P01 / 40001) propagate unchanged so the whole transaction is retried."""
    try:
        async with conn.transaction():
            row = await conn.fetchrow(
                _APPLY_SQL,
                tenant,
                agent,
                failover_id,
                expected_from,
                to_state,
                dict(target) if target is not None else None,
                trigger,
                actor.kind,
                actor.user_id if actor.kind == "human" else None,
                actor.rule_id if actor.kind in ("rule", "policy") else None,
                list(rule_codes),
                list(alert_ids),
                health_snapshot_id,
                approval_id,
                inverse_of,
                operator_hold_until,
                canary_pct,
                reason,
                idempotency_key,
                audit_action,
                dict(audit_detail) if audit_detail else None,
                actor.session_id if actor.kind == "human" else None,
                request_id,
                actor.key_id if actor.kind == "api_key" else None,
            )
    except asyncpg.PostgresError as exc:
        if is_retryable(exc):
            # Deadlock / serialization failure: let the caller's transaction retry as a whole
            # (``run_in_tenant_tx`` in the api, the next tick in the worker), never fail the saga.
            raise
        raise SagaError(db_code(exc), "routing_apply refused the transition") from None
    return Applied(row["transition_id"], int(row["routing_version"]), int(row["audit_seq"]))


async def state_of(conn: Any, tenant: UUID, agent: UUID) -> Any:
    return await conn.fetchrow(STATE_SQL, tenant, agent)


async def hold_active(conn: Any, tenant: UUID, agent: UUID) -> datetime | None:
    """``operator_hold_until`` when it is still in the future (D21)."""
    until: datetime | None = await conn.fetchval(
        "SELECT operator_hold_until FROM sibyl.routing_state WHERE tenant_id = $1"
        " AND agent_id = $2 AND operator_hold_until > now()",
        tenant,
        agent,
    )
    return until
