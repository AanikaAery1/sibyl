"""Shared plumbing for the lane S routes (incidents, approvals, kill switches, queue).

Handlers run through the registry kit (``run_read`` / ``run_write``: one tenant transaction,
audit lock first, fenced Idempotency-Key, ``access.denied`` on refusals). Saga refusals
(``SagaError``) become RFC 9457 problems so the whole request transaction rolls back. Audit rows
written inside ``routing_apply`` do not pass through the api's ``AuditWriter``; the receipt
header is therefore taken from the tenant's chain head when the request appended anything.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID

from ...core.audit import AuditReceipt, audit_actor
from ...core.problems import ProblemError
from ...worker.saga.model import Actor, Env, SagaError
from ..deps import AuthContext
from ..registry._kit import Outcome, request_uuid, services_of

HEAD_SQL = "SELECT seq, hash FROM sibyl.audit_chain_head WHERE tenant_id = $1"


def problem(exc: SagaError) -> ProblemError:
    return ProblemError(exc.code, exc.detail, extensions=exc.extensions or None)


def api_env(ctx: AuthContext) -> Env:
    """The request's saga ``Env``; demo mode and the saga gates come from ``Settings`` (an app
    built without Settings, as in handler tests, keeps the Settings defaults)."""
    services = services_of(ctx)
    settings = services.settings
    gates: dict[str, Any] = {}
    if settings is not None:
        gates = {
            "demo_mode": settings.demo,
            "automation_band": settings.predicted_automation_band,
            "failback_ramp": settings.failback_ramp,
        }
    return Env(
        worker_id="api",
        can_build_handoff=False,
        completion_audit=False,
        audit=services.audit,
        outbox=services.outbox,
        request_id=request_uuid(ctx),
        **gates,
    )


def actor_of(ctx: AuthContext) -> Actor:
    """The principal as a saga actor, attributed by ``core.audit.audit_actor`` (G0-4/G0-6:
    every API key acts as ``api_key`` with its key id)."""
    principal = ctx.principal
    assert principal is not None
    return Actor.of(audit_actor(principal))


async def head_seq(conn: Any, tenant: UUID) -> int:
    row = await conn.fetchrow(HEAD_SQL, tenant)
    return int(row["seq"]) if row is not None else -1


async def receipt_since(conn: Any, tenant: UUID, start: int) -> AuditReceipt | None:
    row = await conn.fetchrow(HEAD_SQL, tenant)
    if row is None or int(row["seq"]) <= start:
        return None
    return AuditReceipt(tenant, int(row["seq"]), bytes(row["hash"]))


def audited(
    ctx: AuthContext, body: Callable[[Any, int], Awaitable[Outcome]]
) -> Callable[[Any], Awaitable[Outcome]]:
    """Wrap a write body: record the chain head first, attach the receipt when rows were added,
    and turn saga refusals into problems."""

    async def work(conn: Any) -> Outcome:
        start = await head_seq(conn, ctx.tenant_id)
        try:
            outcome = await body(conn, start)
        except SagaError as exc:
            raise problem(exc) from None
        if outcome.receipt is None:
            outcome.receipt = await receipt_since(conn, ctx.tenant_id, start)
        return outcome

    return work


def require_reason(reason: str | None) -> str:
    text = (reason or "").strip()
    if len(text) < 10:
        raise ProblemError("validation_failed", "reason must be at least 10 characters")
    return text
