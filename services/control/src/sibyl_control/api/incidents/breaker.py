"""``POST /agents/{agent_id}/preemptive-breaker/clear`` (ruling B19).

An undo never clears the per-agent pre-emptive breaker: an undone automation is evidence toward a
trip. Clearing is a deliberate operation: scope ``routing:override``, step-up always (the guard),
the ``group`` object rule (an agent outside the caller's groups is 404) and ``tenant_role`` (only
a tenant-scoped grant may clear; a group-limited Engineer gets 403), a reason, and the audit row
``preemptive.breaker_cleared``. The state change and the audit append are the predict lane's
``clear_breaker`` (one implementation; it takes ``sibyl.audit_lock`` before the agent row).
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from ...core.audit import audit_actor
from ...core.problems import ProblemError
from ...worker.predict.breaker import clear_breaker
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, jsonable, load_agent, request_uuid, run_write, services_of
from .models import PreemptiveBreakerClear

router = APIRouter()
OP_ID = "clearPreemptiveBreaker"
TENANT_ROLE_RULE = "tenant_role"


def _require_tenant_role(ctx: AuthContext) -> None:
    """``tenant_role``: the caller's ``routing:override`` grant must be tenant-wide."""
    ctx.object_rule_checked(TENANT_ROLE_RULE)
    grant = ctx.grant
    if grant is None or grant.group_ids is not None:
        raise ProblemError(
            "forbidden",
            "clearing the pre-emptive breaker needs a tenant-scoped role",
            audit_denied=True,
        )


@router.post(API_PREFIX + "/agents/{agent_id}/preemptive-breaker/clear")
async def clear_preemptive_breaker(
    agent_id: UUID,
    body: PreemptiveBreakerClear,
    ctx: Annotated[AuthContext, Depends(guard(OP_ID))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        principal = ctx.principal
        if principal is None or not principal.is_human:  # pragma: no cover - session-only route
            raise ProblemError("forbidden", audit_denied=True)
        await load_agent(conn, ctx, agent_id, lock=True)  # group rule (404 outside)
        _require_tenant_role(ctx)
        cleared = await clear_breaker(
            conn,
            ctx.tenant_id,
            agent_id,
            actor=audit_actor(principal),
            reason=body.reason,
            request_id=request_uuid(ctx),
            audit=services_of(ctx).audit,
        )
        if cleared is None:
            raise ProblemError("invalid_transition", "the pre-emptive breaker is not tripped")
        result = jsonable(
            {
                "agent_id": agent_id,
                "tripped_at": cleared.tripped_at,
                "cleared_at": cleared.cleared_at,
                "cleared_by_user_id": principal.id,
            }
        )
        return Outcome(result, receipt=cleared.receipt)

    return await run_write(ctx, work, idempotent=True)
