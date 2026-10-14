"""``/kill-switches``: list, pull (session or break-glass key), release (step-up human), acks.

Pull is the single break-glass route (D20): a ``killswitch:pull``-only key may call it and
nothing else (the guard refuses it elsewhere with ``break_glass_key_misuse``). Its numeric caps
(3 / 10 min per key, 6 / h per tenant) answer 429 ``break_glass_rate_limited``, audited. A human
pull needs a fresh step-up (conditional step-up decided here); OIDC principals have no session
and therefore never pass it.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.audit import AuditRecord, audit_actor
from ...core.authz import PrincipalKind
from ...core.problems import ProblemError
from ...core.ratelimit import POLICIES
from ..contract import API_PREFIX
from ..deps import AuthContext, client_ip, guard, write_denial
from ..incidents.common import actor_of, api_env, audited, receipt_since
from ..incidents.models import KillSwitchAckCreate, KillSwitchCreate, ReasonBody
from ..incidents.views import kill_switch_views
from ..registry._kit import (
    Outcome,
    PageQuery,
    keyset_page,
    run_read,
    run_write,
    services_of,
)
from . import service

router = APIRouter()
BREAK_GLASS_POLICIES = ("break_glass_key", "break_glass_tenant")


async def _break_glass_limits(ctx: AuthContext) -> None:
    principal = ctx.principal
    assert principal is not None
    services = services_of(ctx)
    keys = (f"breakglass:key:{principal.id}", f"breakglass:tenant:{principal.tenant_id}")
    for name, key in zip(BREAK_GLASS_POLICIES, keys, strict=True):
        decision = await services.rate_limiter.hit(key, POLICIES[name])
        if not decision.allowed:
            if ctx.request is not None:
                await write_denial(services, ctx.request, principal, ctx.op.scope)
            raise ProblemError(
                "break_glass_rate_limited",
                extensions={"retry_after_s": decision.retry_after_s},
                headers=decision.headers(),
            )


@router.get(API_PREFIX + "/kill-switches")
async def list_kill_switches(
    ctx: Annotated[AuthContext, Depends(guard("listKillSwitches"))],
    state: Annotated[str | None, Query(pattern="^(pulled|released)$")] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    page = PageQuery.of(limit, cursor, state=state)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.kill_switch WHERE tenant_id = $1"
        if state is not None:
            args.append(state)
            sql += f" AND state = ${len(args)}"
        outcome = await keyset_page(
            conn, ctx, select=sql, args=args, page=page, descending=True, serialize=lambda r: r
        )
        outcome.body["data"] = await kill_switch_views(conn, ctx.tenant_id, outcome.body["data"])
        return outcome

    return await run_read(ctx, work)


@router.post(API_PREFIX + "/kill-switches", status_code=201)
async def pull_kill_switch(
    body: KillSwitchCreate,
    ctx: Annotated[AuthContext, Depends(guard("pullKillSwitch"))],
) -> Response:
    principal = ctx.principal
    assert principal is not None
    breaking = principal.is_break_glass
    ctx.object_rule_checked("break_glass")
    ctx.step_up_if(principal.kind is not PrincipalKind.API_KEY)
    ctx.object_rule_checked("second_owner_tenant_kill")
    if breaking:
        await _break_glass_limits(ctx)
    ip = client_ip(ctx.request) if ctx.request is not None else "unknown"

    async def write(conn: Any, start: int) -> Outcome:
        ks = await service.pull(
            conn,
            api_env(ctx),
            ctx.tenant_id,
            actor=actor_of(ctx),
            roles=principal.roles,
            scope_kind=body.scope_kind,
            scope_id=body.scope_id,
            reason=body.reason.strip(),
            client_ip=ip,
        )
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.kill_switch WHERE tenant_id = $1 AND id = $2", ctx.tenant_id, ks
        )
        view = (await kill_switch_views(conn, ctx.tenant_id, [row]))[0]
        return Outcome(view, status=201, receipt=await receipt_since(conn, ctx.tenant_id, start))

    return await run_write(ctx, audited(ctx, write), idempotent=True)


@router.post(API_PREFIX + "/kill-switches/{kill_switch_id}/release")
async def release_kill_switch(
    kill_switch_id: UUID,
    body: ReasonBody,
    ctx: Annotated[AuthContext, Depends(guard("releaseKillSwitch"))],
) -> Response:
    async def write(conn: Any, start: int) -> Outcome:
        await service.release(
            conn,
            api_env(ctx),
            ctx.tenant_id,
            kill_switch_id,
            actor=actor_of(ctx),
            reason=body.reason.strip(),
        )
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.kill_switch WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            kill_switch_id,
        )
        view = (await kill_switch_views(conn, ctx.tenant_id, [row]))[0]
        return Outcome(view, receipt=await receipt_since(conn, ctx.tenant_id, start))

    return await run_write(ctx, audited(ctx, write), idempotent=True)


@router.post(API_PREFIX + "/kill-switches/{kill_switch_id}/acks", status_code=201)
async def ack_kill_switch(
    kill_switch_id: UUID,
    body: KillSwitchAckCreate,
    ctx: Annotated[AuthContext, Depends(guard("ackKillSwitch"))],
) -> Response:
    principal = ctx.principal
    assert principal is not None

    async def write(conn: Any, start: int) -> Outcome:
        found = await conn.fetchval(
            "SELECT 1 FROM sibyl.kill_switch WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            kill_switch_id,
        )
        if not found:
            raise ProblemError("not_found")
        inserted = await conn.fetchrow(
            "INSERT INTO sibyl.kill_switch_ack (tenant_id, kill_switch_id, gateway_id,"
            " snapshot_version, applied_at) VALUES ($1, $2, $3, $4, now())"
            " ON CONFLICT DO NOTHING RETURNING applied_at",
            ctx.tenant_id,
            kill_switch_id,
            body.gateway_id,
            body.snapshot_version,
        )
        row = inserted or await conn.fetchrow(
            "SELECT applied_at FROM sibyl.kill_switch_ack WHERE tenant_id = $1 AND"
            " kill_switch_id = $2"
            " AND gateway_id = $3 AND snapshot_version = $4",
            ctx.tenant_id,
            kill_switch_id,
            body.gateway_id,
            body.snapshot_version,
        )
        receipt = None
        if inserted is not None:
            receipt = await services_of(ctx).audit.append(
                conn,
                ctx.tenant_id,
                AuditRecord(
                    # The gateway key acts in its own name: api_key + its key id (G0-6).
                    action="killswitch.applied",
                    **audit_actor(principal).fields(),
                    resource_type="kill_switch",
                    resource_id=kill_switch_id,
                    detail={
                        "gateway_id": body.gateway_id,
                        "snapshot_version": body.snapshot_version,
                        "applied_at": row["applied_at"].isoformat(),
                    },
                ),
            )
        view = {
            "kill_switch_id": str(kill_switch_id),
            "gateway_id": body.gateway_id,
            "snapshot_version": body.snapshot_version,
            "applied_at": row["applied_at"].isoformat().replace("+00:00", "Z"),
        }
        return Outcome(view, status=201 if inserted is not None else 200, receipt=receipt)

    return await run_write(ctx, audited(ctx, write), idempotent=True)
