"""Agents: register, list, read, patch, claim, lifecycle (API.md §5.4)."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from ...core.authz import NOT_APPLICABLE
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ._kit import (
    JSON,
    Outcome,
    PageQuery,
    agent_visibility,
    audit,
    check_object,
    jsonable,
    keyset_page,
    load_agent,
    policy_changed,
    refuse,
    require_if_match,
    require_scope,
    run_read,
    run_write,
    user_id,
)
from .models import AgentCreate, AgentPatch, LifecycleChange
from .versions import insert_version
from .views import AGENT_SELECT, agent_detail, agent_etag, agent_summary, profile_hash, tools_hash

router = APIRouter()
AGENTS = API_PREFIX + "/agents"
AGENT = AGENTS + "/{agent_id}"

PATCHABLE = (
    "name",
    "description",
    "kind",
    "framework",
    "tier",
    "risk_class",
    "fail_mode",
    "agent_group_id",
    "owner_user_id",
    "business_process_id",
    "cost_center",
    "tags",
)
SNAPSHOT_FIELDS = frozenset({"tier", "fail_mode", "agent_group_id"})
APPROVE_STAGES = frozenset({"approved", "deployed", "retired"})


async def _exists(conn: Any, table: str, tenant_id: UUID, row_id: UUID | None) -> bool:
    if row_id is None:
        return True
    return bool(
        await conn.fetchval(
            f"SELECT EXISTS (SELECT 1 FROM sibyl.{table} WHERE tenant_id = $1 AND id = $2)",  # noqa: S608
            tenant_id,
            row_id,
        )
    )


async def check_refs(conn: Any, tenant_id: UUID, refs: dict[str, tuple[str, UUID | None]]) -> None:
    """422 with a pointer for every reference that does not exist in the tenant."""
    errors = [
        {"pointer": f"/{name}", "code": "unknown_reference", "message": f"no such {table}"}
        for name, (table, value) in refs.items()
        if not await _exists(conn, table, tenant_id, value)
    ]
    if errors:
        raise ProblemError("validation_failed", extensions={"errors": errors})


async def register_routing(conn: Any, ctx: AuthContext, agent_id: UUID) -> None:
    """``routing_apply(register)``: the agent's routing row starts active/primary (R1)."""
    await conn.fetchrow(
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register',"
        " 'system', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3,"
        " 'route.changed', NULL, NULL, NULL, NULL)",
        ctx.tenant_id,
        agent_id,
        f"register:{agent_id}",
    )


async def _detail_outcome(conn: Any, ctx: AuthContext, agent_id: UUID, **kw: Any) -> Outcome:
    body, etag = await agent_detail(conn, ctx.tenant_id, agent_id)
    return Outcome(body, etag=etag, **kw)


# --- list / get -----------------------------------------------------------------------------


@router.get(AGENTS, operation_id="listAgents")
async def list_agents(
    ctx: Annotated[AuthContext, Depends(guard("listAgents"))],
    limit: int | None = None,
    cursor: str | None = None,
    lifecycle: str | None = None,
    tier: Annotated[int | None, Query(ge=1, le=3)] = None,
    risk_class: str | None = None,
    group_id: UUID | None = None,
    routing_state: str | None = None,
    band: str | None = None,
    q: Annotated[str | None, Query(max_length=120)] = None,
) -> Response:
    page = PageQuery.of(
        limit,
        cursor,
        lifecycle=lifecycle,
        tier=tier,
        risk_class=risk_class,
        group_id=group_id,
        routing_state=routing_state,
        band=band,
        q=q,
    )

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM (" + AGENT_SELECT + agent_visibility(ctx, "a", args)  # noqa: S608
        for column, value in (
            ("a.lifecycle", lifecycle),
            ("a.tier", tier),
            ("a.risk_class", risk_class),
            ("a.agent_group_id", group_id),
            ("rs.state", routing_state),
            ("hs.band", band),
        ):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        if q:
            args.append(f"%{q.replace('%', r'\%').replace('_', r'\_')}%")
            sql += f" AND (a.slug ILIKE ${len(args)} OR a.name ILIKE ${len(args)})"
        sql += ") v WHERE true"
        return await keyset_page(
            conn, ctx, select=sql, args=args, page=page, serialize=agent_summary
        )

    return await run_read(ctx, work)


@router.get(AGENT, operation_id="getAgent")
async def get_agent(
    agent_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getAgent"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        return await _detail_outcome(conn, ctx, agent_id)

    return await run_read(ctx, work)


# --- register -------------------------------------------------------------------------------


@router.post(AGENTS, operation_id="registerAgent", status_code=201)
async def register_agent(
    body: AgentCreate, ctx: Annotated[AuthContext, Depends(guard("registerAgent"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        await check_object(ctx, group_id=body.agent_group_id)
        ctx.object_rule_checked("bound_agent")
        if ctx.principal is not None and ctx.principal.bound_agent_id is not None:
            raise await refuse(ctx, "forbidden", "an agent-bound key may only act as its agent")
        tenant = await conn.fetchrow(
            "SELECT max_agents, (SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1"
            " AND lifecycle <> 'retired') AS n FROM sibyl.tenant WHERE id = $1",
            ctx.tenant_id,
        )
        if tenant["n"] >= tenant["max_agents"]:
            raise ProblemError("max_agents_reached")
        await check_refs(
            conn,
            ctx.tenant_id,
            {
                "agent_group_id": ("agent_group", body.agent_group_id),
                "owner_user_id": ("app_user", body.owner_user_id),
                "business_process_id": ("business_process", body.business_process_id),
            },
        )
        agent_id: UUID = await conn.fetchval("SELECT sibyl.uuidv7()")
        await conn.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, description, kind, framework,"
            " agent_group_id, owner_user_id, business_process_id, tier, risk_class, lifecycle,"
            " fail_mode, cost_center, tags) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,"
            " $11, $12, 'proposed', $13, $14, $15)",
            ctx.tenant_id,
            agent_id,
            body.slug,
            body.name,
            body.description,
            body.kind,
            body.framework,
            body.agent_group_id,
            body.owner_user_id,
            body.business_process_id,
            body.tier,
            body.risk_class,
            body.fail_mode,
            body.cost_center,
            body.tags,
        )
        if body.version is not None:
            await insert_version(conn, ctx, agent_id, body.version)
        await conn.execute(
            "INSERT INTO sibyl.agent_identity (tenant_id, agent_id, tools_hash, updated_by)"
            " VALUES ($1, $2, $3, $4)",
            ctx.tenant_id,
            agent_id,
            tools_hash([]),
            user_id(ctx),
        )
        await register_routing(conn, ctx, agent_id)
        row = dict(
            await conn.fetchrow(
                "SELECT * FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
                ctx.tenant_id,
                agent_id,
            )
        )
        receipt = await audit(
            conn,
            ctx,
            "asset.created",
            resource_type="agent",
            resource_id=agent_id,
            resource_ref=body.slug,
            detail={
                "fields_changed": sorted(body.model_fields_set | {"slug", "tier", "fail_mode"}),
                "profile_hash": profile_hash(row),
            },
        )
        await conn.execute(
            "INSERT INTO sibyl.lifecycle_transition (tenant_id, agent_id, from_stage, to_stage,"
            " actor_user_id, reason, audit_seq) VALUES ($1, $2, NULL, 'proposed', $3,"
            " 'registered', $4)",
            ctx.tenant_id,
            agent_id,
            user_id(ctx),
            receipt.seq,
        )
        return await _detail_outcome(
            conn,
            ctx,
            agent_id,
            status=201,
            receipt=receipt,
            headers={"Location": f"{AGENTS}/{agent_id}"},
        )

    return await run_write(ctx, work, idempotent=True)


# --- patch / claim --------------------------------------------------------------------------


@router.patch(AGENT, operation_id="updateAgent")
async def update_agent(
    agent_id: UUID, body: AgentPatch, ctx: Annotated[AuthContext, Depends(guard("updateAgent"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await load_agent(conn, ctx, agent_id, lock=True)
        current = agent_etag(row)
        try:
            require_if_match(ctx, current)
        except ProblemError as exc:
            if exc.code != "precondition_failed":
                raise
            detail, _ = await agent_detail(conn, ctx.tenant_id, agent_id)
            raise ProblemError("precondition_failed", extensions={"current": detail}) from None
        changes = {
            f: getattr(body, f)
            for f in PATCHABLE
            if f in body.model_fields_set and getattr(body, f) != row[f]
        }
        if "tier" in changes or "risk_class" in changes:
            await require_scope(ctx, "agents:approve", group_id=row["agent_group_id"])
        if "agent_group_id" in changes:
            await check_object(ctx, group_id=changes["agent_group_id"], agent_id=agent_id)
        await check_refs(
            conn,
            ctx.tenant_id,
            {
                "agent_group_id": ("agent_group", changes.get("agent_group_id")),
                "owner_user_id": ("app_user", changes.get("owner_user_id")),
                "business_process_id": ("business_process", changes.get("business_process_id")),
            },
        )
        if not changes:
            return await _detail_outcome(conn, ctx, agent_id)
        sets = ", ".join(f"{column} = ${i}" for i, column in enumerate(changes, start=3))
        await conn.execute(
            f"UPDATE sibyl.agent SET {sets} WHERE tenant_id = $1 AND id = $2",  # noqa: S608
            ctx.tenant_id,
            agent_id,
            *changes.values(),
        )
        updated = {**row, **changes}
        receipt = await audit(
            conn,
            ctx,
            "asset.updated",
            resource_type="agent",
            resource_id=agent_id,
            resource_ref=row["slug"],
            detail={"fields_changed": sorted(changes), "profile_hash": profile_hash(updated)},
        )
        if SNAPSHOT_FIELDS & changes.keys():
            await policy_changed(
                conn, ctx, aggregate_kind="agent", aggregate_id=agent_id, agent_id=agent_id
            )
        return await _detail_outcome(conn, ctx, agent_id, receipt=receipt)

    return await run_write(ctx, work, idempotent=False)


@router.post(AGENT + "/claim", operation_id="claimAgent")
async def claim_agent(
    agent_id: UUID, ctx: Annotated[AuthContext, Depends(guard("claimAgent"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await load_agent(conn, ctx, agent_id, lock=True)
        if not row["is_provisional"]:
            raise ProblemError("not_provisional")
        await conn.execute(
            "UPDATE sibyl.agent SET is_provisional = false, confirmed_at = now()"
            " WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            agent_id,
        )
        receipt = await audit(
            conn,
            ctx,
            "asset.updated",
            resource_type="agent",
            resource_id=agent_id,
            resource_ref=row["slug"],
            detail={
                "fields_changed": ["is_provisional", "confirmed_at"],
                "profile_hash": profile_hash({**row, "is_provisional": False}),
            },
        )
        return await _detail_outcome(conn, ctx, agent_id, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


# --- lifecycle ------------------------------------------------------------------------------


def _transition(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "from_stage": row["from_stage"],
        "to_stage": row["to_stage"],
        "actor_user_id": jsonable(row["actor_user_id"]),
        "reason": row["reason"],
        "audit_seq": row["audit_seq"],
        "created_at": jsonable(row["created_at"]),
    }


@router.get(AGENT + "/lifecycle", operation_id="getAgentLifecycle")
async def get_lifecycle(
    agent_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getAgentLifecycle"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await load_agent(conn, ctx, agent_id)
        rows = await conn.fetch(
            "SELECT * FROM sibyl.lifecycle_transition WHERE tenant_id = $1 AND agent_id = $2"
            " ORDER BY created_at, id",
            ctx.tenant_id,
            agent_id,
        )
        return Outcome(
            {
                "agent_id": str(agent_id),
                "lifecycle": row["lifecycle"],
                "transitions": [_transition(dict(r)) for r in rows],
            }
        )

    return await run_read(ctx, work)


async def _has_bound_key(conn: Any, tenant_id: UUID, agent_id: UUID) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.api_key WHERE tenant_id = $1 AND agent_id = $2"
            " AND status IN ('active', 'rotating') AND expires_at > now())",
            tenant_id,
            agent_id,
        )
    )


def _lifecycle_action(to_stage: str) -> str:
    if to_stage in ("approved", "deployed"):
        return "asset.approved"
    if to_stage == "retired":
        return "asset.retired"
    return "asset.updated"


@router.post(AGENT + "/lifecycle", operation_id="changeAgentLifecycle")
async def change_lifecycle(
    agent_id: UUID,
    body: LifecycleChange,
    ctx: Annotated[AuthContext, Depends(guard("changeAgentLifecycle"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await load_agent(conn, ctx, agent_id, lock=True)
        needed = "agents:approve" if body.to_stage in APPROVE_STAGES else "agents:write"
        await require_scope(ctx, needed, group_id=row["agent_group_id"])
        from_stage = row["lifecycle"]
        ctx.object_rule_checked("tier1_bound_key")
        if (
            row["tier"] == 1
            and from_stage == "proposed"
            and body.to_stage in ("approved", "deployed")
            and not await _has_bound_key(conn, ctx.tenant_id, agent_id)
        ):
            raise ProblemError(
                "tier1_requires_bound_key",
                "a tier-1 agent needs an active agent-bound API key before approval (R35)",
            )
        if from_stage == body.to_stage:
            raise ProblemError("invalid_transition", extensions={"from_state": from_stage})
        await conn.execute(
            "UPDATE sibyl.agent SET lifecycle = $3 WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            agent_id,
            body.to_stage,
        )
        transition_id: UUID = await conn.fetchval("SELECT sibyl.uuidv7()")
        action = _lifecycle_action(body.to_stage)
        detail: JSON
        if action == "asset.approved":
            detail = {
                "lifecycle_from": from_stage,
                "lifecycle_to": body.to_stage,
                "approval_ref": str(transition_id),
            }
        elif action == "asset.retired":
            detail = {"lifecycle_from": from_stage}
        else:
            updated = {**row, "lifecycle": body.to_stage}
            detail = {"fields_changed": ["lifecycle"], "profile_hash": profile_hash(updated)}
        receipt = await audit(
            conn,
            ctx,
            action,
            resource_type="agent",
            resource_id=agent_id,
            resource_ref=row["slug"],
            reason=body.reason,
            detail=detail,
        )
        await conn.execute(
            "INSERT INTO sibyl.lifecycle_transition (tenant_id, id, agent_id, from_stage,"
            " to_stage, actor_user_id, reason, audit_seq) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            ctx.tenant_id,
            transition_id,
            agent_id,
            from_stage,
            body.to_stage,
            user_id(ctx),
            body.reason,
            receipt.seq,
        )
        await policy_changed(
            conn, ctx, aggregate_kind="agent", aggregate_id=agent_id, agent_id=agent_id
        )
        return await _detail_outcome(conn, ctx, agent_id, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


__all__ = ["NOT_APPLICABLE", "check_refs", "register_routing", "router"]
