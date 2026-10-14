"""Continuity plans (sub-resource, R34) and fallback chains (draft → approved → retired).

The plan is one row per agent with ETag ``"<row_version>"``; ``PUT`` with ``If-Match: *``
creates it, any other ``PUT`` replaces it. Silent RTO/RPO/preemptive/inline settings take the
tier defaults (D23, R38, R40). A chain is edited only as a draft; approving it (four-eyes on
tier 1) retires the previous approved chain and points the plan at it. Plan and chain changes
that the gateway sees emit ``policy_changed`` in the same transaction.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.etag import etag_for_row, etag_for_version
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    JSON,
    Outcome,
    PageQuery,
    config_changed,
    deny,
    has_scope,
    jsonable,
    keyset_page,
    load_agent,
    money,
    parse_money,
    policy_changed,
    refuse,
    require_if_match,
    run_read,
    run_write,
    user_id,
)
from ._refs import content_ref
from .models import (
    ContinuityPlanPut,
    FallbackChainAction,
    FallbackChainCreate,
    FallbackChainPut,
    FallbackStepInput,
)

router = APIRouter()

TIER_RTO_S = {1: 900, 2: 3600, 3: 14400}
TIER_RPO_S = {1: 60, 2: 300, 3: 900}
TIER_PREEMPTIVE = {1: "approval", 2: "degrade_then_auto", 3: "auto"}
KIND_RANK = {
    "retry": 0,
    "alt_model_same_provider": 1,
    "alt_provider": 2,
    "backup_agent": 3,
    "degraded_safe_mode": 4,
    "human_queue": 5,
}
VIABLE_CREDENTIAL_STATES = ("active", "rotating")

_PLAN_FIELDS = (
    "rto_s",
    "rpo_s",
    "credential_mode",
    "degraded_mode",
    "inline_fallback",
    "preemptive_mode",
    "approval_timeout_s",
    "approval_timeout_policy",
    "fallback_chain_id",
    "on_call_user_id",
    "on_call_ref",
    "budget_usd_month",
    "max_inflight",
    "rps_limit",
    "drill_schedule",
    "expected_cadence_s",
)


# --- continuity plan ------------------------------------------------------------------------


def plan_view(row: dict[str, Any]) -> JSON:
    rps = row["rps_limit"]
    return {
        "agent_id": str(row["agent_id"]),
        "rto_s": row["rto_s"],
        "rpo_s": row["rpo_s"],
        "credential_mode": row["credential_mode"],
        "degraded_mode": row["degraded_mode"],
        "inline_fallback": row["inline_fallback"],
        "preemptive_mode": row["preemptive_mode"],
        "approval_timeout_s": row["approval_timeout_s"],
        "approval_timeout_policy": row["approval_timeout_policy"],
        "fallback_chain_id": jsonable(row["fallback_chain_id"]),
        "on_call_user_id": jsonable(row["on_call_user_id"]),
        "on_call_ref": row["on_call_ref"],
        "budget_usd_month": money(row["budget_usd_month"]),
        "max_inflight": row["max_inflight"],
        "rps_limit": int(rps) if rps is not None else None,
        "drill_schedule": row["drill_schedule"],
        "expected_cadence_s": row["expected_cadence_s"],
        "approved_by_user_id": jsonable(row["approved_by_user_id"]),
        "approved_at": jsonable(row["approved_at"]),
        "row_version": row["row_version"],
        "updated_at": jsonable(row["updated_at"]),
    }


def _plan_audit(row: dict[str, Any] | None) -> JSON | None:
    if row is None:
        return None
    view = plan_view(row)
    return {k: view[k] for k in _PLAN_FIELDS}


async def _plan_row(conn: Any, tenant: UUID, agent: UUID, *, lock: bool = False) -> Any:
    sql = "SELECT * FROM sibyl.continuity_plan WHERE tenant_id = $1 AND agent_id = $2"
    return await conn.fetchrow(sql + (" FOR UPDATE" if lock else ""), tenant, agent)


@router.get(API_PREFIX + "/agents/{agent_id}/continuity-plan")
async def get_continuity_plan(
    agent_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getContinuityPlan"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        row = await _plan_row(conn, ctx.tenant_id, agent_id)
        if row is None:
            raise ProblemError("plan_missing", "this agent has no continuity plan yet")
        return Outcome(plan_view(dict(row)), etag=etag_for_version(row["row_version"]))

    return await run_read(ctx, work)


async def _check_plan_chain(conn: Any, tenant: UUID, agent: UUID, chain_id: UUID | None) -> None:
    if chain_id is None:
        return
    chain = await conn.fetchrow(
        "SELECT agent_id, status FROM sibyl.fallback_chain WHERE tenant_id = $1 AND id = $2",
        tenant,
        chain_id,
    )
    if chain is None:
        raise ProblemError("validation_failed", "fallback_chain_id names no chain")
    if chain["agent_id"] != agent:
        raise ProblemError("chain_agent_mismatch", "the chain belongs to another agent")
    if chain["status"] != "approved":
        raise ProblemError("chain_not_approved", "only an approved chain can back a plan")


async def _inline_approver(
    ctx: AuthContext, agent: dict[str, Any], current: Any, inline: bool
) -> tuple[UUID | None, datetime | None, bool]:
    """``(approved_by, approved_at, set_now)`` for the tier-1 inline-fallback rule."""
    ctx.object_rule_checked("tier1_inline_fallback_approver")
    kept_by = current["approved_by_user_id"] if current is not None else None
    kept_at = current["approved_at"] if current is not None else None
    if agent["tier"] != 1 or not inline:
        return kept_by, kept_at, False
    if current is not None and current["inline_fallback"] and kept_by is not None:
        return kept_by, kept_at, False
    if not has_scope(ctx, "agents:approve"):
        raise await refuse(
            ctx,
            "tier1_inline_fallback_needs_approver",
            "inline fallback on a tier-1 agent needs an approver holding agents:approve",
        )
    return user_id(ctx), None, True


@router.put(API_PREFIX + "/agents/{agent_id}/continuity-plan")
async def put_continuity_plan(
    agent_id: UUID,
    body: ContinuityPlanPut,
    ctx: Annotated[AuthContext, Depends(guard("putContinuityPlan"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        agent = await load_agent(conn, ctx, agent_id, lock=True)
        current = await _plan_row(conn, tenant, agent_id, lock=True)
        current_etag = etag_for_version(current["row_version"]) if current is not None else None
        require_if_match(
            ctx,
            current_etag,
            allow_star_create=True,
            body=plan_view(dict(current)) if current is not None else None,
        )
        tier = int(agent["tier"])
        inline = body.inline_fallback if body.inline_fallback is not None else tier != 1
        approved_by, approved_at, approve_now = await _inline_approver(ctx, agent, current, inline)
        await _check_plan_chain(conn, tenant, agent_id, body.fallback_chain_id)
        if (
            body.approval_timeout_policy == "fail_safe"
            and tier == 1
            and await conn.fetchval("SELECT sibyl.agent_pii_exposed($1, $2)", tenant, agent_id)
        ):
            raise ProblemError(
                "fail_safe_forbidden",
                "fail_safe is refused on a tier-1 agent with PII or residency exposure (D22)",
            )
        values: dict[str, Any] = {
            "rto_s": body.rto_s or TIER_RTO_S[tier],
            "rpo_s": body.rpo_s if body.rpo_s is not None else TIER_RPO_S[tier],
            "credential_mode": body.credential_mode,
            "degraded_mode": body.degraded_mode,
            "inline_fallback": inline,
            "preemptive_mode": body.preemptive_mode or TIER_PREEMPTIVE[tier],
            "approval_timeout_s": body.approval_timeout_s,
            "approval_timeout_policy": body.approval_timeout_policy,
            "fallback_chain_id": body.fallback_chain_id,
            "on_call_user_id": body.on_call_user_id,
            "on_call_ref": body.on_call_ref,
            "budget_usd_month": parse_money(body.budget_usd_month),
            "max_inflight": body.max_inflight,
            "rps_limit": Decimal(body.rps_limit) if body.rps_limit is not None else None,
            "drill_schedule": body.drill_schedule,
            "expected_cadence_s": body.expected_cadence_s,
            "approved_by_user_id": approved_by,
        }
        cols = list(values)
        args = [values[c] for c in cols]
        if current is None:
            placeholders = ", ".join(f"${i + 3}" for i in range(len(cols)))
            row = await conn.fetchrow(
                # columns are the fixed names of ``values``; data travels as parameters
                f"INSERT INTO sibyl.continuity_plan (tenant_id, agent_id, {', '.join(cols)},"  # noqa: S608
                f" approved_at) VALUES ($1, $2, {placeholders},"
                f" CASE WHEN ${len(cols) + 3}::boolean THEN now() ELSE ${len(cols) + 4} END)"
                " RETURNING *",
                tenant,
                agent_id,
                *args,
                approve_now,
                approved_at,
            )
            status = 201
        else:
            sets = ", ".join(f"{c} = ${i + 3}" for i, c in enumerate(cols))
            n = len(cols)
            row = await conn.fetchrow(
                f"UPDATE sibyl.continuity_plan SET {sets},"  # noqa: S608 (fixed column names)
                f" approved_at = CASE WHEN ${n + 3}::boolean THEN now() ELSE ${n + 4} END,"
                " row_version = row_version + 1"
                " WHERE tenant_id = $1 AND agent_id = $2 RETURNING *",
                tenant,
                agent_id,
                *args,
                approve_now,
                approved_at,
            )
            status = 200
        result = dict(row)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="continuity_plan",
            resource_id=result["id"],
            field_name="continuity_plan",
            before=_plan_audit(dict(current) if current is not None else None),
            after=_plan_audit(result),
            reason=body.reason,
        )
        await policy_changed(
            conn,
            ctx,
            aggregate_kind="continuity_plan",
            aggregate_id=result["id"],
            agent_id=agent_id,
        )
        return Outcome(
            plan_view(result),
            status=status,
            etag=etag_for_version(result["row_version"]),
            receipt=receipt,
        )

    return await run_write(ctx, work, idempotent=False)


# --- fallback chains ------------------------------------------------------------------------


async def _steps(conn: Any, tenant: UUID, chain_ids: list[UUID]) -> dict[UUID, list[JSON]]:
    rows = await conn.fetch(
        "SELECT s.*, c.status AS credential_status FROM sibyl.fallback_step s"
        " LEFT JOIN sibyl.provider_credential_meta c"
        "   ON c.tenant_id = s.tenant_id AND c.id = s.credential_id"
        " WHERE s.tenant_id = $1 AND s.chain_id = ANY($2::uuid[])"
        " ORDER BY s.chain_id, s.position",
        tenant,
        chain_ids,
    )
    out: dict[UUID, list[JSON]] = {c: [] for c in chain_ids}
    for r in rows:
        viable = not r["target_erased"] and (
            r["credential_id"] is None or r["credential_status"] in VIABLE_CREDENTIAL_STATES
        )
        out[r["chain_id"]].append(
            {
                "id": str(r["id"]),
                "position": r["position"],
                "kind": r["kind"],
                "provider_id": jsonable(r["provider_id"]),
                "model_id": jsonable(r["model_id"]),
                "backup_agent_id": jsonable(r["backup_agent_id"]),
                "credential_id": jsonable(r["credential_id"]),
                "risk": r["risk"],
                "max_attempts": r["max_attempts"],
                "params": r["params"],
                "target_erased": r["target_erased"],
                "viable": viable,
            }
        )
    return out


def chain_view(row: dict[str, Any], steps: list[JSON]) -> JSON:
    return {
        "id": str(row["id"]),
        "agent_id": str(row["agent_id"]),
        "version_no": row["version_no"],
        "status": row["status"],
        "steps": steps,
        "note": row["note"],
        "requested_by_user_id": jsonable(row["requested_by_user_id"]),
        "approved_by_user_id": jsonable(row["approved_by_user_id"]),
        "approved_at": jsonable(row["approved_at"]),
        "retired_at": jsonable(row["retired_at"]),
        "created_at": jsonable(row["created_at"]),
    }


async def _chain_out(conn: Any, tenant: UUID, row: Any) -> JSON:
    steps = await _steps(conn, tenant, [row["id"]])
    return chain_view(dict(row), steps[row["id"]])


def _chain_etag(row: Any) -> str:
    return etag_for_row(row["updated_at"], row["id"])


def _step_summary(steps: list[FallbackStepInput]) -> list[JSON]:
    return [
        {
            "kind": s.kind,
            "provider_id": jsonable(s.provider_id),
            "model_id": jsonable(s.model_id),
            "backup_agent_id": jsonable(s.backup_agent_id),
            "credential_id": jsonable(s.credential_id),
            "risk": s.risk,
            "params_ref": content_ref(s.params or {}),
        }
        for s in steps
    ]


def _shape(steps: list[FallbackStepInput], agent_id: UUID) -> None:
    """Order and per-kind requirements, answered before the database's deferred trigger."""
    for i, step in enumerate(steps):
        if i and steps[i - 1].kind == "human_queue":
            raise ProblemError("step_after_human_queue", "human_queue must be the last step")
        if i and KIND_RANK[step.kind] < KIND_RANK[steps[i - 1].kind]:
            raise ProblemError(
                "step_rank_order",
                "steps run retry, alt model, alt provider, backup agent, safe mode, human queue",
            )
        if step.kind == "backup_agent":
            if step.backup_agent_id is None:
                raise ProblemError("validation_failed", f"step {i}: backup_agent needs an agent")
            if step.backup_agent_id == agent_id:
                raise ProblemError("backup_is_self", "an agent cannot be its own backup")
        elif step.backup_agent_id is not None:
            raise ProblemError(
                "validation_failed", f"step {i}: backup_agent_id only on backup_agent"
            )
        if step.kind == "alt_provider" and step.provider_id is None:
            raise ProblemError("validation_failed", f"step {i}: alt_provider needs provider_id")
        if step.kind == "alt_model_same_provider" and step.model_id is None:
            raise ProblemError("validation_failed", f"step {i}: alt_model needs model_id")


async def _exists(conn: Any, table: str, tenant: UUID, ids: set[UUID]) -> bool:
    if not ids:
        return True
    found = await conn.fetchval(
        f"SELECT count(*) FROM sibyl.{table}"  # noqa: S608 (table from a fixed tuple)
        " WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
        tenant,
        list(ids),
    )
    return int(found) == len(ids)


async def _validate_steps(
    conn: Any, tenant: UUID, agent_id: UUID, steps: list[FallbackStepInput]
) -> None:
    _shape(steps, agent_id)
    for table, attr in (
        ("provider", "provider_id"),
        ("model", "model_id"),
        ("agent", "backup_agent_id"),
    ):
        ids = {getattr(s, attr) for s in steps if getattr(s, attr) is not None}
        if not await _exists(conn, table, tenant, ids):
            raise ProblemError("validation_failed", f"a step's {attr} names nothing in this tenant")
    vaulted = (
        await conn.fetchval(
            "SELECT credential_mode FROM sibyl.continuity_plan"
            " WHERE tenant_id = $1 AND agent_id = $2",
            tenant,
            agent_id,
        )
        == "vaulted_fallback"
    )
    for i, step in enumerate(steps):
        if step.kind == "alt_provider" and step.credential_id is None and vaulted:
            raise ProblemError(
                "alt_provider_requires_credential",
                f"step {i}: the plan uses vaulted_fallback, so alt_provider needs credential_id",
            )
        if step.credential_id is None:
            continue
        cred = await conn.fetchrow(
            "SELECT provider_id, status FROM sibyl.provider_credential_meta"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            step.credential_id,
        )
        if cred is None or cred["status"] not in VIABLE_CREDENTIAL_STATES:
            raise ProblemError("validation_failed", f"step {i}: credential_id is not active")
        if step.provider_id is not None and cred["provider_id"] != step.provider_id:
            raise ProblemError(
                "validation_failed", f"step {i}: credential belongs to another provider"
            )


async def _insert_steps(
    conn: Any, tenant: UUID, chain_id: UUID, steps: list[FallbackStepInput]
) -> None:
    for position, s in enumerate(steps):
        await conn.execute(
            "INSERT INTO sibyl.fallback_step (tenant_id, chain_id, position, kind, provider_id,"
            " model_id, backup_agent_id, credential_id, risk, max_attempts, params)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)",
            tenant,
            chain_id,
            position,
            s.kind,
            s.provider_id,
            s.model_id,
            s.backup_agent_id,
            s.credential_id,
            s.risk,
            s.max_attempts or 1,
            s.params or {},
        )


@router.get(API_PREFIX + "/agents/{agent_id}/fallback-chains")
async def list_fallback_chains(
    agent_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("listFallbackChains"))],
    status: Annotated[str | None, Query(pattern="^(draft|approved|retired)$")] = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    page = PageQuery.of(limit, cursor, agent_id=agent_id, status=status)

    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        args: list[Any] = [ctx.tenant_id, agent_id]
        sql = "SELECT * FROM sibyl.fallback_chain WHERE tenant_id = $1 AND agent_id = $2"
        if status is not None:
            args.append(status)
            sql += f" AND status = ${len(args)}"
        outcome = await keyset_page(
            conn, ctx, select=sql, args=args, page=page, serialize=lambda r: r
        )
        rows = outcome.body["data"]
        steps = await _steps(conn, ctx.tenant_id, [r["id"] for r in rows])
        outcome.body["data"] = [chain_view(r, steps[r["id"]]) for r in rows]
        return outcome

    return await run_read(ctx, work)


@router.post(API_PREFIX + "/agents/{agent_id}/fallback-chains", status_code=201)
async def create_fallback_chain(
    agent_id: UUID,
    body: FallbackChainCreate,
    ctx: Annotated[AuthContext, Depends(guard("createFallbackChain"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        await load_agent(conn, ctx, agent_id, lock=True)
        if body.clone_from_chain_id is not None and not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.fallback_chain"
            " WHERE tenant_id = $1 AND id = $2 AND agent_id = $3)",
            tenant,
            body.clone_from_chain_id,
            agent_id,
        ):
            raise ProblemError(
                "validation_failed", "clone_from_chain_id names no chain of this agent"
            )
        await _validate_steps(conn, tenant, agent_id, body.steps)
        row = await conn.fetchrow(
            "INSERT INTO sibyl.fallback_chain (tenant_id, agent_id, version_no, status,"
            " requested_by_user_id, note)"
            " SELECT $1, $2, coalesce(max(version_no), 0) + 1, 'draft', $3, $4"
            "   FROM sibyl.fallback_chain WHERE tenant_id = $1 AND agent_id = $2"
            " RETURNING *",
            tenant,
            agent_id,
            user_id(ctx),
            body.note,
        )
        await _insert_steps(conn, tenant, row["id"], body.steps)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="fallback_chain",
            resource_id=row["id"],
            field_name="fallback_chain",
            before=None,
            after={
                "chain_id": row["id"],
                "agent_id": agent_id,
                "version_no": row["version_no"],
                "status": "draft",
                "clone_from_chain_id": jsonable(body.clone_from_chain_id),
                "steps": _step_summary(body.steps),
            },
            reason=body.reason,
        )
        return Outcome(
            await _chain_out(conn, tenant, row), status=201, etag=_chain_etag(row), receipt=receipt
        )

    return await run_write(ctx, work, idempotent=True)


async def _load_chain(conn: Any, ctx: AuthContext, chain_id: UUID) -> tuple[Any, dict[str, Any]]:
    """The chain (locked) and its agent; ``load_agent`` is skipped when the op has no group
    rule so ``actOnFallbackChain`` evaluates the group through ``ctx.action``."""
    chain = await conn.fetchrow(
        "SELECT * FROM sibyl.fallback_chain WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        ctx.tenant_id,
        chain_id,
    )
    if chain is None:
        raise ProblemError("not_found")
    if "group" in ctx.op.object_rules:
        agent = await load_agent(conn, ctx, chain["agent_id"], lock=True)
    else:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.agent WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            ctx.tenant_id,
            chain["agent_id"],
        )
        agent = dict(row)
    return chain, agent


@router.put(API_PREFIX + "/fallback-chains/{chain_id}")
async def put_fallback_chain(
    chain_id: UUID,
    body: FallbackChainPut,
    ctx: Annotated[AuthContext, Depends(guard("putFallbackChain"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        chain, _agent = await _load_chain(conn, ctx, chain_id)
        require_if_match(ctx, _chain_etag(chain))
        if chain["status"] != "draft":
            raise ProblemError("chain_immutable", f"a {chain['status']} chain cannot be edited")
        await _validate_steps(conn, tenant, chain["agent_id"], body.steps)
        before = await _steps(conn, tenant, [chain_id])
        await conn.execute(
            "DELETE FROM sibyl.fallback_step WHERE tenant_id = $1 AND chain_id = $2",
            tenant,
            chain_id,
        )
        await _insert_steps(conn, tenant, chain_id, body.steps)
        row = await conn.fetchrow(
            "UPDATE sibyl.fallback_chain SET note = $3, updated_at = clock_timestamp()"
            " WHERE tenant_id = $1 AND id = $2 RETURNING *",
            tenant,
            chain_id,
            body.note,
        )
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="fallback_chain",
            resource_id=chain_id,
            field_name="fallback_chain.steps",
            before={
                "steps_ref": content_ref(before[chain_id]),
                "note_ref": content_ref(chain["note"]),
            },
            after={"steps": _step_summary(body.steps), "note_ref": content_ref(body.note)},
            reason=body.reason,
        )
        return Outcome(await _chain_out(conn, tenant, row), etag=_chain_etag(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=False)


async def _approve(
    conn: Any, ctx: AuthContext, chain: Any, agent: dict[str, Any]
) -> tuple[Any, UUID | None]:
    tenant = ctx.tenant_id
    if chain["status"] != "draft":
        raise ProblemError(
            "invalid_transition",
            f"only a draft chain can be approved; this one is {chain['status']}",
            extensions={"from_state": chain["status"], "action": "approve"},
        )
    approver = user_id(ctx)
    if agent["tier"] == 1 and approver == chain["requested_by_user_id"]:
        raise ProblemError("self_approval", "tier-1 chains need a second approver (four-eyes)")
    previous = await conn.fetchval(
        "UPDATE sibyl.fallback_chain SET status = 'retired', retired_at = now()"
        " WHERE tenant_id = $1 AND agent_id = $2 AND status = 'approved' RETURNING id",
        tenant,
        chain["agent_id"],
    )
    row = await conn.fetchrow(
        "UPDATE sibyl.fallback_chain SET status = 'approved', approved_by_user_id = $3,"
        " approved_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING *",
        tenant,
        chain["id"],
        approver,
    )
    await conn.execute(
        "UPDATE sibyl.continuity_plan SET fallback_chain_id = $3, row_version = row_version + 1"
        " WHERE tenant_id = $1 AND agent_id = $2",
        tenant,
        chain["agent_id"],
        chain["id"],
    )
    return row, previous


async def _retire(conn: Any, ctx: AuthContext, chain: Any) -> Any:
    tenant = ctx.tenant_id
    if chain["status"] == "retired":
        raise ProblemError(
            "invalid_transition",
            "the chain is already retired",
            extensions={"from_state": "retired", "action": "retire"},
        )
    await conn.execute(
        "UPDATE sibyl.continuity_plan SET fallback_chain_id = NULL, row_version = row_version + 1"
        " WHERE tenant_id = $1 AND agent_id = $2 AND fallback_chain_id = $3",
        tenant,
        chain["agent_id"],
        chain["id"],
    )
    return await conn.fetchrow(
        "UPDATE sibyl.fallback_chain SET status = 'retired', retired_at = now()"
        " WHERE tenant_id = $1 AND id = $2 RETURNING *",
        tenant,
        chain["id"],
    )


@router.post(API_PREFIX + "/fallback-chains/{chain_id}/actions")
async def act_on_fallback_chain(
    chain_id: UUID,
    body: FallbackChainAction,
    ctx: Annotated[AuthContext, Depends(guard("actOnFallbackChain"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        chain, agent = await _load_chain(conn, ctx, chain_id)
        try:
            ctx.action(body.action, resource_group_id=agent["agent_group_id"])
        except ProblemError as exc:
            raise await deny(ctx, exc) from None
        before = chain["status"]
        previous: UUID | None = None
        if body.action == "approve":
            row, previous = await _approve(conn, ctx, chain, agent)
        else:
            row = await _retire(conn, ctx, chain)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="fallback_chain",
            resource_id=chain_id,
            field_name="fallback_chain.status",
            before={"status": before},
            after={
                "status": row["status"],
                "action": body.action,
                "retired_previous_chain_id": jsonable(previous),
            },
            reason=body.reason,
        )
        if body.action == "approve" or before == "approved":
            await policy_changed(
                conn,
                ctx,
                aggregate_kind="fallback_chain",
                aggregate_id=chain_id,
                agent_id=chain["agent_id"],
            )
        return Outcome(await _chain_out(conn, tenant, row), etag=_chain_etag(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)
