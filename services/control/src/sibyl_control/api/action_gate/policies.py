"""``/action-policies`` (ACTION-GATE.md §3): list, create a draft version, get, approve (tier-1
four-eyes), retire; the dry runs are in ``simulate.py``.

A version is immutable; a change is a new draft for the same scope, and approving it supersedes
the scope's approved version in the same transaction. Every write is audited and emits
``policy_changed`` so the signed snapshot (which carries approved policies) rebuilds.

Lane AG-LIVE: versions of one scope share a stable ``policy_id`` (derived by the database from
the scope's first version; the row ``id`` stays the version id, the snapshot key and the
document's ``policy_id``); each version keeps its ``change_note`` and its approval trail
(``approvals``); ``scope`` carries a display label; superseded versions are history in lists.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sibyl_schemas import action_gate as ag

from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    PageQuery,
    audit,
    keyset_page,
    op_reason,
    policy_changed,
    refuse,
    run_read,
    run_write,
    user_id,
)
from . import service
from .models import ActionPolicyCreate, ReasonBody
from .views import policy_etag, policy_view, scope_id

router = APIRouter()
_LABELED = (
    "SELECT p.*, CASE p.scope_kind WHEN 'agent' THEN a.name WHEN 'agent_group' THEN g.name END"
    " AS scope_label FROM sibyl.action_policy p"
    " LEFT JOIN sibyl.agent a ON a.tenant_id = p.tenant_id AND a.id = p.agent_id"
    " LEFT JOIN sibyl.agent_group g ON g.tenant_id = p.tenant_id AND g.id = p.agent_group_id"
    " WHERE p.tenant_id = $1"
)
_POLICY_SQL = _LABELED + " AND p.id = $2"
_RULES_SQL = (
    "SELECT * FROM sibyl.action_rule WHERE tenant_id = $1 AND policy_id = $2 ORDER BY position"
)
_STATES = "^(draft|approved|superseded|retired)$"
_SCOPES = "^(tenant|agent_group|agent)$"
_NIL = UUID(int=0)


async def _load(conn: Any, tenant: UUID, policy_id: UUID, *, lock: bool = False) -> dict[str, Any]:
    row = await conn.fetchrow(_POLICY_SQL + (" FOR UPDATE OF p" if lock else ""), tenant, policy_id)
    if row is None:
        raise ProblemError("not_found")
    return dict(row)


async def _view(conn: Any, tenant: UUID, row: dict[str, Any], status: int = 200) -> Outcome:
    if "scope_label" not in row:  # a row from UPDATE … RETURNING *
        row = {**row, "scope_label": (await _load(conn, tenant, row["id"]))["scope_label"]}
    rules = await conn.fetch(_RULES_SQL, tenant, row["id"])
    return Outcome(policy_view(row, rules), status=status, etag=policy_etag(row))


@router.get(API_PREFIX + "/action-policies")
async def list_action_policies(
    ctx: Annotated[AuthContext, Depends(guard("listActionPolicies"))],
    state: Annotated[str | None, Query(pattern=_STATES)] = None,
    scope_kind: Annotated[str | None, Query(pattern=_SCOPES)] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    policy_id: Annotated[UUID | None, Query()] = None,
    include_history: Annotated[bool, Query()] = False,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    """Superseded versions are history: listed with ``include_history`` or
    ``state=superseded``."""
    page = PageQuery.of(
        limit,
        cursor,
        state=state,
        scope_kind=scope_kind,
        agent_id=agent_id,
        policy_id=policy_id,
        include_history=include_history,
    )

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = _LABELED
        for column, value in (
            ("p.state", state),
            ("p.scope_kind", scope_kind),
            ("p.agent_id", agent_id),
            ("p.policy_id", policy_id),
        ):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        if not include_history and state is None:
            sql += " AND p.state <> 'superseded'"
        outcome = await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("p.created_at", "p.id"),
            descending=True,
            serialize=lambda r: r,
        )
        views = []
        for row in outcome.body["data"]:
            rules = await conn.fetch(_RULES_SQL, ctx.tenant_id, row["id"])
            views.append(policy_view(row, rules))
        outcome.body["data"] = views
        return outcome

    return await run_read(ctx, work)


async def _scope(conn: Any, ctx: AuthContext, body: ActionPolicyCreate) -> tuple[Any, Any]:
    """→ (agent_id, agent_group_id) after checking the scope object exists in the tenant."""
    if body.scope_kind == "tenant":
        if body.scope_id is not None:
            raise ProblemError("validation_failed", "a tenant-scope policy takes no scope_id")
        return None, None
    if body.scope_id is None:
        raise ProblemError("validation_failed", f"a {body.scope_kind} policy needs scope_id")
    table = "agent" if body.scope_kind == "agent" else "agent_group"
    found = await conn.fetchval(
        f"SELECT 1 FROM sibyl.{table} WHERE tenant_id = $1 AND id = $2",  # noqa: S608 - fixed
        ctx.tenant_id,
        body.scope_id,
    )
    if found is None:
        raise ProblemError("not_found", f"{table} {body.scope_id} does not exist")
    return (body.scope_id, None) if body.scope_kind == "agent" else (None, body.scope_id)


async def _check_based_on(
    conn: Any, tenant: UUID, body: ActionPolicyCreate, agent_id: Any, group_id: Any
) -> None:
    """``based_on_id`` must be a version of the same scope (versions of one scope share their
    ``policy_id``; a draft cannot move a policy to another scope)."""
    if body.based_on_id is None:
        return
    same = await conn.fetchval(
        "SELECT 1 FROM sibyl.action_policy WHERE tenant_id = $1 AND id = $2 AND scope_kind = $3"
        " AND agent_id IS NOT DISTINCT FROM $4::uuid"
        " AND agent_group_id IS NOT DISTINCT FROM $5::uuid",
        tenant,
        body.based_on_id,
        body.scope_kind,
        agent_id,
        group_id,
    )
    if same is None:
        raise ProblemError(
            "validation_failed", "based_on_id is not a version of this scope's policy"
        )


async def _insert_rules(conn: Any, tenant: UUID, policy_id: UUID, policy: ag.ActionPolicy) -> int:
    rules = list(policy.rules)
    for position, rule in enumerate(rules, start=1):
        dumped = rule.model_dump(mode="json", by_alias=True)
        await conn.execute(
            "INSERT INTO sibyl.action_rule (tenant_id, policy_id, position, rule_id, tool, effect,"
            " reason, when_expr, cumulative, data_class)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            tenant,
            policy_id,
            position,
            dumped["rule_id"],
            dumped["tool"],
            dumped["effect"],
            dumped["reason"],
            dumped.get("when"),
            dumped.get("cumulative"),
            dumped.get("data_class"),
        )
    return len(rules)


@router.post(API_PREFIX + "/action-policies", status_code=201)
async def create_action_policy(
    body: ActionPolicyCreate,
    ctx: Annotated[AuthContext, Depends(guard("createActionPolicy"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        agent_id, group_id = await _scope(conn, ctx, body)
        await _check_based_on(conn, tenant, body, agent_id, group_id)
        version = await conn.fetchval(
            "SELECT coalesce(max(version_no), 0) + 1 FROM sibyl.action_policy"
            " WHERE tenant_id = $1 AND scope_kind = $2"
            " AND coalesce(agent_id, agent_group_id, $3::uuid)"
            " = coalesce($4::uuid, $5::uuid, $3::uuid)",
            tenant,
            body.scope_kind,
            _NIL,
            agent_id,
            group_id,
        )
        policy_id = uuid4()
        document = {
            **service.DOCUMENT_DEFAULTS,
            **body.document,
            "policy_id": str(policy_id),
            "version": int(version),
        }
        if agent_id is not None:  # an agent policy carries the agent's declared tools
            document = service.with_allowlist(
                document, await service.allowed_tools(conn, tenant, agent_id)
            )
        policy = service.parse_document(document)
        normalised = service.normalised(policy)
        digest = service.document_digest(normalised)
        four_eyes_tier1 = await service.tier1_in_scope(
            conn, tenant, body.scope_kind, agent_id, group_id
        )
        creator = user_id(ctx)
        if creator is None:  # pragma: no cover - the route is human-only
            raise ProblemError("forbidden")
        await conn.execute(
            "INSERT INTO sibyl.action_policy (tenant_id, id, name, scope_kind, agent_id,"
            " agent_group_id, version_no, document, document_sha256, default_effect,"
            " hold_timeout_s, four_eyes, approval_four_eyes, rule_count, created_by_user_id,"
            " change_note)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
            tenant,
            policy_id,
            body.name,
            body.scope_kind,
            agent_id,
            group_id,
            int(version),
            normalised,
            digest,
            str(getattr(policy.default_effect, "value", policy.default_effect)),
            int(policy.hold_timeout_s),
            body.four_eyes,
            four_eyes_tier1,
            len(policy.rules),
            creator,
            None if body.change_note is None else body.change_note.strip() or None,
        )
        await _insert_rules(conn, tenant, policy_id, policy)
        row = await _load(conn, tenant, policy_id)
        given = body.reason or (body.change_note if len(body.change_note or "") >= 10 else None)
        receipt = await audit(
            conn,
            ctx,
            "action_policy.created",
            resource_type="action_policy",
            resource_id=policy_id,
            reason=op_reason(ctx, given),
            detail={
                "policy_id": policy_id,
                "lineage_policy_id": row["policy_id"],
                "version_no": int(version),
                "scope_kind": body.scope_kind,
                "scope_id": scope_id(row),
                "document_sha256": digest.hex(),
            },
        )
        outcome = await _view(conn, tenant, row, 201)
        outcome.receipt = receipt
        return outcome

    return await run_write(ctx, work, idempotent=True)


@router.get(API_PREFIX + "/action-policies/{policy_id}")
async def get_action_policy(
    policy_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getActionPolicy"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        return await _view(conn, ctx.tenant_id, await _load(conn, ctx.tenant_id, policy_id))

    return await run_read(ctx, work)


def _transition(action: str, row: dict[str, Any], allowed: tuple[str, ...]) -> None:
    if row["state"] not in allowed:
        raise ProblemError(
            "invalid_transition",
            f"policy is {row['state']}; {action} needs {' or '.join(allowed)}",
            extensions={"from_state": row["state"], "action": action},
        )


async def _changed(conn: Any, ctx: AuthContext, row: dict[str, Any]) -> None:
    await policy_changed(
        conn, ctx, aggregate_kind="action_policy", aggregate_id=row["id"], agent_id=row["agent_id"]
    )


@router.post(API_PREFIX + "/action-policies/{policy_id}/approve")
async def approve_action_policy(
    policy_id: UUID,
    body: ReasonBody,
    ctx: Annotated[AuthContext, Depends(guard("approveActionPolicy"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        row = await _load(conn, tenant, policy_id, lock=True)
        ctx.object_rule_checked("four_eyes_tier1")
        _transition("approve", row, ("draft",))
        approver = user_id(ctx)
        four_eyes = bool(row["approval_four_eyes"]) or await service.tier1_in_scope(
            conn, tenant, row["scope_kind"], row["agent_id"], row["agent_group_id"]
        )
        if four_eyes and approver == row["created_by_user_id"]:
            raise await refuse(
                ctx, "self_approval", "a tier-1 agent is in scope: another person must approve"
            )
        if not await service.approved_budget_ok(conn, tenant, row):
            raise ProblemError(
                "validation_failed", "approved action policies would exceed the 1 MiB budget"
            )
        previous = await conn.fetchrow(
            "UPDATE sibyl.action_policy SET state = 'superseded', superseded_by = $2,"
            " superseded_at = now() WHERE tenant_id = $1 AND state = 'approved'"
            " AND scope_kind = $3 AND agent_id IS NOT DISTINCT FROM $4::uuid"
            " AND agent_group_id IS NOT DISTINCT FROM $5::uuid RETURNING id",
            tenant,
            policy_id,
            row["scope_kind"],
            row["agent_id"],
            row["agent_group_id"],
        )
        now = await conn.fetchval("SELECT now()")
        trail = {
            "user_id": str(approver),
            "at": now.isoformat().replace("+00:00", "Z"),
            "reason": body.reason.strip(),
        }
        updated = dict(
            await conn.fetchrow(
                "UPDATE sibyl.action_policy SET state = 'approved', approved_by_user_id = $3,"
                " approved_at = now(), approvals = approvals || $4::jsonb"
                " WHERE tenant_id = $1 AND id = $2 RETURNING *",
                tenant,
                policy_id,
                approver,
                [trail],
            )
        )
        receipt = await audit(
            conn,
            ctx,
            "action_policy.approved",
            resource_type="action_policy",
            resource_id=policy_id,
            reason=body.reason.strip(),
            detail={
                "policy_id": policy_id,
                "version_no": int(row["version_no"]),
                "approved_by": approver,
                "four_eyes": four_eyes,
                "supersedes": None if previous is None else previous["id"],
                "document_sha256": bytes(row["document_sha256"]).hex(),
            },
        )
        await _changed(conn, ctx, updated)
        outcome = await _view(conn, tenant, updated)
        outcome.receipt = receipt
        return outcome

    return await run_write(ctx, work, idempotent=True)


@router.post(API_PREFIX + "/action-policies/{policy_id}/retire")
async def retire_action_policy(
    policy_id: UUID,
    body: ReasonBody,
    ctx: Annotated[AuthContext, Depends(guard("retireActionPolicy"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        row = await _load(conn, tenant, policy_id, lock=True)
        _transition("retire", row, ("draft", "approved"))
        updated = dict(
            await conn.fetchrow(
                "UPDATE sibyl.action_policy SET state = 'retired', retired_by_user_id = $3,"
                " retired_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING *",
                tenant,
                policy_id,
                user_id(ctx),
            )
        )
        receipt = await audit(
            conn,
            ctx,
            "action_policy.retired",
            resource_type="action_policy",
            resource_id=policy_id,
            reason=body.reason.strip(),
            detail={"policy_id": policy_id, "version_no": int(row["version_no"])},
        )
        if row["state"] == "approved":
            await _changed(conn, ctx, updated)
        outcome = await _view(conn, tenant, updated)
        outcome.receipt = receipt
        return outcome

    return await run_write(ctx, work, idempotent=True)
