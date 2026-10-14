"""``/held-actions`` (ACTION-GATE.md §2, §3): an enforcement point holds an escalated action, a
human approves or denies it, the enforcement point polls for the decision.

* create (key ``actions:hold``, bound-agent rule): idempotent per (agent, call_id); the control
  plane re-evaluates with its own approved policy. When that evaluation is ``block`` the hold is
  created already ``denied`` (``action.blocked``); otherwise it is ``pending``
  (``action.escalated``) until ``hold_timeout_s``.
* decide (``actions:decide``): the requester never decides and the person the agent acted for
  (``on_behalf_of`` user) never approves (409 ``self_approval``); a ``four_eyes`` policy needs two
  distinct approvers (each approval is audited, the second one releases the action); one deny
  ends the hold; a sensitive tool needs a fresh step-up. The final approval adds a call under a
  cumulative cap to its window when the cap had not counted it (``service.count_approved``).
* every change appends to the hold's decision trail (``history.py``).
* B31: an ``on_behalf_of`` of kind ``user`` must name a user of the tenant, else 422
  ``validation_failed`` and nothing is held (the enforcement point fails closed). B32: a
  deactivated user (``disabled`` / ``deprovisioned``) gets the same answer as an unknown one.
"""

from __future__ import annotations

import json
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import Response
from sibyl_schemas import action_gate as ag

from ...core.outbox import OutboxMessage
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    PageQuery,
    audit,
    check_object,
    keyset_page,
    load_agent,
    refuse,
    run_read,
    run_write,
    services_of,
)
from . import history, service
from .args import open_args, scrub_args, seal_args
from .models import HeldActionAction
from .views import held_etag, held_view
from .wire import parse_wire

router = APIRouter()
_HELD_SQL = "SELECT * FROM sibyl.held_action WHERE tenant_id = $1 AND id = $2"
_AGENT_GROUP_SQL = "SELECT agent_group_id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2"
_STATES = "^(pending|approved|denied|expired|cancelled)$"
ARGS_SCOPE = "actions:decide"
"""``include=args`` on the list: humans who may decide held actions see the scrubbed
arguments (``GET /held-actions/{id}`` shows them to every human reader)."""
_LIST_SQL = (
    "SELECT h.*, a.agent_group_id AS list_agent_group_id FROM sibyl.held_action h"
    " LEFT JOIN sibyl.agent a ON a.tenant_id = h.tenant_id AND a.id = h.agent_id"
    " WHERE h.tenant_id = $1"
)
DEFAULT_HOLD_TIMEOUT_S = 900
MAX_PATHS = 64


def _event(event_type: str, row: dict[str, Any]) -> OutboxMessage:
    return OutboxMessage.for_event(
        event_type,
        "held_action",
        row["id"],
        {
            "held_action_id": str(row["id"]),
            "agent_id": str(row["agent_id"]),
            "tool": row["tool"],
            "state": row["state"],
            "decision": row["decision"],
        },
    )


async def _emit(conn: Any, ctx: AuthContext, event_type: str, row: dict[str, Any]) -> None:
    await services_of(ctx).outbox.emit(conn, ctx.tenant_id, _event(event_type, row))


def _key_id(ctx: AuthContext) -> UUID:
    principal = ctx.principal
    assert principal is not None
    return principal.id


async def _require_known_user(
    conn: Any, tenant: UUID, behalf: ag.OnBehalfOfUser | ag.OnBehalfOfExternal | None
) -> None:
    """B31: a ``user`` on-behalf-of must be a user of this tenant (422 otherwise, fail closed).
    B32: a deactivated user (``disabled`` or ``deprovisioned``, the statuses that cannot sign
    in) is refused with the same answer, so the refusal does not reveal that the account
    exists."""
    if not isinstance(behalf, ag.OnBehalfOfUser):
        return
    known = await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2"
        " AND status IN ('invited', 'active'))",
        tenant,
        UUID(behalf.id),
    )
    if not known:
        raise ProblemError("validation_failed", "on_behalf_of.id is not a user of this tenant")


async def _create(conn: Any, ctx: AuthContext, body: ag.HeldActionRequest) -> Outcome:
    tenant = ctx.tenant_id
    agent_id = UUID(body.agent_id)
    agent = await load_agent(conn, ctx, agent_id)
    existing = await conn.fetchrow(
        "SELECT * FROM sibyl.held_action WHERE tenant_id = $1 AND agent_id = $2 AND call_id = $3",
        tenant,
        agent_id,
        body.call_id,
    )
    if existing is not None:
        return Outcome(held_view(existing, history=True), status=200, etag=held_etag(existing))
    await _require_known_user(conn, tenant, ag.on_behalf_of_of(body))
    service.args_size(body.args)
    clean = scrub_args(ctx.request, body.args)  # type: ignore[arg-type]
    found = await service.applicable(conn, tenant, agent)
    decision = ag.evaluate_all(found.policies, body.tool, clean) if found.policies else None
    server_effect = service.effect_of(decision) if decision is not None else "escalate"
    blocked = server_effect == "block"
    reason = service.clip_reason(
        decision.reason if blocked and decision is not None else body.reason,
        decision.reason if decision is not None else "escalated by the enforcement point",
    )
    policy_id, version = await _policy_ref(conn, tenant, decision, body)
    rule_id = (decision.rule_id if decision is not None else None) or body.rule_id
    timeout = body.hold_timeout_s
    if decision is not None and decision.hold_timeout_s is not None:
        timeout = int(decision.hold_timeout_s)
    sensitive = bool(decision.sensitive) if decision is not None else False
    four_eyes = int(agent["tier"]) == 1 or any(bool(r["four_eyes"]) for r in found.rows)
    held_id = uuid4()
    now = await conn.fetchval("SELECT now()")
    counter = await service.counter_of(conn, tenant, agent_id, body.call_id, decision)
    behalf = ag.on_behalf_of_of(body)
    behalf_user = UUID(behalf.id) if isinstance(behalf, ag.OnBehalfOfUser) else None
    behalf_ref = behalf.ref if isinstance(behalf, ag.OnBehalfOfExternal) else None
    first = history.entry(
        "blocked" if blocked else "requested", now, key_id=_key_id(ctx), reason=reason
    )
    paths = list(decision.matched_paths)[:MAX_PATHS] if decision is not None else []
    ref = await seal_args(
        conn,
        ctx.request,  # type: ignore[arg-type]
        tenant=tenant,
        agent_id=agent_id,
        held_action_id=held_id,
        api_key_id=_key_id(ctx),
        clean=clean,
        now=now,
    )
    digest = bytes.fromhex(body.args_sha256)
    row = dict(
        await conn.fetchrow(
            "INSERT INTO sibyl.held_action (tenant_id, id, agent_id, policy_id, policy_version,"
            " rule_id, call_id, tool, source, args_sha256, args_payload_ref, args_bytes,"
            " server_effect, reason, sensitive, approvals_required, requested_by_key_id, state,"
            " decision, decided_at, hold_timeout_s, expires_at, on_behalf_of_kind,"
            " on_behalf_of_user_id, on_behalf_of_ref, history, matched_paths, counter_key,"
            " counter_amount, counter_max, counter_window_s, counter_policy_id)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,"
            " $18::text, $19, CASE WHEN $18::text = 'denied' THEN now() END, $20::int,"
            " now() + make_interval(secs => $20::int), $21, $22, $23, $24, $25, $26, $27, $28,"
            " $29, $30) RETURNING *",
            tenant,
            held_id,
            agent_id,
            policy_id,
            version,
            rule_id,
            body.call_id,
            body.tool,
            body.source,
            digest,
            ref,
            len(json.dumps(clean, separators=(",", ":")).encode()),
            server_effect,
            reason,
            sensitive,
            2 if four_eyes else 1,
            _key_id(ctx),
            "denied" if blocked else "pending",
            "deny" if blocked else None,
            timeout,
            None if behalf is None else behalf.kind,
            behalf_user,
            behalf_ref,
            [first],
            paths,
            *counter,
        )
    )
    detail: dict[str, Any] = {
        "agent_id": agent_id,
        "tool": body.tool,
        "call_id": body.call_id,
        "policy_id": policy_id,
        "rule_id": rule_id,
    }
    if behalf is not None:  # who the agent acted for; an external ref stays out of the chain
        detail["on_behalf_of_kind"] = behalf.kind
        if behalf_user is not None:
            detail["on_behalf_of_user_id"] = behalf_user
    if blocked:
        receipt = await audit(
            conn,
            ctx,
            "action.blocked",
            resource_type="agent",
            resource_id=agent_id,
            reason=reason,
            detail={**detail, "held_action_id": held_id},
        )
        await _emit(conn, ctx, "action.decided", row)
    else:
        receipt = await audit(
            conn,
            ctx,
            "action.escalated",
            resource_type="agent",
            resource_id=agent_id,
            reason=reason,
            detail={**detail, "held_action_id": held_id},
        )
        await _emit(conn, ctx, "action.held", row)
    return Outcome(held_view(row, history=True), status=201, etag=held_etag(row), receipt=receipt)


async def _policy_ref(
    conn: Any, tenant: UUID, decision: ag.Decision | None, body: ag.HeldActionRequest
) -> tuple[UUID | None, int | None]:
    """The deciding policy: the control plane's own decision, else the one the enforcement
    point names (when it exists in this tenant)."""
    if decision is not None and decision.policy_id is not None:
        return UUID(decision.policy_id), decision.policy_version
    if body.policy_id is None:
        return None, None
    row = await conn.fetchrow(
        "SELECT id, version_no FROM sibyl.action_policy WHERE tenant_id = $1 AND id = $2",
        tenant,
        UUID(body.policy_id),
    )
    return (None, None) if row is None else (row["id"], int(row["version_no"]))


@router.post(API_PREFIX + "/held-actions", status_code=201)
async def create_held_action(
    payload: Annotated[dict[str, Any], Body()],
    ctx: Annotated[AuthContext, Depends(guard("createHeldAction"))],
) -> Response:
    """Body: ``sibyl_schemas.action_gate.HeldActionRequest`` (AG-ENFORCE's wire model)."""
    body = parse_wire(ag.HeldActionRequest, payload)

    async def work(conn: Any) -> Outcome:
        return await _create(conn, ctx, body)

    return await run_write(ctx, work, idempotent=True)


def _may_see_args(ctx: AuthContext, agent_group_id: UUID | None) -> bool:
    principal = ctx.principal
    if principal is None or not principal.is_human:
        return False
    grant = principal.grants.get(ARGS_SCOPE)
    if grant is None:
        return False
    return grant.group_ids is None or agent_group_id in grant.group_ids


@router.get(API_PREFIX + "/held-actions")
async def list_held_actions(
    ctx: Annotated[AuthContext, Depends(guard("listHeldActions"))],
    state: Annotated[list[Annotated[str, Query(pattern=_STATES)]] | None, Query()] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    tool: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    include: Annotated[str | None, Query(pattern="^args$")] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    """``state`` may repeat (any of); ``include=args`` adds the scrubbed arguments for callers
    allowed to see them (others get ``args: null``)."""
    states = sorted(set(state)) if state else None
    page = PageQuery.of(limit, cursor, state=states, agent_id=agent_id, tool=tool)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = _LIST_SQL
        groups = ctx.group_filter()  # D53: a monitor key sees its watched groups only
        if groups is not None:
            args.append(list(groups))
            sql += f" AND a.agent_group_id = ANY(${len(args)}::uuid[])"
        for column, value in (("h.agent_id", agent_id), ("h.tool", tool)):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        if states:
            args.append(states)
            sql += f" AND h.state = ANY(${len(args)}::text[])"
        outcome = await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("h.created_at", "h.id"),
            descending=True,
            serialize=lambda row: row,
        )
        views = []
        for row in outcome.body["data"]:
            opened = None
            if include == "args" and ctx.request is not None:
                if _may_see_args(ctx, row["list_agent_group_id"]):
                    opened = await open_args(
                        conn, ctx.request, ctx.tenant_id, row["args_payload_ref"]
                    )
            views.append(held_view(row, args=opened))
        outcome.body["data"] = views
        return outcome

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/held-actions/{held_action_id}")
async def get_held_action(
    held_action_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getHeldAction"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(_HELD_SQL, ctx.tenant_id, held_action_id)
        if row is None:
            raise ProblemError("not_found")
        group = await conn.fetchval(_AGENT_GROUP_SQL, ctx.tenant_id, row["agent_id"])
        await check_object(ctx, group_id=group, agent_id=row["agent_id"])
        principal = ctx.principal
        args = None
        if principal is not None and principal.is_human and ctx.request is not None:
            args = await open_args(conn, ctx.request, ctx.tenant_id, row["args_payload_ref"])
        return Outcome(held_view(row, args=args, history=True), etag=held_etag(row))

    return await run_read(ctx, work)


async def _check_decider(
    conn: Any, ctx: AuthContext, row: dict[str, Any], body: HeldActionAction
) -> None:
    """Pending and in time; never the requester; never the person the agent acted for (approve);
    a second approval from someone else."""
    ctx.action(body.action, step_up_required=bool(row["sensitive"]))
    principal = ctx.principal
    assert principal is not None
    expired = await conn.fetchval("SELECT $1::timestamptz <= now()", row["expires_at"])
    if row["state"] != "pending" or expired:
        raise ProblemError(
            "action_not_pending",
            f"held action is {row['state'] if not expired else 'past its hold timeout'}",
            extensions={"state": row["state"]},
        )
    if principal.id == row["requested_by_key_id"]:
        raise await refuse(ctx, "self_approval", "the requester cannot decide its own hold")
    if body.action != "approve":
        return
    if principal.id == row["on_behalf_of_user_id"]:
        raise await refuse(
            ctx, "self_approval", "the agent acted on your behalf: someone else must approve"
        )
    if any(a.get("user_id") == str(principal.id) for a in row["approvals"] or []):
        raise ProblemError("duplicate_approver", "a second approval must come from someone else")


async def _deny(conn: Any, ctx: AuthContext, row: dict[str, Any], reason: str) -> Any:
    principal = ctx.principal
    assert principal is not None
    now = await conn.fetchval("SELECT now()")
    trail = history.entry(
        "denied",
        now,
        user_id=principal.id,
        reason=reason,
        step_up=bool(row["sensitive"]),
        approvals=len(row["approvals"] or []),
    )
    return await conn.fetchrow(
        "UPDATE sibyl.held_action SET state = 'denied', decision = 'deny',"
        " decided_by_user_id = $3, decided_at = now(), decision_reason = $4,"
        " history = history || $5::jsonb WHERE tenant_id = $1 AND id = $2 RETURNING *",
        ctx.tenant_id,
        row["id"],
        principal.id,
        reason,
        [trail],
    )


async def _approve(
    conn: Any, ctx: AuthContext, row: dict[str, Any], reason: str
) -> tuple[Any, bool, dict[str, Any]]:
    """Record one approval; the last one needed releases the action and, for a call under a
    cumulative cap the cap had not counted, adds it to the window."""
    principal = ctx.principal
    assert principal is not None
    tenant = ctx.tenant_id
    now = await conn.fetchval("SELECT now()")
    session = None if principal.session_id is None else str(principal.session_id)
    approvals = [
        *(row["approvals"] or []),
        {"user_id": str(principal.id), "session_id": session, "at": history.stamp(now)},
    ]
    required = int(row["approvals_required"])
    final = len(approvals) >= required
    trail = history.entry(
        "approved" if final else "approval",
        now,
        user_id=principal.id,
        reason=reason,
        step_up=bool(row["sensitive"]),
        approvals=len(approvals),
    )
    extra: dict[str, Any] = {"approvals": len(approvals), "approvals_required": required}
    if not final:
        updated = await conn.fetchrow(
            "UPDATE sibyl.held_action SET approvals = $3, history = history || $4::jsonb"
            " WHERE tenant_id = $1 AND id = $2 RETURNING *",
            tenant,
            row["id"],
            approvals,
            [trail],
        )
        return updated, False, extra
    counted = await service.count_approved(conn, tenant, row, now)
    if row["counter_key"] is not None:
        extra["counted_toward_cap"] = counted
    updated = await conn.fetchrow(
        "UPDATE sibyl.held_action SET state = 'approved', decision = 'allow', approvals = $3,"
        " decided_by_user_id = $4, decided_at = now(), decision_reason = $5,"
        " history = history || $6::jsonb,"
        " counter_applied_at = CASE WHEN $7::bool THEN now() END"
        " WHERE tenant_id = $1 AND id = $2 RETURNING *",
        tenant,
        row["id"],
        approvals,
        principal.id,
        reason,
        [trail],
        counted,
    )
    return updated, True, extra


async def _decide(conn: Any, ctx: AuthContext, row: dict[str, Any], body: HeldActionAction) -> Any:
    await _check_decider(conn, ctx, row, body)
    principal = ctx.principal
    assert principal is not None
    reason = body.reason.strip()
    session = None if principal.session_id is None else str(principal.session_id)
    elapsed = int(
        await conn.fetchval(
            "SELECT extract(epoch FROM now() - $1::timestamptz)::int", row["created_at"]
        )
    )
    if body.action == "deny":
        updated = await _deny(conn, ctx, row, reason)
        action, final = "action.denied", True
        extra: dict[str, Any] = {}
    else:
        updated, final, extra = await _approve(conn, ctx, row, reason)
        action = "action.approved"
    updated = dict(updated)
    receipt = await audit(
        conn,
        ctx,
        action,
        resource_type="held_action",
        resource_id=row["id"],
        reason=reason,
        detail={
            "held_action_id": row["id"],
            "agent_id": row["agent_id"],
            "tool": row["tool"],
            "decided_by": principal.id,
            "decision_session_id": session,
            "elapsed_s": elapsed,
            **extra,
        },
    )
    if final:
        await _emit(conn, ctx, "action.decided", updated)
    return updated, receipt


@router.post(API_PREFIX + "/held-actions/{held_action_id}/actions")
async def act_on_held_action(
    held_action_id: UUID,
    body: HeldActionAction,
    ctx: Annotated[AuthContext, Depends(guard("actOnHeldAction"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(_HELD_SQL + " FOR UPDATE", ctx.tenant_id, held_action_id)
        if row is None:
            raise ProblemError("not_found")
        updated, receipt = await _decide(conn, ctx, dict(row), body)
        args = None
        if ctx.request is not None:
            args = await open_args(conn, ctx.request, ctx.tenant_id, updated["args_payload_ref"])
        view = held_view(updated, args=args, history=True)
        return Outcome(view, etag=held_etag(updated), receipt=receipt)

    try:
        return await run_write(ctx, work, idempotent=True)
    except ProblemError as exc:
        if exc.code in history.RECORDED_REFUSALS:
            await history.record_refusal(ctx, held_action_id, body.reason, exc.code)
        raise
