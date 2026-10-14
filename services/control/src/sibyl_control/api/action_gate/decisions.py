"""``POST /action-decisions`` (ACTION-GATE.md §2.3): the authoritative cumulative
check-and-increment, idempotent per (agent, call_id).

Body ``ActionDecisionRequest`` and answer ``ActionDecisionResult {call_id, within_cap,
counter_value}`` are AG-ENFORCE's wire models. The enforcement point names the policy, rule and
``counter_key`` (``<policy_id>/<rule_id>[/<hash>]``) its local evaluation produced; the control
plane checks that the policy applies to the agent and that the key belongs to that rule, and
takes ``max`` and ``window_s`` from its own copy of the rule (never from the caller). The
window is kept under the policy's stable ``policy_id`` (``service.lineage_key``), so a new
version continues the same window. The counter is incremented only when within the cap, with
one conditional upsert, so concurrent calls never pass it. The answer is stored and a repeated
call_id returns it unchanged. A refused increment is audited with the rule's ``on_exceed``
effect (``action.escalated`` / ``action.blocked``); an accepted one is sampled as
``action.allowed`` (always when sensitive).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends
from fastapi.responses import Response
from pydantic import MISSING
from sibyl_schemas import action_gate as ag

from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, audit, jsonable, load_agent, run_write
from . import service
from .wire import parse_wire

router = APIRouter()


def _answer(row: Any, *, replayed: bool) -> dict[str, Any]:
    body: dict[str, Any] = jsonable(
        {
            "call_id": row["call_id"],
            "within_cap": bool(row["within_cap"]),
            "counter_value": None
            if row["counter_value"] is None
            else service.decimal_text(Decimal(row["counter_value"])),
            "agent_id": row["agent_id"],
            "effect": row["effect"],
            "policy_id": row["policy_id"],
            "policy_version": row["policy_version"],
            "rule_id": row["rule_id"],
            "counter_key": row["counter_key"],
            "max": None
            if row["counter_max"] is None
            else service.decimal_text(Decimal(row["counter_max"])),
            "window_s": row["window_s"],
            "window_start": row["window_start"],
            "replayed": replayed,
        }
    )
    return body


async def _rule(
    conn: Any, tenant: UUID, agent: dict[str, Any], body: ag.ActionDecisionRequest
) -> tuple[Any, ag.ActionPolicy, ag.ActionRule]:
    """The named policy (approved, or superseded while snapshots catch up), applying to this
    agent, and its cumulative rule; the counter key must be that rule's."""
    row = await conn.fetchrow(
        "SELECT * FROM sibyl.action_policy WHERE tenant_id = $1 AND id = $2"
        " AND state IN ('approved', 'superseded')",
        tenant,
        UUID(body.policy_id),
    )
    applies = row is not None and (
        row["scope_kind"] == "tenant"
        or row["agent_id"] == agent["id"]
        or (row["agent_group_id"] is not None and row["agent_group_id"] == agent["agent_group_id"])
    )
    if row is None or not applies:
        raise ProblemError("not_found", "no such policy applies to this agent")
    policy = service.stored_policy(row)
    rule = service.find_rule(policy, body.rule_id)
    if rule is None or rule.cumulative is MISSING:
        raise ProblemError("validation_failed", f"rule {body.rule_id!r} has no cumulative cap")
    prefix = f"{body.policy_id}/{body.rule_id}"
    if body.counter_key != prefix and not body.counter_key.startswith(prefix + "/"):
        raise ProblemError("validation_failed", "counter_key does not belong to this rule")
    return row, policy, rule


@router.post(API_PREFIX + "/action-decisions")
async def decide_action(
    payload: Annotated[dict[str, Any], Body()],
    ctx: Annotated[AuthContext, Depends(guard("decideAction"))],
) -> Response:
    """Body: ``sibyl_schemas.action_gate.ActionDecisionRequest``."""
    body = parse_wire(ag.ActionDecisionRequest, payload)

    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        agent_id = UUID(body.agent_id)
        agent = await load_agent(conn, ctx, agent_id)
        stored = await conn.fetchrow(
            "SELECT * FROM sibyl.action_decision WHERE tenant_id = $1 AND agent_id = $2"
            " AND call_id = $3",
            tenant,
            agent_id,
            body.call_id,
        )
        if stored is not None:
            return Outcome(_answer(stored, replayed=True))
        row, policy, rule = await _rule(conn, tenant, agent, body)
        cap = rule.cumulative
        assert cap is not MISSING
        limits = service.Cap(
            counter_key=service.lineage_key(
                body.counter_key, str(row["id"]), str(row["policy_id"])
            ),
            increment=Decimal(body.increment),
            max=Decimal(str(cap.max)),
            window_s=int(cap.window_s),
        )
        now = await conn.fetchval("SELECT now()")
        result = await service.check_and_increment(conn, tenant, agent_id, limits, now)
        effect = rule.effect if result.accepted else cap.exceed_effect
        effect_text = str(getattr(effect, "value", effect))
        note = "within cap" if result.accepted else f"cap {limits.max} per {limits.window_s}s"
        reason = service.clip_reason(f"{rule.reason} ({note})", "cumulative cap")
        principal = ctx.principal
        assert principal is not None
        stored = await conn.fetchrow(
            "INSERT INTO sibyl.action_decision (tenant_id, agent_id, call_id, tool, policy_id,"
            " policy_version, rule_id, effect, reason, counter_key, window_s, window_start,"
            " amount, counter_value, counter_max, within_cap, args_sha256, source, api_key_id)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,"
            " $18, $19) RETURNING *",
            tenant,
            agent_id,
            body.call_id,
            body.tool,
            row["id"],
            int(row["version_no"]),
            rule.rule_id,
            effect_text,
            reason,
            body.counter_key,
            limits.window_s,
            result.window_start,
            limits.increment,
            result.value,
            limits.max,
            result.accepted,
            bytes.fromhex(body.args_sha256),
            body.source,
            principal.id,
        )
        detail = {
            "agent_id": agent_id,
            "tool": body.tool,
            "call_id": body.call_id,
            "policy_id": row["id"],
            "rule_id": rule.rule_id,
        }
        receipt = None
        if effect_text == "block":
            receipt = await audit(
                conn,
                ctx,
                "action.blocked",
                resource_type="agent",
                resource_id=agent_id,
                reason=reason,
                detail=detail,
            )
        elif effect_text == "escalate":
            receipt = await audit(
                conn,
                ctx,
                "action.escalated",
                resource_type="agent",
                resource_id=agent_id,
                reason=reason,
                detail={**detail, "held_action_id": None},
            )
        else:
            sensitive = any(ag.tool_matches(g, body.tool) for g in policy.sensitive_tools)
            if service.sample_allowed(body.call_id, sensitive=sensitive):
                receipt = await audit(
                    conn,
                    ctx,
                    "action.allowed",
                    resource_type="agent",
                    resource_id=agent_id,
                    reason=reason,
                    detail={**detail, "sampled": not sensitive},
                )
        return Outcome(_answer(stored, replayed=False), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)
