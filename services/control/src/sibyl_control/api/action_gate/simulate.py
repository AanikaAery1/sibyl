"""Policy dry runs (ACTION-GATE.md §3; lane AG-LIVE adds the draft): decide a sample call with
the pure evaluator and write nothing (no business row, no counter; the Idempotency-Key record is
the only write, like every POST).

* ``POST /action-policies/{policy_id}/simulate``: a stored version.
* ``POST /action-policies/simulate``: an unsaved document (the policy editor). It is normalised
  with the create defaults under a placeholder id, so the answer's ``policy_id`` is null when the
  draft decides.

With ``agent_id`` the simulated document takes the place of the approved policy of its own scope
and is combined with the agent's other approved policies (most restrictive wins), and an
enforced allowlist without a list of its own takes the agent identity's declared tools, exactly
as enforcement would see it.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sibyl_schemas import action_gate as ag

from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, jsonable, run_write
from . import service
from .models import ActionPolicyDraftSimulate, ActionSimulate

router = APIRouter()
DRAFT_POLICY_ID = "00000000-0000-0000-0000-000000000000"
Scope = tuple[str, UUID | None, UUID | None]
"""(scope_kind, agent_id, agent_group_id) of the simulated document."""


def _counter(need: ag.CounterNeed | None, counters: Mapping[str, Any] | None) -> Any:
    if need is None:
        return None
    current = (
        None if counters is None or need.counter_key not in counters else counters[need.counter_key]
    )
    return {
        "key": need.counter_key,
        "amount": need.increment,
        "max": need.max,
        "window_s": int(need.window_s),
        "value": None if current is None else str(current),
        "window_start": None,
    }


def _answer(
    decision: ag.Decision,
    counters: Mapping[str, Any] | None,
    *,
    state: str | None,
    now: datetime,
) -> dict[str, Any]:
    draft = decision.policy_id == DRAFT_POLICY_ID
    body: dict[str, Any] = jsonable(
        {
            "effect": service.effect_of(decision),
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "matched_paths": list(decision.matched_paths),
            "policy_id": None if draft else decision.policy_id,
            "policy_version": None if draft else decision.policy_version,
            "counter": _counter(decision.needs_counter, counters),
            "sensitive": bool(decision.sensitive),
            "hold_timeout_s": decision.hold_timeout_s,
            "policy_state": state,
            "evaluated_at": now,
        }
    )
    return body


async def _decide(
    conn: Any,
    tenant: UUID,
    document: dict[str, Any],
    scope: Scope | None,
    body: ActionSimulate | ActionPolicyDraftSimulate,
) -> ag.Decision:
    """Evaluate ``document`` alone, or for ``body.agent_id`` beside the agent's other approved
    policies (those of another scope than ``scope``)."""
    others: list[ag.ActionPolicy] = []
    if body.agent_id is not None:
        agent = await conn.fetchrow(
            "SELECT id, agent_group_id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
            tenant,
            body.agent_id,
        )
        if agent is None:
            raise ProblemError("not_found", "agent not found")
        tools = await service.allowed_tools(conn, tenant, body.agent_id)
        document = service.with_allowlist(document, tools)
        found = await service.applicable(conn, tenant, dict(agent))
        others = [
            p
            for r, p in zip(found.rows, found.policies, strict=True)
            if (r["scope_kind"], r["agent_id"], r["agent_group_id"]) != scope
        ]
    policy = service.parse_document(document)
    return ag.evaluate_all([policy, *others], body.tool, body.args, body.counters)


@router.post(API_PREFIX + "/action-policies/simulate")
async def simulate_action_policy_draft(
    body: ActionPolicyDraftSimulate,
    ctx: Annotated[AuthContext, Depends(guard("simulateActionPolicyDraft"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        scope = await _draft_scope(conn, tenant, body)
        document = {
            **service.DOCUMENT_DEFAULTS,
            **body.document,
            "policy_id": DRAFT_POLICY_ID,
            "version": 1,
        }
        decision = await _decide(conn, tenant, document, scope, body)
        now = await conn.fetchval("SELECT now()")
        return Outcome(_answer(decision, body.counters, state=None, now=now))

    return await run_write(ctx, work, idempotent=True)


async def _draft_scope(conn: Any, tenant: UUID, body: ActionPolicyDraftSimulate) -> Scope | None:
    """The draft's scope, checked against the agent it is simulated for (422 when it cannot
    apply to that agent; 404 when the scope object does not exist)."""
    kind = body.scope_kind or ("agent" if body.agent_id is not None else None)
    if kind is None:
        if body.scope_id is not None:
            raise ProblemError("validation_failed", "scope_id needs scope_kind")
        return None
    if kind == "tenant":
        if body.scope_id is not None:
            raise ProblemError("validation_failed", "a tenant-scope policy takes no scope_id")
        return ("tenant", None, None)
    target = body.scope_id or (body.agent_id if kind == "agent" else None)
    if target is None:
        raise ProblemError("validation_failed", f"a {kind} draft needs scope_id or agent_id")
    table = "agent" if kind == "agent" else "agent_group"
    found = await conn.fetchval(
        f"SELECT 1 FROM sibyl.{table} WHERE tenant_id = $1 AND id = $2",  # noqa: S608 - fixed
        tenant,
        target,
    )
    if found is None:
        raise ProblemError("not_found", f"{table} {target} does not exist")
    if body.agent_id is not None:
        group = await conn.fetchval(
            "SELECT agent_group_id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
            tenant,
            body.agent_id,
        )
        covers = target == body.agent_id if kind == "agent" else target == group
        if not covers:
            raise ProblemError("validation_failed", "the draft's scope does not cover agent_id")
    return (kind, target, None) if kind == "agent" else (kind, None, target)


@router.post(API_PREFIX + "/action-policies/{policy_id}/simulate")
async def simulate_action_policy(
    policy_id: UUID,
    body: ActionSimulate,
    ctx: Annotated[AuthContext, Depends(guard("simulateActionPolicy"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.action_policy WHERE tenant_id = $1 AND id = $2", tenant, policy_id
        )
        if row is None:
            raise ProblemError("not_found")
        document = service.json_value(row["document"])
        scope = (row["scope_kind"], row["agent_id"], row["agent_group_id"])
        decision = await _decide(conn, tenant, document, scope, body)
        now = await conn.fetchval("SELECT now()")
        return Outcome(_answer(decision, body.counters, state=row["state"], now=now))

    return await run_write(ctx, work, idempotent=True)
