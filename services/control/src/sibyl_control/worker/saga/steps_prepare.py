"""Saga steps before routing moves: ``validate`` and ``check_viability`` (which may open an
approval and park the saga in ``waiting_approval``)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from ...core.outbox import OutboxMessage
from . import routing, viability
from .gating import BREAKER_THRESHOLD, approval_for, at_least
from .model import DEFAULT_APPROVAL_TIMEOUT_S, RULE_FAILURE_MODE, Actor, Env, SagaError, Target
from .rows import (
    FAILOVER_FROM,
    Progress,
    Row,
    _agent,
    _alerts,
    _audit,
    allowed_from,
    finish,
    opened,
    results,
    saga_actor,
    save,
    with_result,
)


async def suppress_for_hold(conn: Any, tenant: UUID, alert_id: UUID | None) -> None:
    """D21: a blocked rule/policy actor counts on the alert, at most once per evaluation:
    ``hold_suppressed_at`` (last suppression) must predate the alert's ``last_evaluated_at``."""
    if alert_id is None:
        return
    await conn.execute(
        "UPDATE sibyl.alert SET hold_suppressed_count = hold_suppressed_count + 1,"
        " hold_suppressed_at = now() WHERE tenant_id = $1 AND id = $2"
        " AND (hold_suppressed_at IS NULL OR hold_suppressed_at < last_evaluated_at)",
        tenant,
        alert_id,
    )


async def _prediction_persisted(conn: Any, env: Env, row: Row) -> bool:
    """D39: after the 20 s degraded pause the agent's latest 15 m prediction is still at the
    band the saga was opened for (predictions are sparse: no newer row means unchanged)."""
    latest = await conn.fetchval(
        "SELECT probability_band FROM sibyl.prediction WHERE tenant_id = $1 AND agent_id = $2"
        " AND horizon_s = 900 AND predicted_at > now() - interval '1 hour'"
        " ORDER BY predicted_at DESC, id DESC LIMIT 1",
        row["tenant_id"],
        row["agent_id"],
    )
    floor = (opened(row).get("prediction") or {}).get("persist_band") or env.automation_band
    return latest is not None and at_least(str(latest), str(floor))


async def _revert_degrade(conn: Any, env: Env, tenant: UUID, row: Row) -> None:
    info = results(row).get("degrade")
    if not info:
        return
    state = await routing.state_of(conn, tenant, row["agent_id"])
    if state is None or state["state"] != "degraded":
        return
    if str(state["last_transition_id"]) != str(info.get("transition_id")):
        return  # somebody acted since; leave it
    await routing.apply(
        conn,
        tenant,
        row["agent_id"],
        expected_from="degraded",
        to_state="active",
        trigger="rule",
        actor=saga_actor(row),
        idempotency_key=f"failover:{row['id']}:revert_degrade",
        audit_action="route.changed",
        failover_id=row["id"],
        rule_codes=row["rule_codes"],
        reason="prediction did not persist after the degraded pause",
    )


async def step_validate(conn: Any, env: Env, tenant: UUID, row: Row) -> tuple[Row, Progress]:
    actor = saga_actor(row)
    if row["cancel_requested"]:
        row = await finish(conn, env, tenant, row, "cancelled", "cancel_requested")
        return row, Progress("cancelled", "validate", "cancel_requested")
    state = await routing.state_of(conn, tenant, row["agent_id"])
    if state is None:
        raise SagaError("invalid_transition", "the agent has no routing state")
    if state["state"] == "killed":
        row = await finish(conn, env, tenant, row, "cancelled", "agent_killed")
        return row, Progress("cancelled", "validate", "agent_killed")
    if actor.automated and await routing.hold_active(conn, tenant, row["agent_id"]):
        await suppress_for_hold(conn, tenant, row.get("trigger_alert_id"))
        await _revert_degrade(conn, env, tenant, row)
        row = await finish(conn, env, tenant, row, "cancelled", "operator_hold")
        return row, Progress("cancelled", "validate", "operator_hold")
    if state["state"] not in allowed_from(row):
        raise SagaError("stale_precondition", f"agent is {state['state']}")
    info = opened(row)
    if info.get("degrade_then_auto") and not await _prediction_persisted(conn, env, row):
        await _revert_degrade(conn, env, tenant, row)
        row = await finish(conn, env, tenant, row, "cancelled", "prediction_not_persisted")
        return row, Progress("cancelled", "validate", "prediction_not_persisted")
    row = await save(
        conn,
        env,
        tenant,
        row,
        step="check_viability",
        step_results=with_result(row, "validate", {"routing_state": state["state"], "ok": True}),
    )
    return row, Progress("continue", "check_viability")


def failure_mode_of(row: Mapping[str, Any]) -> str | None:
    info = opened(row)
    mode = info.get("failure_mode")
    if mode:
        return str(mode)
    for code in row.get("rule_codes") or ():
        if code in RULE_FAILURE_MODE:
            return RULE_FAILURE_MODE[code]
    return None


async def breaker_open(conn: Any, tenant: UUID, agent_id: UUID) -> bool:
    """ML §4.6 guard rail 5: two undone or fp-verdicted automated transitions in 7 days."""
    n = await conn.fetchval(
        "SELECT (SELECT count(*) FROM sibyl.routing_transition t"
        "         WHERE t.tenant_id = $1 AND t.agent_id = $2 AND t.actor_kind IN ('rule', 'policy')"
        "           AND t.created_at > now() - interval '7 days'"
        "           AND EXISTS (SELECT 1 FROM sibyl.routing_transition u WHERE u.tenant_id = $1"
        "                         AND u.inverse_of = t.id))"
        "    + (SELECT count(*) FROM sibyl.alert a WHERE a.tenant_id = $1 AND a.agent_id = $2"
        "         AND a.verdict = 'fp' AND a.failover_id IS NOT NULL"
        "         AND a.first_fired_at > now() - interval '7 days')",
        tenant,
        agent_id,
    )
    return int(n or 0) >= BREAKER_THRESHOLD


async def step_check_viability(conn: Any, env: Env, tenant: UUID, row: Row) -> tuple[Row, Progress]:
    agent = await _agent(conn, tenant, row["agent_id"])
    state = await routing.state_of(conn, tenant, row["agent_id"])
    info = opened(row)
    ctx = await viability.load_context(
        conn,
        tenant,
        agent,
        routing_state=state["state"],
        failure_mode=failure_mode_of(row),
        excluded=[UUID(p) for p in info.get("excluded_provider_ids") or ()],
        demo_mode=env.demo_mode,
    )
    chosen, candidates = await viability.choose(
        conn, ctx, target=Target.from_json(info.get("target"))
    )
    record: dict[str, Any] = {"candidates": [c.as_json() for c in candidates]}
    if chosen is None:
        raise SagaError(
            "target_not_viable",
            "no fallback step is viable",
            extensions={"candidates": record["candidates"]},
        )
    record["chosen"] = {
        **chosen.as_json(),
        "target": routing.target_json(
            chosen.routing_kind,
            provider_id=chosen.provider_id,
            model_id=chosen.model_id,
            agent_id=chosen.backup_agent_id,
            step_id=chosen.step_id,
        ),
        "to_state": "degraded" if chosen.kind == "degraded_safe_mode" else "failed_over",
    }
    actor = saga_actor(row)
    plan = ctx.plan or {}
    need = approval_for(
        tier=ctx.tier,
        trigger=str(info.get("trigger") or "detected"),
        actor_kind=actor.kind,
        step_kind=chosen.kind,
        preemptive_mode=str(
            (info.get("prediction") or {}).get("mode") or plan.get("preemptive_mode") or "auto"
        ),
        breaker_open=await breaker_open(conn, tenant, row["agent_id"]),
    )
    row = await save(
        conn,
        env,
        tenant,
        row,
        chosen_step_id=chosen.step_id,
        step_results=with_result(row, "check_viability", record),
    )
    if need is None:
        row = await save(conn, env, tenant, row, step="write_routing")
        return row, Progress("continue", "write_routing")
    row = await request_approval(conn, env, tenant, row, agent, chosen, need, plan, state)
    return row, Progress("waiting", "write_routing")


async def request_approval(
    conn: Any,
    env: Env,
    tenant: UUID,
    row: Row,
    agent: Row,
    chosen: viability.Candidate,
    requested_action: str,
    plan: Mapping[str, Any],
    state: Mapping[str, Any],
) -> Row:
    actor = saga_actor(row)
    timeout_s = int(plan.get("approval_timeout_s") or DEFAULT_APPROVAL_TIMEOUT_S)
    evidence = {
        "rule_codes": list(row.get("rule_codes") or []),
        "step_id": None if chosen.step_id is None else str(chosen.step_id),
        "step_kind": chosen.kind,
        "trigger": opened(row).get("trigger"),
        "prediction": opened(row).get("prediction"),
        "candidates": results(row).get("check_viability", {}).get("candidates", [])[:10],
    }
    approval = await conn.fetchrow(
        "INSERT INTO sibyl.approval (tenant_id, failover_id, agent_id, requested_action, risk,"
        " tier,"
        " requested_by_kind, requested_by_rule_id, requested_by_user_id, alert_id,"
        " health_snapshot_id,"
        " evidence, expires_at, timeout_policy)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb,"
        "         now() + make_interval(secs => $13), $14)"
        " RETURNING id, timeout_policy, expires_at, evidence",
        tenant,
        row["id"],
        row["agent_id"],
        requested_action,
        chosen.risk,
        int(agent["tier"]),
        "human" if actor.kind == "human" else "rule",
        actor.rule_id if actor.kind != "human" else None,
        actor.user_id if actor.kind == "human" else None,
        row.get("trigger_alert_id"),
        row.get("health_snapshot_id"),
        evidence,
        timeout_s,
        str(plan.get("approval_timeout_policy") or "hold"),
    )
    transition_id = None
    if actor.kind != "human" and state["state"] in FAILOVER_FROM:
        applied = await routing.apply(
            conn,
            tenant,
            row["agent_id"],
            expected_from=state["state"],
            to_state="awaiting_approval",
            trigger="rule" if actor.kind == "rule" else "policy",
            actor=actor,
            idempotency_key=f"failover:{row['id']}:awaiting_approval",
            audit_action="failover.proposed",
            failover_id=row["id"],
            rule_codes=row.get("rule_codes") or [],
            alert_ids=_alerts(row),
            health_snapshot_id=row.get("health_snapshot_id"),
            approval_id=approval["id"],
            audit_detail={
                "rules": list(row.get("rule_codes") or []),
                "evidence_hashes": [],
                "risk": chosen.risk,
                "approval_id": str(approval["id"]),
            },
            request_id=env.request_id,
        )
        transition_id = applied.transition_id
    await _audit(
        conn,
        env,
        tenant,
        "approval.requested",
        actor if actor.kind in ("human", "rule") else Actor("rule"),
        resource_type="approval",
        resource_id=approval["id"],
        reason=opened(row).get("reason") if actor.kind == "human" else None,
        detail={
            "approval_id": str(approval["id"]),
            "agent_id": str(row["agent_id"]),
            "risk": chosen.risk,
            "action": requested_action,
            "requested_by_actor": actor.kind,
            "timeout_policy": approval["timeout_policy"],
            "expires_at": approval["expires_at"].isoformat(),
            "incident_id": str(row["id"]),
        },
    )
    await env.outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "approval.requested",
            "approval",
            approval["id"],
            {
                "approval_id": str(approval["id"]),
                "incident_id": str(row["id"]),
                "agent_id": str(row["agent_id"]),
            },
        ),
    )
    out = with_result(
        row,
        "approval",
        {
            "approval_id": str(approval["id"]),
            "requested_action": requested_action,
            "transition_id": None if transition_id is None else str(transition_id),
        },
    )
    return await save(
        conn,
        env,
        tenant,
        row,
        state="waiting_approval",
        step="write_routing",
        approval_id=approval["id"],
        routing_transition_id=transition_id or row.get("routing_transition_id"),
        step_results=out,
        claim_lock_until=None,
    )
