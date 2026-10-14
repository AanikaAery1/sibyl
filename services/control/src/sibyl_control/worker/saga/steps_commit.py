"""Saga steps that move routing and close out: ``write_routing`` → ``create_handoff_tasks`` →
``mark_alert_actioned``."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ..handoff import tasks as handoff_tasks
from ..handoff.side_effects import ledger_of, unsafe_to_resume
from . import routing, viability
from .model import SYSTEM, TIER_RTO_S, Actor, Env, SagaError, Target
from .rows import (
    Progress,
    Row,
    _agent,
    _alerts,
    _audit,
    _uuid,
    allowed_from,
    finish,
    opened,
    results,
    saga_actor,
    save,
    with_result,
)
from .steps_prepare import failure_mode_of


@dataclass(frozen=True)
class RoutingPlan:
    to_state: str
    target: Mapping[str, Any] | None
    trigger: str
    actor: Actor
    audit_action: str
    reason: str | None
    approval_id: UUID | None
    audit_detail: Mapping[str, Any] | None = None


async def _routing_plan(conn: Any, tenant: UUID, row: Row, current: str) -> RoutingPlan:
    chosen = results(row).get("check_viability", {}).get("chosen") or {}
    to_state = str(chosen.get("to_state") or "failed_over")
    target = chosen.get("target")
    actor = saga_actor(row)
    reason = opened(row).get("reason")
    approval_id = row.get("approval_id")
    timeout = results(row).get("approval_timeout")
    if approval_id is not None:
        approval = await conn.fetchrow(
            "SELECT state, decided_by_user_id, decision_reason FROM sibyl.approval"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            approval_id,
        )
        if approval is not None and approval["state"] == "approved":
            decision = results(row).get("decision") or {}
            approver = Actor(
                "human",
                user_id=approval["decided_by_user_id"],
                session_id=_uuid(decision.get("session_id")),
            )
            trigger = "approval" if current in ("awaiting_approval", "degraded") else "operator"
            return RoutingPlan(
                to_state,
                target,
                trigger,
                approver,
                "override.by_human",
                approval["decision_reason"] or "approved",
                approval_id,
            )
        if timeout and timeout.get("policy") == "fail_safe":
            return RoutingPlan(
                to_state,
                target,
                "approval_timeout",
                SYSTEM,
                "route.changed",
                "approval timed out",
                approval_id,
            )
        raise SagaError("approval_not_pending", "the approval was not granted")
    if actor.kind == "human":
        return RoutingPlan(to_state, target, "operator", actor, "override.by_human", reason, None)
    trigger = "policy" if actor.kind == "policy" else "rule"
    return RoutingPlan(to_state, target, trigger, actor, "route.changed", reason, None)


async def _recheck_viability(conn: Any, env: Env, tenant: UUID, row: Row) -> None:
    """After an approval wait (up to ``approval_timeout_s``) the chosen target is checked again:
    a credential revoked or a provider that went down meanwhile is never routed to."""
    chosen = results(row).get("check_viability", {}).get("chosen") or {}
    info = opened(row)
    target = Target.from_json(info.get("target"))
    if target is None and chosen.get("step_id"):
        target = Target(step_id=UUID(str(chosen["step_id"])))
    if target is None:
        return
    agent = await _agent(conn, tenant, row["agent_id"])
    ctx = await viability.load_context(
        conn,
        tenant,
        agent,
        routing_state=str(row["from_state"]),
        failure_mode=failure_mode_of(row),
        excluded=[UUID(p) for p in info.get("excluded_provider_ids") or ()],
        demo_mode=env.demo_mode,
    )
    again, candidates = await viability.choose(conn, ctx, target=target)
    if again is None:
        raise SagaError(
            "target_not_viable",
            "the approved target is no longer viable",
            extensions={"candidates": [c.as_json() for c in candidates]},
        )


async def _audit_started(
    conn: Any,
    env: Env,
    tenant: UUID,
    row: Row,
    transition_id: str,
    target: Mapping[str, Any] | None,
) -> None:
    """``failover.started`` (actors rule/system, security-auditor §3) once routing moved for an
    automated saga; a human-requested one is audited as ``override.by_human`` instead."""
    actor = saga_actor(row)
    if not env.completion_audit or actor.kind not in ("rule", "policy", "system"):
        return
    await _audit(
        conn,
        env,
        tenant,
        "failover.started",
        actor if actor.kind == "rule" else SYSTEM,
        resource_type="agent",
        resource_id=row["agent_id"],
        detail={
            "transition_id": transition_id,
            "to_target": target,
            "steps_ok": [s for s in ("validate", "check_viability") if s in results(row)],
        },
    )


async def step_write_routing(conn: Any, env: Env, tenant: UUID, row: Row) -> tuple[Row, Progress]:
    state = await routing.state_of(conn, tenant, row["agent_id"])
    if state is None or state["state"] == "killed":
        row = await finish(conn, env, tenant, row, "cancelled", "agent_killed")
        return row, Progress("cancelled", "write_routing", "agent_killed")
    prior = results(row).get("write_routing")
    if prior is None:
        if row.get("approval_id") is not None:
            await _recheck_viability(conn, env, tenant, row)
        plan = await _routing_plan(conn, tenant, row, state["state"])
        if state["state"] not in (*allowed_from(row), "awaiting_approval"):
            raise SagaError("stale_precondition", f"agent is {state['state']}")
        applied = await routing.apply(
            conn,
            tenant,
            row["agent_id"],
            expected_from=state["state"],
            to_state=plan.to_state,
            trigger=plan.trigger,
            actor=plan.actor,
            idempotency_key=f"failover:{row['id']}:write_routing",
            audit_action=plan.audit_action,
            failover_id=row["id"],
            target=plan.target,
            rule_codes=row.get("rule_codes") or [],
            alert_ids=_alerts(row),
            health_snapshot_id=row.get("health_snapshot_id"),
            approval_id=plan.approval_id,
            reason=plan.reason,
            audit_detail=plan.audit_detail,
            request_id=env.request_id,
        )
        prior = {
            "transition_id": str(applied.transition_id),
            "routing_version": applied.routing_version,
            "to_state": plan.to_state,
            "trigger": plan.trigger,
        }
        await _audit_started(conn, env, tenant, row, prior["transition_id"], plan.target)
    row = await save(
        conn,
        env,
        tenant,
        row,
        step="create_handoff_tasks",
        to_state=prior["to_state"],
        routing_transition_id=UUID(prior["transition_id"]),
        step_results=with_result(row, "write_routing", prior),
    )
    return row, Progress("continue", "create_handoff_tasks")


async def step_create_handoff_tasks(
    conn: Any, env: Env, tenant: UUID, row: Row
) -> tuple[Row, Progress]:
    chosen = results(row).get("check_viability", {}).get("chosen") or {}
    info = opened(row)
    to_humans = chosen.get("kind") == "human_queue"
    seen = await handoff_tasks.in_flight(conn, tenant, row["agent_id"])
    # A-4: in-flight work with a recorded non-idempotent side effect never continues on the
    # new route by itself; it is held for the operator queue (built by the worker role).
    must_hold = any(unsafe_to_resume(t) for t in seen)
    if not to_humans and not must_hold:
        record: dict[str, Any] = {
            "in_flight": len(seen),
            "continued_on_new_route": len(seen),
            "created": [],
            "held_for_operator": [],
            "side_effect_ledger": ledger_of(seen)[: handoff_tasks.MAX_LEDGER_ENTRIES],
        }
    else:
        if not env.can_build_handoff:
            row = await save(conn, env, tenant, row, claim_lock_until=None, claimed_by="api")
            return row, Progress("yield", "create_handoff_tasks")
        agent = await _agent(conn, tenant, row["agent_id"])
        codes = list(row.get("rule_codes") or [])
        actor = saga_actor(row)
        record = await handoff_tasks.create_for_saga(
            conn,
            tenant,
            handoff_tasks.SagaTaskSpec(
                failover_id=row["id"],
                transition_id=row.get("routing_transition_id"),
                agent=agent,
                failure_mode=failure_mode_of(row) or "tool_failure",
                trigger_kind="operator" if actor.kind == "human" else "rule",
                rule_code=codes[0] if codes else None,
                alert_id=row.get("trigger_alert_id"),
                health_snapshot_id=row.get("health_snapshot_id"),
                reason=str(info.get("reason") or "Detected by the Sibyl rules engine."),
                actor=actor if actor.kind in ("human", "rule", "system") else SYSTEM,
            ),
            audit=env.audit,
            outbox=env.outbox,
            request_id=env.request_id,
            hold_unsafe_only=not to_humans,
            seen=seen,
        )
    row = await save(
        conn,
        env,
        tenant,
        row,
        step="mark_alert_actioned",
        step_results=with_result(row, "create_handoff_tasks", record),
    )
    return row, Progress("continue", "mark_alert_actioned")


async def _rto(conn: Any, tenant: UUID, row: Row) -> dict[str, Any]:
    """sre §4.1: trigger (alert first fired, else saga opened) → serving on a viable route."""
    info = await conn.fetchrow(
        "SELECT extract(epoch FROM now() - coalesce(a.first_fired_at, $3))::int AS rto_s,"
        " coalesce(p.rto_s, CASE g.tier WHEN 1 THEN $4::int WHEN 2 THEN $5::int ELSE $6::int END)"
        "   AS target"
        " FROM sibyl.agent g LEFT JOIN sibyl.alert a ON a.tenant_id = g.tenant_id AND a.id = $7"
        " LEFT JOIN sibyl.continuity_plan p ON p.tenant_id = g.tenant_id AND p.agent_id = g.id"
        " WHERE g.tenant_id = $1 AND g.id = $2",
        tenant,
        row["agent_id"],
        row["created_at"],
        TIER_RTO_S[1],
        TIER_RTO_S[2],
        TIER_RTO_S[3],
        row.get("trigger_alert_id"),
    )
    if info is None:
        return {}
    return {
        "rto_s": info["rto_s"],
        "rto_target_s": info["target"],
        "rto_met": info["rto_s"] <= info["target"],
    }


async def step_mark_alert_actioned(
    conn: Any, env: Env, tenant: UUID, row: Row
) -> tuple[Row, Progress]:
    alerts = _alerts(row)
    marked = 0
    if alerts:
        marked = len(
            await conn.fetch(
                "UPDATE sibyl.alert SET failover_id = $2 WHERE tenant_id = $1"
                " AND id = ANY($3::uuid[]) AND failover_id IS NULL RETURNING id",
                tenant,
                row["id"],
                alerts,
            )
        )
    rto = await _rto(conn, tenant, row)
    out = with_result(row, "mark_alert_actioned", {"alerts": marked})
    out["done"] = rto
    row = await save(
        conn,
        env,
        tenant,
        row,
        step="done",
        state="done",
        finished_at=await conn.fetchval("SELECT now()"),
        claim_lock_until=None,
        step_results=out,
    )
    if env.completion_audit:
        actor = saga_actor(row)
        written = results(row).get("write_routing") or {}
        await _audit(
            conn,
            env,
            tenant,
            "failover.completed",
            actor if actor.kind in ("rule", "system", "human") else SYSTEM,
            resource_type="agent",
            resource_id=row["agent_id"],
            reason=opened(row).get("reason") if actor.kind == "human" else None,
            detail={
                "transition_id": written.get("transition_id"),
                "to_target": (results(row).get("check_viability", {}).get("chosen") or {}).get(
                    "target"
                ),
                "steps_ok": [
                    s
                    for s in (
                        "validate",
                        "check_viability",
                        "write_routing",
                        "create_handoff_tasks",
                        "mark_alert_actioned",
                    )
                    if s in results(row)
                ],
                "incident_id": str(row["id"]),
                **rto,
            },
        )
    return row, Progress("done", "done")
