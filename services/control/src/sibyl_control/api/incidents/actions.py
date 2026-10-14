"""Operator incident actions (API.md §6.3), each in the request transaction.

Open (``POST /incidents``): ``failover`` (saga driven inline; tier-1 backup agent → four-eyes
approval, 202), ``degrade`` / ``recover`` / ``quarantine`` (one routing change recorded as a
``done`` saga), ``handoff`` (routing to the human queue inline; the worker builds the tasks,
202), ``kill`` (sugar for an agent-scope kill switch).

Transition (``POST /incidents/{id}/actions``): ``approve`` / ``deny`` (decider ≠ requester),
``undo`` (inverse of the newest automated transition, 30-minute hold, D21), ``clear_hold``
(owner or security_admin), ``release`` (quarantine, or an agent-scope kill with step-up),
``fail_back`` (failing_back at 10 %; the failback loop completes it), ``cancel``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord, audit_actor
from ...core.outbox import OutboxMessage
from ...core.problems import ProblemError
from ...worker.saga import engine, entry, routing
from ...worker.saga.model import OPERATOR_HOLD, Env, SagaOpen, Target
from ..deps import AuthContext
from ..killswitch import service as killswitch
from ..registry._kit import require_scope
from .common import actor_of, api_env
from .models import IncidentAction, IncidentCreate

LIVE = ("pending", "running", "waiting_approval")
BREAKER_WINDOW = timedelta(days=7)


@dataclass(frozen=True)
class Done:
    incident_id: UUID
    status: int  # 201 done, 202 pending / waiting, 200 transition


def _bad(action: str, from_state: str, detail: str) -> ProblemError:
    return ProblemError(
        "invalid_transition", detail, extensions={"from_state": from_state, "action": action}
    )


async def _routing(conn: Any, tenant: UUID, agent_id: UUID) -> Any:
    rs = await routing.state_of(conn, tenant, agent_id)
    if rs is None:
        raise ProblemError("invalid_transition", "the agent has no routing state yet")
    return rs


async def _no_live_saga(conn: Any, tenant: UUID, agent_id: UUID) -> None:
    live = await entry.live_saga(conn, tenant, agent_id)
    if live is not None:
        raise ProblemError("saga_in_flight", extensions={"incident_id": str(live)})


def _request_key(ctx: AuthContext) -> str:
    key = ctx.request.headers.get("idempotency-key", "") if ctx.request is not None else ""
    principal = ctx.principal
    assert principal is not None
    return f"api:{principal.id}:{key}"


async def _simple(
    conn: Any,
    ctx: AuthContext,
    env: Env,
    *,
    agent_id: UUID,
    kind: str,
    from_states: tuple[str, ...],
    to_state: str,
    reason: str,
    audit_action: str,
    audit_detail: dict[str, Any] | None = None,
) -> Done:
    """One operator routing change recorded as a ``done`` saga (degrade, recover, quarantine)."""
    tenant = ctx.tenant_id
    rs = await _routing(conn, tenant, agent_id)
    if rs["state"] not in from_states:
        raise _bad(
            kind, rs["state"], f"agent is {rs['state']}; {kind} needs {', '.join(from_states)}"
        )
    await _no_live_saga(conn, tenant, agent_id)
    actor = actor_of(ctx)
    row, _ = await entry.open_saga(
        conn,
        tenant,
        SagaOpen(
            agent_id=agent_id,
            actor=actor,
            trigger="operator",
            idempotency_key=_request_key(ctx),
            request_idempotency_key=ctx.request.headers.get("idempotency-key")
            if ctx.request
            else None,
            kind=kind,
            priority="immediate",
            reason=reason,
        ),
        inline=True,
        env=env,
    )
    applied = await routing.apply(
        conn,
        tenant,
        agent_id,
        expected_from=rs["state"],
        to_state=to_state,
        trigger="operator",
        actor=actor,
        idempotency_key=f"failover:{row['id']}:write_routing",
        audit_action=audit_action,
        failover_id=row["id"],
        reason=reason,
        audit_detail=audit_detail,
        request_id=env.request_id,
    )
    await engine.save(
        conn,
        env,
        tenant,
        row,
        state="done",
        step="done",
        to_state=to_state,
        routing_transition_id=applied.transition_id,
        finished_at=await conn.fetchval("SELECT now()"),
        claim_lock_until=None,
    )
    return Done(row["id"], 201)


async def _failover(
    conn: Any, ctx: AuthContext, env: Env, body: IncidentCreate, *, target: Target | None
) -> Done:
    tenant = ctx.tenant_id
    rs = await _routing(conn, tenant, body.agent_id)
    allowed = (
        ("active", "degraded", "failed_over")
        if body.action == "handoff"
        else ("active", "degraded")
    )
    if rs["state"] not in allowed:
        raise _bad(body.action, rs["state"], f"agent is {rs['state']}")
    await _no_live_saga(conn, tenant, body.agent_id)
    refs = body.evidence_refs
    row, _ = await entry.open_saga(
        conn,
        tenant,
        SagaOpen(
            agent_id=body.agent_id,
            actor=actor_of(ctx),
            trigger="operator",
            idempotency_key=_request_key(ctx),
            request_idempotency_key=ctx.request.headers.get("idempotency-key")
            if ctx.request
            else None,
            target=target,
            priority="immediate",
            reason=body.reason.strip(),
            alert_ids=tuple(refs.alert_ids) if refs else (),
            trigger_alert_id=refs.alert_ids[0] if refs and refs.alert_ids else None,
            health_snapshot_id=refs.health_snapshot_id if refs else None,
            failure_mode="tool_failure" if body.action == "handoff" else None,
        ),
        inline=True,
        env=env,
    )
    row, progress = await engine.drive(conn, env, tenant, row["id"])
    return Done(row["id"], 201 if progress.status == "done" else 202)


async def open_incident(
    conn: Any, ctx: AuthContext, body: IncidentCreate, agent: dict[str, Any]
) -> Done:
    env = api_env(ctx)
    group = agent["agent_group_id"]
    reason = body.reason.strip()
    action = body.action
    if action == "kill":
        ctx.action("kill", resource_group_id=group)
        principal = ctx.principal
        assert principal is not None
        rs = await _routing(conn, ctx.tenant_id, body.agent_id)
        if rs["state"] == "killed":
            raise _bad("kill", "killed", "the agent is already killed")
        ks = await killswitch.pull(
            conn,
            env,
            ctx.tenant_id,
            actor=actor_of(ctx),
            roles=principal.roles,
            scope_kind="agent",
            scope_id=body.agent_id,
            reason=reason,
            client_ip="api",
        )
        kill_row = await conn.fetchval(
            "SELECT id FROM sibyl.failover WHERE tenant_id = $1 AND agent_id = $2"
            " AND kind = 'kill' AND kill_switch_id = $3",
            ctx.tenant_id,
            body.agent_id,
            ks,
        )
        return Done(kill_row, 201)
    ctx.action(action, resource_group_id=group)
    if action == "degrade":
        return await _simple(
            conn,
            ctx,
            env,
            agent_id=body.agent_id,
            kind="degrade",
            from_states=("active",),
            to_state="degraded",
            reason=reason,
            audit_action="override.by_human",
        )
    if action == "recover":
        return await _simple(
            conn,
            ctx,
            env,
            agent_id=body.agent_id,
            kind="recover",
            from_states=("degraded",),
            to_state="active",
            reason=reason,
            audit_action="override.by_human",
        )
    if action == "quarantine":
        return await _simple(
            conn,
            ctx,
            env,
            agent_id=body.agent_id,
            kind="quarantine",
            from_states=("active", "degraded", "failed_over"),
            to_state="quarantined",
            reason=reason,
            audit_action="quarantine.applied",
            audit_detail={"cause": "operator", "policy_violation_ids": []},
        )
    if action == "handoff":
        return await _failover(conn, ctx, env, body, target=Target(kind="human_queue"))
    target = None
    if body.target is not None:
        t = body.target
        if t.step_id is None and t.kind is None:
            raise ProblemError("validation_failed", "target needs step_id or kind")
        target = Target(
            step_id=t.step_id,
            kind=t.kind,
            provider_id=t.provider_id,
            model_id=t.model_id,
            agent_id=t.agent_id,
        )
    return await _failover(conn, ctx, env, body, target=target)


# --- transitions on an existing incident ------------------------------------------------------


async def _approval(conn: Any, tenant: UUID, incident: dict[str, Any]) -> Any:
    if incident["approval_id"] is None:
        return None
    return await conn.fetchrow(
        "SELECT *, expires_at <= now() AS expired FROM sibyl.approval WHERE tenant_id = $1"
        " AND id = $2 FOR UPDATE",
        tenant,
        incident["approval_id"],
    )


async def _decide(
    conn: Any, ctx: AuthContext, env: Env, incident: dict[str, Any], body: IncidentAction
) -> int:
    tenant = ctx.tenant_id
    ctx.action(body.action)
    approval = await _approval(conn, tenant, incident)
    if (
        approval is None
        or incident["state"] != "waiting_approval"
        or approval["state"] != "pending"
        or approval["expired"]
    ):
        raise ProblemError("approval_not_pending")
    principal = ctx.principal
    assert principal is not None
    requester = approval["requested_by_user_id"] or incident["requested_by_user_id"]
    if requester is not None and requester == principal.id:
        raise ProblemError("self_approval", "the requester cannot decide their own approval")
    reason = body.reason.strip()
    approve = body.action == "approve"
    await conn.execute(
        "UPDATE sibyl.approval SET state = $3, decided_by_user_id = $4, decided_at = now(),"
        " decision_reason = $5 WHERE tenant_id = $1 AND id = $2",
        tenant,
        approval["id"],
        "approved" if approve else "denied",
        principal.id,
        reason,
    )
    elapsed = int(
        await conn.fetchval(
            "SELECT extract(epoch FROM now() - $1::timestamptz)::int", approval["created_at"]
        )
    )
    await env.audit.append(
        conn,
        tenant,
        AuditRecord(
            action="approval.granted" if approve else "approval.denied",
            **audit_actor(principal).fields(),
            resource_type="approval",
            resource_id=approval["id"],
            reason=reason,
            detail={
                "approval_id": str(approval["id"]),
                "agent_id": str(incident["agent_id"]),
                "decided_by": str(principal.id),
                "decision_session_id": None
                if principal.session_id is None
                else str(principal.session_id),
                "elapsed_s": elapsed,
                "incident_id": str(incident["id"]),
            },
            request_id=env.request_id,
        ),
    )
    await env.outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "approval.decided",
            "approval",
            approval["id"],
            {
                "approval_id": str(approval["id"]),
                "incident_id": str(incident["id"]),
                "decision": "approved" if approve else "denied",
            },
        ),
    )
    decision = {"session_id": None if principal.session_id is None else str(principal.session_id)}
    if approve:
        row = await engine.save(
            conn,
            env,
            tenant,
            incident,
            state="running",
            claimed_by="api",
            claim_lock_until=await conn.fetchval("SELECT now()"),
            step_results=engine.with_result(incident, "decision", {**decision, "approved": True}),
        )
        row, progress = await engine.drive(conn, env, tenant, row["id"])
        return 200 if progress.status == "done" else 202
    rs = await routing.state_of(conn, tenant, incident["agent_id"])
    if rs is not None and rs["state"] == "awaiting_approval":
        await routing.apply(
            conn,
            tenant,
            incident["agent_id"],
            expected_from="awaiting_approval",
            to_state="degraded",
            trigger="approval",
            actor=actor_of(ctx),
            idempotency_key=f"failover:{incident['id']}:denied",
            audit_action="override.by_human",
            failover_id=incident["id"],
            approval_id=approval["id"],
            reason=reason,
            request_id=env.request_id,
        )
    row = await engine.save(
        conn,
        env,
        tenant,
        incident,
        step_results=engine.with_result(incident, "decision", {**decision, "approved": False}),
    )
    await engine.finish(conn, env, tenant, row, "cancelled", "approval_denied")
    return 200


async def _cancel_live(conn: Any, env: Env, tenant: UUID, agent_id: UUID) -> None:
    for live in await conn.fetch(
        "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND agent_id = $2"
        " AND state = ANY($3::text[]) FOR UPDATE",
        tenant,
        agent_id,
        list(LIVE),
    ):
        await engine.finish(conn, env, tenant, dict(live), "cancelled", "undone")


async def _breaker(conn: Any, ctx: AuthContext, env: Env, agent_id: UUID) -> None:
    """ML §4.6 rail 5: the second undo in 7 days forces ``preemptive_mode=approval``."""
    n = await conn.fetchval(
        "SELECT count(*) FROM sibyl.routing_transition t WHERE t.tenant_id = $1 AND t.agent_id = $2"
        " AND t.actor_kind IN ('rule', 'policy') AND t.created_at > now() - $3::interval"
        " AND EXISTS (SELECT 1 FROM sibyl.routing_transition u WHERE u.tenant_id = $1"
        "             AND u.inverse_of = t.id)",
        ctx.tenant_id,
        agent_id,
        BREAKER_WINDOW,
    )
    if int(n or 0) < 2:
        return
    before = await conn.fetchval(
        "UPDATE sibyl.continuity_plan p SET preemptive_mode = 'approval',"
        " row_version = row_version + 1 FROM (SELECT preemptive_mode FROM sibyl.continuity_plan"
        " WHERE tenant_id = $1 AND agent_id = $2 FOR UPDATE) old"
        " WHERE p.tenant_id = $1 AND p.agent_id = $2 AND old.preemptive_mode <> 'approval'"
        " RETURNING old.preemptive_mode",
        ctx.tenant_id,
        agent_id,
    )
    if before is None:
        return
    principal = ctx.principal
    assert principal is not None
    await env.audit.append(
        conn,
        ctx.tenant_id,
        AuditRecord(
            action="config.changed",
            **audit_actor(principal).fields(),
            resource_type="agent",
            resource_id=agent_id,
            reason="per-agent breaker: two undone automated transitions in 7 days",
            detail={
                "field": "continuity_plan.preemptive_mode",
                "before": before,
                "after": "approval",
            },
            request_id=env.request_id,
        ),
    )


async def _undo(
    conn: Any, ctx: AuthContext, env: Env, incident: dict[str, Any], reason: str
) -> int:
    tenant = ctx.tenant_id
    agent_id = incident["agent_id"]
    rs = await _routing(conn, tenant, agent_id)
    t = await conn.fetchrow(
        "SELECT t.*, EXISTS (SELECT 1 FROM sibyl.routing_transition u WHERE u.tenant_id ="
        " t.tenant_id"
        "  AND u.inverse_of = t.id) AS undone FROM sibyl.routing_transition t"
        " WHERE t.tenant_id = $1 AND t.failover_id = $2 AND t.actor_kind IN ('rule', 'policy')"
        " ORDER BY t.routing_version DESC LIMIT 1",
        tenant,
        incident["id"],
    )
    if t is None:
        raise ProblemError("nothing_to_undo", "this incident made no automated transition")
    if t["undone"]:
        raise ProblemError("already_undone")
    if rs["last_transition_id"] != t["id"]:
        raise ProblemError(
            "nothing_to_undo", "a newer transition has happened since; it is not the latest"
        )
    await _cancel_live(conn, env, tenant, agent_id)
    actor = actor_of(ctx)
    hold_until = await conn.fetchval("SELECT now() + $1::interval", OPERATOR_HOLD)
    row, _ = await entry.open_saga(
        conn,
        tenant,
        SagaOpen(
            agent_id=agent_id,
            actor=actor,
            trigger="operator",
            idempotency_key=_request_key(ctx),
            kind="undo",
            priority="immediate",
            reason=reason,
        ),
        inline=True,
        env=env,
        extra_results={"undo_of": str(incident["id"]), "inverse_of": str(t["id"])},
    )
    applied = await routing.apply(
        conn,
        tenant,
        agent_id,
        expected_from=rs["state"],
        to_state=t["from_state"],
        trigger="undo",
        actor=actor,
        idempotency_key=f"failover:{row['id']}:undo",
        audit_action="failover.undone",
        failover_id=row["id"],
        inverse_of=t["id"],
        operator_hold_until=hold_until,
        reason=reason,
        request_id=env.request_id,
    )
    await engine.save(
        conn,
        env,
        tenant,
        row,
        state="done",
        step="done",
        to_state=t["from_state"],
        routing_transition_id=applied.transition_id,
        undo_plan={"inverse_of": str(t["id"]), "operator_hold_until": hold_until.isoformat()},
        finished_at=await conn.fetchval("SELECT now()"),
        claim_lock_until=None,
    )
    for task in await conn.fetch(
        "UPDATE sibyl.handoff_task SET state = 'returned', outcome = 'returned_to_agent'"
        " WHERE tenant_id = $1 AND failover_id = $2 AND state = 'queued' RETURNING id, task_id",
        tenant,
        incident["id"],
    ):
        await env.audit.append(
            conn,
            tenant,
            AuditRecord(
                action="handoff.returned",
                **actor.audit_fields(),
                resource_type="handoff_task",
                resource_id=task["id"],
                detail={
                    "task_id": str(task["task_id"]),
                    "operator_id": str(actor.user_id),
                    "outcome": "returned_to_agent",
                },
                request_id=env.request_id,
            ),
        )
    await conn.execute(
        "INSERT INTO sibyl.label (tenant_id, agent_id, kind, label_strength, judges_kind,"
        " judges_id,"
        " judged_as_of, labeller_kind, labeller_ref, value, reason)"
        " VALUES ($1, $2, 'failover_outcome', 'verdict', 'transition', $3, now(), 'operator', $4,"
        " $5::jsonb, $6)",
        tenant,
        agent_id,
        str(t["id"]),
        str(actor.user_id),
        {"undone_by_operator": True, "incident_id": str(incident["id"])},
        reason,
    )
    await _breaker(conn, ctx, env, agent_id)
    return 200


async def _clear_hold(
    conn: Any, ctx: AuthContext, env: Env, incident: dict[str, Any], reason: str
) -> int:
    ctx.action("clear_hold")
    principal = ctx.principal
    assert principal is not None
    if not principal.roles & {"owner", "security_admin"}:
        raise ProblemError(
            "forbidden", "clear_hold is for owners and security admins", audit_denied=True
        )
    tenant = ctx.tenant_id
    rs = await _routing(conn, tenant, incident["agent_id"])
    if not await routing.hold_active(conn, tenant, incident["agent_id"]):
        raise _bad("clear_hold", rs["state"], "there is no operator hold to clear")
    if rs["state"] not in ("active", "degraded", "quarantined", "failed_over"):
        raise _bad("clear_hold", rs["state"], f"cannot clear a hold while {rs['state']}")
    await routing.apply(
        conn,
        tenant,
        incident["agent_id"],
        expected_from=rs["state"],
        to_state=rs["state"],
        trigger="operator",
        actor=actor_of(ctx),
        idempotency_key=f"clear_hold:{incident['id']}:{_request_key(ctx)}",
        audit_action="override.by_human",
        failover_id=incident["id"],
        reason=reason,
        request_id=env.request_id,
    )
    return 200


async def _release(
    conn: Any, ctx: AuthContext, env: Env, incident: dict[str, Any], reason: str
) -> int:
    tenant = ctx.tenant_id
    agent_id = incident["agent_id"]
    rs = await _routing(conn, tenant, agent_id)
    killed = rs["state"] == "killed"
    ctx.action("release", step_up_required=killed)
    if rs["state"] not in ("quarantined", "killed"):
        raise _bad("release", rs["state"], "release is for quarantined or killed agents")
    if killed:
        await require_scope(ctx, "killswitch:release")
        covering = await conn.fetch(
            "SELECT k.id, k.scope_kind FROM sibyl.kill_switch k WHERE k.tenant_id = $1"
            " AND k.state = 'pulled' AND (k.scope_kind = 'tenant'"
            "  OR (k.scope_kind = 'agent' AND k.scope_id = $2)"
            "  OR EXISTS (SELECT 1 FROM sibyl.failover f WHERE f.tenant_id = k.tenant_id"
            "             AND f.agent_id = $2 AND f.kind = 'kill'"
            "             AND f.kill_switch_id = k.id))",
            tenant,
            agent_id,
        )
        if not covering or any(k["scope_kind"] != "agent" for k in covering):
            raise _bad(
                "release",
                "killed",
                "a tenant or provider kill switch covers this agent; release it via /kill-switches",
            )
        await killswitch.release(
            conn, env, tenant, covering[0]["id"], actor=actor_of(ctx), reason=reason
        )
        return 200
    await require_scope(ctx, "quarantine:act")
    quarantined_for = int(
        await conn.fetchval(
            "SELECT extract(epoch FROM now() - $1::timestamptz)::int", rs["state_since"]
        )
    )
    await _simple(
        conn,
        ctx,
        env,
        agent_id=agent_id,
        kind="release",
        from_states=("quarantined",),
        to_state="active",
        reason=reason,
        audit_action="quarantine.released",
        audit_detail={"quarantined_for_s": quarantined_for},
    )
    return 200


async def _fail_back(
    conn: Any, ctx: AuthContext, env: Env, incident: dict[str, Any], reason: str
) -> int:
    tenant = ctx.tenant_id
    rs = await _routing(conn, tenant, incident["agent_id"])
    if rs["state"] != "failed_over":
        raise _bad("fail_back", rs["state"], "fail_back needs a failed_over agent")
    if incident["state"] != "done" or incident["kind"] not in ("failover", "preemptive"):
        raise _bad("fail_back", rs["state"], "the incident's failover has not completed")
    await _no_live_saga(conn, tenant, incident["agent_id"])
    actor = actor_of(ctx)
    row, _ = await entry.open_saga(
        conn,
        tenant,
        SagaOpen(
            agent_id=incident["agent_id"],
            actor=actor,
            trigger="operator",
            idempotency_key=_request_key(ctx),
            kind="failback",
            reason=reason,
        ),
        inline=True,
        env=env,
        extra_results={"incident_id": str(incident["id"])},
    )
    applied = await routing.apply(
        conn,
        tenant,
        incident["agent_id"],
        expected_from="failed_over",
        to_state="failing_back",
        trigger="operator",
        actor=actor,
        idempotency_key=f"failover:{row['id']}:failing_back",
        audit_action="failback.started",
        failover_id=row["id"],
        canary_pct=10,
        reason=reason,
        audit_detail={"canary_pct": 10},
        request_id=env.request_id,
    )
    await engine.save(
        conn,
        env,
        tenant,
        row,
        step="write_routing",
        routing_transition_id=applied.transition_id,
        claimed_by="failback",
        claim_lock_until=None,
        step_results=engine.with_result(row, "ramp", {"pct": 10, "operator": True}),
    )
    return 200


async def _cancel(
    conn: Any, ctx: AuthContext, env: Env, incident: dict[str, Any], reason: str
) -> int:
    tenant = ctx.tenant_id
    state, step = incident["state"], incident["step"]
    before_routing = step in ("validate", "check_viability", "write_routing")
    if incident["kind"] not in ("failover", "preemptive"):
        raise _bad("cancel", state, f"a {incident['kind']} incident cannot be cancelled")
    if state not in LIVE or (state == "running" and not before_routing):
        raise _bad(
            "cancel", state, "only a pending, waiting or not-yet-routed saga can be cancelled"
        )
    rs = await routing.state_of(conn, tenant, incident["agent_id"])
    transition_id = None
    if state == "waiting_approval" and rs is not None and rs["state"] == "awaiting_approval":
        applied = await routing.apply(
            conn,
            tenant,
            incident["agent_id"],
            expected_from="awaiting_approval",
            to_state="degraded",
            trigger="approval",
            actor=actor_of(ctx),
            idempotency_key=f"failover:{incident['id']}:cancelled",
            audit_action="failover.rolled_back",
            failover_id=incident["id"],
            approval_id=incident["approval_id"],
            reason=reason,
            audit_detail={"cause": "operator_cancel"},
            request_id=env.request_id,
        )
        transition_id = str(applied.transition_id)
    else:
        principal = ctx.principal
        assert principal is not None
        await env.audit.append(
            conn,
            tenant,
            AuditRecord(
                action="failover.rolled_back",
                **audit_actor(principal).fields(),
                resource_type="agent",
                resource_id=incident["agent_id"],
                reason=reason,
                detail={
                    "transition_id": None,
                    "cause": "operator_cancel",
                    "incident_id": str(incident["id"]),
                },
                request_id=env.request_id,
            ),
        )
    row = await engine.save(
        conn,
        env,
        tenant,
        incident,
        cancel_requested=True,
        step_results=engine.with_result(incident, "cancel", {"transition_id": transition_id}),
    )
    await engine.finish(conn, env, tenant, row, "cancelled", "operator_cancel")
    return 200


async def act(
    conn: Any,
    ctx: AuthContext,
    incident: dict[str, Any],
    agent: dict[str, Any],
    body: IncidentAction,
) -> int:
    env = api_env(ctx)
    reason = body.reason.strip()
    group = agent["agent_group_id"]
    if body.expected_routing_version is not None:
        rs = await routing.state_of(conn, ctx.tenant_id, incident["agent_id"])
        if rs is not None and int(rs["routing_version"]) != body.expected_routing_version:
            raise ProblemError(
                "stale_precondition",
                extensions={
                    "current": {"state": rs["state"], "routing_version": rs["routing_version"]}
                },
            )
    if body.action in ("approve", "deny"):
        return await _decide(conn, ctx, env, incident, body)
    if body.action == "undo":
        ctx.action("undo", resource_group_id=group)
        return await _undo(conn, ctx, env, incident, reason)
    if body.action == "clear_hold":
        return await _clear_hold(conn, ctx, env, incident, reason)
    if body.action == "release":
        return await _release(conn, ctx, env, incident, reason)
    if body.action == "fail_back":
        ctx.action("fail_back", resource_group_id=group)
        return await _fail_back(conn, ctx, env, incident, reason)
    ctx.action("cancel", resource_group_id=group)
    return await _cancel(conn, ctx, env, incident, reason)
