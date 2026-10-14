"""Saga worker on PG17: detected triggers, viability, approvals, batching, crash resume."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.core.settings import Settings
from sibyl_control.worker.saga import runner
from sibyl_lane_s_world import SWorld


def _tick(s: SWorld, wid: str = "saga:test") -> runner.TenantRun:
    return s.run(runner.run_tenant(s.worker_db, s.env(wid), s.a.id))


def _ready_agent(s: SWorld, *, tier: int = 2, **kw: Any) -> dict[str, Any]:
    """An agent on provider P (model M) with an approved chain: alt model on P2, then humans."""
    p, p2 = s.provider(), s.provider()
    m, m2 = s.model(p), s.model(p2)
    agent = s.agent(tier=tier, model=m, **kw)
    s.plan(agent)
    steps = s.chain(
        agent,
        [
            {"kind": "alt_model_same_provider", "model_id": s.model(p), "label": "same"},
            {"kind": "alt_provider", "provider_id": p2, "model_id": m2},
            {"kind": "human_queue"},
        ],
    )
    return {"agent": agent, "p": p, "p2": p2, "m": m, "m2": m2, "steps": steps}


def test_detected_failure_fails_over_automatically_and_once(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    alert = s.alert(a["agent"])
    head = s.head(s.a)
    run = _tick(s)
    assert len(run.detected) == 1
    saga = s.saga(run.detected[0])
    assert saga["state"] == "done" and saga["step"] == "done"
    assert saga["actor_kind"] == "rule" and saga["trigger_alert_id"] == alert
    rs = s.routing(a["agent"])
    assert rs["state"] == "failed_over"
    assert rs["current_step_id"] == a["steps"]["same"]
    assert s.val("SELECT failover_id FROM sibyl.alert WHERE id = $1", alert) == saga["id"]
    actions = s.audit_actions(s.a, head)
    assert "route.changed" in actions and "failover.completed" in actions
    res = s.results(saga["id"])
    assert res["done"]["rto_met"] is True
    assert _tick(s).detected == ()  # idempotent: the actioned alert is never re-opened
    assert len(s.sagas(a["agent"])) == 1


def test_lone_agent_waits_one_extra_cycle(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    alert = s.alert(a["agent"], fired_ago_s=1)
    assert _tick(s).detected == ()
    s.admin.execute(
        "UPDATE sibyl.alert SET first_fired_at = now() - interval '30 seconds' WHERE id = $1", alert
    )
    assert len(_tick(s).detected) == 1


def test_unhealthy_provider_skips_the_wait_and_its_steps(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    s.provider_status(a["p"], "major_outage")
    s.alert(a["agent"], fired_ago_s=1)
    run = _tick(s)
    assert len(run.detected) == 1
    rs = s.routing(a["agent"])
    assert rs["target_provider_id"] == a["p2"]  # same-provider model skipped: provider_unhealthy
    candidates = s.results(run.detected[0])["check_viability"]["candidates"]
    assert candidates[0]["reason"] == "provider_unhealthy"


def test_tool_loop_hands_off_with_checkpoint_fidelity(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s, tier=1)
    task = uuid4()
    s.checkpoint(a["agent"], task)
    s.alert(a["agent"], code="tool_loop")
    run = _tick(s)
    saga = s.saga(run.detected[0])
    assert saga["state"] == "done"
    rs = s.routing(a["agent"])
    assert rs["state"] == "failed_over" and rs["target_kind"] == "human_queue"
    task_row = s.one(
        "SELECT * FROM sibyl.handoff_task WHERE tenant_id = $1 AND failover_id = $2",
        s.a.id,
        saga["id"],
    )
    assert task_row["task_id"] == task and task_row["fidelity"] == "checkpoint"
    assert task_row["failure_mode"] == "infinite_loop" and task_row["priority"] == 1
    assert task_row["next_action"] == "Post the batch to the ledger"
    assert "handoff.created" in s.audit_actions(s.a)


def test_tier1_backup_agent_waits_for_approval(sworld: SWorld) -> None:
    s = sworld
    p = s.provider()
    backup = s.agent(tier=2)
    agent = s.agent(tier=1, model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup, "risk": "high"}])
    alert = s.alert(agent)
    run = _tick(s)
    saga = s.saga(run.detected[0])
    assert saga["state"] == "waiting_approval" and saga["step"] == "write_routing"
    approval = s.one("SELECT * FROM sibyl.approval WHERE id = $1", saga["approval_id"])
    assert approval["requested_by_kind"] == "rule" and approval["tier"] == 1
    assert approval["requested_action"] == "backup_agent_failover" and approval["alert_id"] == alert
    rs = s.routing(agent)
    assert rs["state"] == "awaiting_approval" and rs["approval_id"] == approval["id"]
    assert {"failover.proposed", "approval.requested"} <= set(s.audit_actions(s.a))


def test_operator_hold_blocks_the_rule_actor_and_counts(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    s.in_tenant(
        s.a,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'active', NULL, 'operator',"
        " 'human', $3, NULL, NULL, NULL, NULL, NULL, NULL, now() + interval '30 minutes', NULL,"
        " 'hold for test', $4, 'override.by_human', NULL, NULL, NULL, NULL)",
        s.a.id,
        a["agent"],
        s.a.users["owner"],
        f"hold:{a['agent']}",
    )
    alert = s.alert(a["agent"])
    assert _tick(s).detected == ()
    _tick(s)
    held = s.one("SELECT * FROM sibyl.alert WHERE id = $1", alert)
    assert held["hold_suppressed_count"] == 1
    assert held["hold_suppressed_at"] is not None
    assert held["hold_suppressed_at"] >= held["last_evaluated_at"]
    evidence = held["evidence"]
    assert "hold_suppressed_at" not in (
        json.loads(evidence) if isinstance(evidence, str) else evidence
    )
    assert s.routing(a["agent"])["state"] == "active"
    # A fresh evaluation of the alert is suppressed (and counted) once more.
    s.admin.execute("UPDATE sibyl.alert SET last_evaluated_at = now() WHERE id = $1", alert)
    _tick(s)
    _tick(s)
    again = s.one("SELECT * FROM sibyl.alert WHERE id = $1", alert)
    assert again["hold_suppressed_count"] == 2
    assert again["hold_suppressed_at"] > held["hold_suppressed_at"]


def test_provider_collapse_is_batched_tier1_first(sworld: SWorld) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    m2 = s.model(p2)
    agents = {}
    for tier in (3, 1, 2):
        agent = s.agent(tier=tier, model=s.model(p))
        s.plan(agent)
        s.chain(
            agent,
            [
                {"kind": "alt_model_same_provider", "model_id": s.model(p)},
                {"kind": "alt_provider", "provider_id": p2, "model_id": m2},
            ],
        )
        agents[tier] = agent
    incident = s.provider_incident(p, list(agents.values()))
    for agent in agents.values():
        s.alert(agent, band="degraded", fired_ago_s=1, incident=incident)
    run = _tick(s)
    assert len(run.detected) == 3
    sagas = [s.saga(f) for f in run.detected]
    batch = {s.results(x["id"])["open"]["batch"]["position"]: x["agent_id"] for x in sagas}
    assert batch[0] == agents[1]  # tier 1 first
    for agent in agents.values():
        rs = s.routing(agent)
        assert rs["state"] == "failed_over" and rs["target_provider_id"] == p2


def test_saga_resumes_after_a_worker_crash_without_double_routing(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    s.alert(a["agent"])
    opened = s.run(runner.detect_tenant(s.worker_db, s.env("w1"), s.a.id))
    fid = opened[0]
    progress = s.run(runner.run_saga(s.worker_db, s.env("w1"), s.a.id, fid, max_steps=3))
    assert [p.status for p in progress] == ["continue", "continue", "continue"]
    saga = s.saga(fid)
    assert saga["state"] == "running" and saga["step"] == "create_handoff_tasks"
    # w1 dies holding the claim; another worker cannot take it until the lock lapses.
    assert s.run(runner.run_saga(s.worker_db, s.env("w2"), s.a.id, fid)) == []
    s.admin.execute(
        "UPDATE sibyl.failover SET claim_lock_until = now() - interval '1 s' WHERE id = $1", fid
    )
    progress = s.run(runner.run_saga(s.worker_db, s.env("w2"), s.a.id, fid))
    assert progress[-1].status == "done"
    assert s.saga(fid)["claimed_by"] == "w2"
    n = s.val(
        "SELECT count(*) FROM sibyl.routing_transition WHERE tenant_id = $1 AND failover_id = $2",
        s.a.id,
        fid,
    )
    assert n == 1


def test_no_viable_step_fails_with_reasons(sworld: SWorld) -> None:
    s = sworld
    p = s.provider()
    agent = s.agent(model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_model_same_provider", "model_id": s.model(p, allowed=False)}])
    s.alert(agent)
    run = _tick(s)
    saga = s.saga(run.detected[0])
    assert saga["state"] == "failed" and saga["error"] == "target_not_viable"
    err = s.results(saga["id"])["error"]
    assert err["candidates"][0]["reason"] == "model_not_allowed"
    assert s.routing(agent)["state"] == "active"
    assert _tick(s).detected == ()  # a failed saga still owns its alert


def test_killed_agent_saga_is_cancelled(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    s.alert(a["agent"])
    fid = s.run(runner.detect_tenant(s.worker_db, s.env(), s.a.id))[0]
    s.in_tenant(
        s.a,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'killed', NULL, 'operator',"
        " 'human', $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'kill for test', $4,"
        " 'override.by_human', NULL, NULL, NULL, NULL)",
        s.a.id,
        a["agent"],
        s.a.users["owner"],
        f"kill:{a['agent']}",
    )
    progress = s.run(runner.run_saga(s.worker_db, s.env(), s.a.id, fid))
    assert progress[-1].status == "cancelled"
    assert s.saga(fid)["error"] == "agent_killed"


def test_vaulted_credential_needed_for_alt_provider(sworld: SWorld) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2}, {"kind": "human_queue"}])
    s.in_tenant(
        s.a,
        "UPDATE sibyl.continuity_plan SET credential_mode = 'vaulted_fallback'"
        " WHERE tenant_id = $1 AND agent_id = $2",
        s.a.id,
        agent,
    )
    s.alert(agent)
    run = _tick(s)
    candidates = s.results(run.detected[0])["check_viability"]["candidates"]
    assert candidates[0]["reason"] == "credential_missing"
    assert s.routing(agent)["target_kind"] == "human_queue"


def test_automated_failover_audits_started_then_completed(sworld: SWorld) -> None:
    """S-15: the audit log shows the saga start (``failover.started``, rule actor, with the
    transition and target) before ``failover.completed``."""
    s = sworld
    a = _ready_agent(s)
    s.alert(a["agent"])
    head = s.head(s.a)
    saga = s.saga(_tick(s).detected[0])
    actions = s.audit_actions(s.a, head)
    assert actions.index("failover.started") < actions.index("failover.completed")
    row = s.one(
        "SELECT actor_type, detail FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'failover.started' AND seq > $2",
        s.a.id,
        head,
    )
    detail = row["detail"] if isinstance(row["detail"], dict) else json.loads(row["detail"])
    assert row["actor_type"] == "rule"
    assert detail["transition_id"] == str(saga["routing_transition_id"])
    assert detail["to_target"]["step_id"] == str(a["steps"]["same"])
    assert detail["steps_ok"] == ["validate", "check_viability"]


def test_human_queue_with_nothing_in_flight_queues_one_request_only_task(sworld: SWorld) -> None:
    """S-15: no viable fallback (revoked credential), so work goes to people; a gateway-only
    agent has no tracked in-flight task, and the handoff is still the terminal step."""
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2}, {"kind": "human_queue"}])
    s.in_tenant(
        s.a,
        "UPDATE sibyl.continuity_plan SET credential_mode = 'vaulted_fallback'"
        " WHERE tenant_id = $1 AND agent_id = $2",
        s.a.id,
        agent,
    )
    s.alert(agent)
    head = s.head(s.a)
    saga = s.saga(_tick(s).detected[0])
    assert saga["state"] == "done"
    assert s.routing(agent)["target_kind"] == "human_queue"
    tasks = s.rows(
        "SELECT * FROM sibyl.handoff_task WHERE tenant_id = $1 AND failover_id = $2",
        s.a.id,
        saga["id"],
    )
    assert len(tasks) == 1
    assert tasks[0]["fidelity"] == "request_only" and tasks[0]["trigger_kind"] == "rule"
    assert tasks[0]["agent_id"] == agent and tasks[0]["state"] == "queued"
    assert s.results(saga["id"])["create_handoff_tasks"]["created"] == [str(tasks[0]["id"])]
    actions = s.audit_actions(s.a, head)
    assert "failover.started" in actions and "handoff.created" in actions
    assert _tick(s).detected == ()  # idempotent: no second task on the next tick
    assert s.val("SELECT count(*) FROM sibyl.handoff_task WHERE agent_id = $1", agent) == 1


def test_failover_to_a_model_with_nothing_in_flight_creates_no_task(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    s.alert(a["agent"])
    saga = s.saga(_tick(s).detected[0])
    assert s.routing(a["agent"])["target_kind"] != "human_queue"
    n = s.val("SELECT count(*) FROM sibyl.handoff_task WHERE failover_id = $1", saga["id"])
    assert n == 0


def test_tick_entrypoint_runs(sworld: SWorld) -> None:
    import logging

    from sibyl_control.worker.loops import LOOPS, LoopContext, resolve_tick

    spec = next(x for x in LOOPS if x.name == "saga")
    tick = resolve_tick(spec)
    assert tick is not None
    s = sworld
    a = _ready_agent(s)
    s.alert(a["agent"])
    s.run(tick(LoopContext("saga", s.worker_db, Settings(), logging.getLogger("t"))))
    assert s.routing(a["agent"])["state"] == "failed_over"
    assert UUID(str(s.sagas(a["agent"])[0]["id"]))
