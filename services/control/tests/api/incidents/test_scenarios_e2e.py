"""End-to-end PG17 scenarios across the api and the lane S workers (ROADMAP M2/M3 acceptance).

1. tier-1 hard outage → automatic alt-provider failover (vaulted credential) and, for an agent
   whose only same-provider model is down, a checkpoint-fidelity handoff an operator completes;
2. tier-1 backup-agent failover needs four-eyes (self-approval 409, a second human approves);
3. undo → 30-minute hold blocks rule actors but not humans or kill; clear_hold resumes;
4. tenant-wide kill; a second tenant kill within 10 min by the same owner is refused, by a
   different owner allowed;
5. approval timeout forces hold for a tier-1 PII agent (D22);
6. failback probe returns the agent to its primary.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.core.settings import Settings
from sibyl_control.worker.approvals import timeouts
from sibyl_control.worker.failback import probe
from sibyl_control.worker.loops import LOOPS, LoopContext, resolve_tick
from sibyl_control.worker.saga import PredictedTrigger, open_predicted, runner
from sibyl_lane_s_world import SWorld

REASON = "e2e scenario: operator decision with context"


def _saga_tick(s: SWorld) -> runner.TenantRun:
    return s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id))


def _credential(s: SWorld, provider: UUID) -> str:
    resp = s.post(
        "owner",
        "/provider-credentials",
        {
            "provider_id": str(provider),
            "name": f"fallback-{uuid4().hex[:6]}",
            "base_url": "http://sibyl-sim:8300/v1",
            "auth_scheme": "bearer",
            "secret": "sk-test-" + uuid4().hex,
        },
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


def _incident(s: SWorld, fid: Any, who: str = "owner") -> dict[str, Any]:
    resp = s.get(who, f"/incidents/{fid}")
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


def test_1_tier1_hard_outage_fails_over_and_hands_off(sworld: SWorld) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    cred = _credential(s, p2)
    billing = s.agent(tier=1, model=s.model(p))
    s.plan(billing)
    s.in_tenant(
        s.a,
        "UPDATE sibyl.continuity_plan SET credential_mode = 'vaulted_fallback'"
        " WHERE tenant_id = $1 AND agent_id = $2",
        s.a.id,
        billing,
    )
    s.chain(
        billing,
        [
            {"kind": "alt_model_same_provider", "model_id": s.model(p)},
            {
                "kind": "alt_provider",
                "provider_id": p2,
                "model_id": s.model(p2),
                "credential_id": UUID(cred),
                "risk": "medium",
            },
            {"kind": "human_queue"},
        ],
    )
    quotes = s.agent(tier=1, model=s.model(p))
    s.plan(quotes)
    s.chain(
        quotes,
        [{"kind": "alt_model_same_provider", "model_id": s.model(p)}, {"kind": "human_queue"}],
    )
    task = uuid4()
    s.checkpoint(quotes, task)
    s.provider_status(p, "major_outage")
    incident = s.provider_incident(p, [billing, quotes])
    for agent in (billing, quotes):
        s.alert(agent, incident=incident, fired_ago_s=5)

    run = _saga_tick(s)
    assert len(run.detected) == 2
    rs = s.routing(billing)
    assert rs["state"] == "failed_over" and rs["target_provider_id"] == p2
    rq = s.routing(quotes)
    assert rq["state"] == "failed_over" and rq["target_kind"] == "human_queue"

    by_agent = {s.saga(f)["agent_id"]: f for f in run.detected}
    inc = _incident(s, by_agent[billing])
    assert inc["state"] == "done" and inc["routing"]["state"] == "failed_over"
    assert inc["step_results"]["done"]["rto_met"] is True
    assert "fail_back" in inc["available_actions"] and "undo" in inc["available_actions"]
    assert inc["chosen_step"]["kind"] == "alt_provider"
    candidates = inc["step_results"]["check_viability"]["candidates"]
    assert candidates[0]["reason"] in ("provider_unhealthy", "provider_incident_batch")

    handoff = _incident(s, by_agent[quotes])
    assert len(handoff["handoff_tasks"]) == 1
    task_id = handoff["handoff_tasks"][0]["id"]
    queue = s.get("operator", "/queue").json()
    assert task_id in {t["id"] for t in queue["data"]}
    packet = s.get("operator", f"/handoff-tasks/{task_id}/packet")
    assert packet.status_code == 200 and packet.json()["fidelity"] == "checkpoint"
    claim = s.post("operator", f"/handoff-tasks/{task_id}/actions", {"action": "claim"})
    assert claim.status_code == 200, claim.text
    done = s.post(
        "operator",
        f"/handoff-tasks/{task_id}/actions",
        {
            "action": "complete",
            "outcome": "resolved",
            "outcome_note": "posted by hand",
            "rating": 5,
        },
    )
    assert done.status_code == 200 and done.json()["state"] == "completed"
    summary = s.get("operator", "/queue").json()["summary"]
    assert summary["completed_despite_failure"] >= 1


def test_2_tier1_backup_agent_needs_four_eyes(sworld: SWorld) -> None:
    s = sworld
    backup = s.agent(tier=2)
    agent = s.agent(tier=1, model=s.model(s.provider()))
    s.plan(agent)
    steps = s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup, "risk": "high"}])
    opened = s.post(
        "owner",
        "/incidents",
        {
            "agent_id": str(agent),
            "action": "failover",
            "target": {"step_id": str(steps["backup_agent"])},
            "reason": REASON,
        },
    )
    assert opened.status_code == 202, opened.text
    inc = opened.json()
    assert inc["state"] == "waiting_approval"
    assert inc["approval"]["requested_by_kind"] == "human"
    assert inc["routing"]["state"] == "active"  # nothing moves before the second human
    self_approve = s.post(
        "owner", f"/incidents/{inc['id']}/actions", {"action": "approve", "reason": REASON}
    )
    assert self_approve.status_code == 409
    assert self_approve.json()["type"].endswith("/self_approval")
    operator = s.post(
        "operator", f"/incidents/{inc['id']}/actions", {"action": "approve", "reason": REASON}
    )
    assert operator.status_code == 403  # approvals:decide is owner / security_admin only
    approved = s.post(
        "approver", f"/incidents/{inc['id']}/actions", {"action": "approve", "reason": REASON}
    )
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["state"] == "done" and body["routing"]["target_agent_id"] == str(backup)
    assert body["approval"]["state"] == "approved"
    assert body["transition"]["actor_user_id"] == str(s.users["approver"])
    assert body["transition"]["approval_id"] == body["approval"]["id"]
    again = s.post(
        "approver", f"/incidents/{inc['id']}/actions", {"action": "approve", "reason": REASON}
    )
    assert again.status_code == 409 and again.json()["type"].endswith("/approval_not_pending")


def test_2b_rule_requested_backup_approval_and_deny(sworld: SWorld) -> None:
    s = sworld
    backup = s.agent(tier=3)
    agent = s.agent(tier=1, model=s.model(s.provider()))
    s.plan(agent)
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    s.alert(agent)
    fid = _saga_tick(s).detected[0]
    inc = _incident(s, fid)
    assert inc["routing"]["state"] == "awaiting_approval"
    assert inc["approval"]["requested_by_kind"] == "rule"
    denied = s.post("owner", f"/incidents/{fid}/actions", {"action": "deny", "reason": REASON})
    assert denied.status_code == 200, denied.text
    assert denied.json()["state"] == "cancelled"
    assert denied.json()["routing"]["state"] == "degraded"


def test_2c_a_human_deny_holds_for_the_failure_it_was_made_in(sworld: SWorld) -> None:
    """S-26: after a person denies the failover, another detected alert that was already open
    (R1 beside R3) must not open a new saga a second later: the agent stays degraded, which is
    what the deny means. A failure that starts after the deny is a new episode."""
    s = sworld
    backup = s.agent(tier=3)
    agent = s.agent(tier=1, model=s.model(s.provider()))
    s.plan(agent)
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    s.alert(agent, code="consecutive_failures", fired_ago_s=120)
    s.alert(agent, code="error_rate", fired_ago_s=100)  # open throughout, not yet actioned
    fid = _saga_tick(s).detected[0]
    denied = s.post("owner", f"/incidents/{fid}/actions", {"action": "deny", "reason": REASON})
    assert denied.status_code == 200, denied.text
    assert _saga_tick(s).detected == (), "the deny is not re-asked by the next open alert"
    assert s.routing(agent)["state"] == "degraded"
    # a failure that starts after the deny is a new episode: move the deny 60 s into the past and
    # fire an alert 30 s ago (after it, and past the lone-agent corroboration age)
    s.admin.execute(
        "UPDATE sibyl.approval SET decided_at = now() - interval '60 seconds'"
        " WHERE agent_id = $1 AND state = 'denied'",
        agent,
    )
    s.alert(agent, code="p95_latency", fired_ago_s=30)
    assert len(_saga_tick(s).detected) == 1


def test_3_undo_hold_blocks_rules_not_humans_or_kill(sworld: SWorld) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(tier=2, model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent)
    fid = _saga_tick(s).detected[0]
    assert s.routing(agent)["state"] == "failed_over"

    undone = s.post("owner", f"/incidents/{fid}/actions", {"action": "undo", "reason": REASON})
    assert undone.status_code == 200, undone.text
    body = undone.json()
    assert body["routing"]["state"] == "active"
    assert body["operator_hold_until"] is not None
    assert body["transition"]["undone_by"] is not None
    assert (
        s.post("owner", f"/incidents/{fid}/actions", {"action": "undo", "reason": REASON})
        .json()["type"]
        .endswith("/already_undone")
    )

    # Rule actors are blocked: a new detected alert opens nothing and counts as suppressed.
    alert = s.alert(agent)
    assert _saga_tick(s).detected == ()
    assert s.val("SELECT hold_suppressed_count FROM sibyl.alert WHERE id = $1", alert) == 1

    async def predicted() -> Any:
        async with s.worker_db.tenant_tx(s.a.id) as conn:
            return await open_predicted(
                conn,
                s.a.id,
                PredictedTrigger(
                    agent_id=agent,
                    band="0.90",
                    confidence="high",
                    contributing_rules=("error_trend", "latency_trend"),
                ),
                env=s.env(),
            )

    assert s.run(predicted()).action == "suppressed"

    # Humans are not blocked.
    degraded = s.post(
        "owner", "/incidents", {"agent_id": str(agent), "action": "degrade", "reason": REASON}
    )
    assert degraded.status_code == 201, degraded.text
    recovered = s.post(
        "owner", "/incidents", {"agent_id": str(agent), "action": "recover", "reason": REASON}
    )
    assert recovered.status_code == 201

    # clear_hold is for owners / security admins only.
    undo_incident = s.sagas(agent)[1]["id"]
    refused = s.post(
        "operator",
        f"/incidents/{undo_incident}/actions",
        {"action": "clear_hold", "reason": REASON},
    )
    assert refused.status_code == 403
    cleared = s.post(
        "owner", f"/incidents/{undo_incident}/actions", {"action": "clear_hold", "reason": REASON}
    )
    assert cleared.status_code == 200, cleared.text
    assert s.routing(agent)["operator_hold_until"] is None

    # Kill bypasses a hold too (new hold via a second undo cycle is not needed: kill works now).
    killed = s.post(
        "owner",
        "/incidents",
        {"agent_id": str(agent), "action": "kill", "reason": "kill during the hold test"},
    )
    assert killed.status_code == 201, killed.text
    assert s.routing(agent)["state"] == "killed"
    release = s.post(
        "owner",
        f"/incidents/{killed.json()['id']}/actions",
        {"action": "release", "reason": REASON},
    )
    assert release.status_code == 200, release.text
    assert s.routing(agent)["state"] == "active"
    # With the hold cleared, the rule actor works again.
    assert len(_saga_tick(s).detected) == 1


def test_3b_kill_beats_a_live_hold(sworld: SWorld) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(tier=3, model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent)
    fid = _saga_tick(s).detected[0]
    assert (
        s.post(
            "owner", f"/incidents/{fid}/actions", {"action": "undo", "reason": REASON}
        ).status_code
        == 200
    )
    assert s.routing(agent)["operator_hold_until"] is not None
    resp = s.post(
        "owner",
        "/kill-switches",
        {
            "scope_kind": "agent",
            "scope_id": str(agent),
            "reason": "kill while automation is paused",
        },
    )
    assert resp.status_code == 201, resp.text
    assert s.routing(agent)["state"] == "killed"


def test_4_tenant_kill_second_owner_rule(sworld: SWorld) -> None:
    s = sworld
    agents = [s.agent(tier=t, model=s.model(s.provider())) for t in (1, 2)]
    s.plan(agents[0])
    s.chain(agents[0], [{"kind": "human_queue"}])
    s.alert(agents[0])
    pending = s.run(runner.detect_tenant(s.worker_db, s.env(), s.a.id))
    body = {"scope_kind": "tenant", "reason": "tenant-wide incident: stop every agent now"}
    first = s.post("owner", "/kill-switches", body)
    assert first.status_code == 201, first.text
    ks = first.json()
    assert set(map(str, agents)) <= set(ks["affected_agent_ids"])
    for agent in agents:
        assert s.routing(agent)["state"] == "killed"
    for fid in pending:  # kill beats everything: the live saga is cancelled, nothing progresses
        assert s.saga(fid)["state"] == "cancelled"
    assert s.post("owner", "/kill-switches", body).json()["type"].endswith("/already_pulled")
    released = s.post("owner", f"/kill-switches/{ks['id']}/release", {"reason": REASON})
    assert released.status_code == 200, released.text
    assert s.routing(agents[1])["state"] == "active"
    again = s.post("owner", "/kill-switches", body)
    assert again.status_code == 409 and again.json()["type"].endswith("/second_owner_required")
    other = s.post("owner2", "/kill-switches", body)
    assert other.status_code == 201, other.text
    released = s.post("owner2", f"/kill-switches/{other.json()['id']}/release", {"reason": REASON})
    assert released.status_code == 200


def test_5_approval_timeout_forces_hold_for_pii(sworld: SWorld) -> None:
    s = sworld
    backup = s.agent(tier=2)
    agent = s.agent(tier=1, model=s.model(s.provider()), tags=("pii",))
    s.plan(agent)
    s.in_tenant(
        s.a,
        "UPDATE sibyl.continuity_plan SET approval_timeout_policy = 'fail_safe'"
        " WHERE tenant_id = $1 AND agent_id = $2",
        s.a.id,
        agent,
    )
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    s.alert(agent)
    fid = _saga_tick(s).detected[0]
    inc = _incident(s, fid)
    assert inc["approval"]["timeout_policy"] == "hold"  # D22 layer (b) at insert
    assert inc["approval"]["evidence"]["timeout_policy_applied"] == "hold_forced_d22"
    s.admin.execute(
        "UPDATE sibyl.approval SET expires_at = now() - interval '1 s' WHERE id = $1",
        UUID(inc["approval"]["id"]),
    )
    tick = resolve_tick(next(x for x in LOOPS if x.name == "approvals"))
    assert tick is not None
    s.run(tick(LoopContext("approvals", s.worker_db, Settings(), logging.getLogger("t"))))
    after = _incident(s, fid)
    assert after["state"] == "cancelled" and after["approval"]["state"] == "expired"
    assert after["routing"]["state"] == "degraded"
    applied = s.val(
        "SELECT detail->>'timeout_policy_applied' FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'approval.expired' AND resource_id = $2",
        s.a.id,
        UUID(inc["approval"]["id"]),
    )
    assert applied == "hold_forced_d22"
    assert (
        timeouts.applied_policy(
            {"evidence": {}, "timeout_policy": "fail_safe", "tier": 1, "pii": True}
        )
        == "hold_forced_d22"
    )


def test_6_failback_probe_returns_to_primary(sworld: SWorld) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(tier=2, model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent, snapshot_ago_s=600)
    fid = _saga_tick(s).detected[0]
    s.admin.execute(
        "UPDATE sibyl.routing_state SET state_since = now() - interval '6 minutes' WHERE"
        " agent_id = $1",
        agent,
    )
    run = s.run(probe.run_tenant(s.worker_db, s.env("failback:e2e"), s.a.id))
    assert len(run.probed) == 1
    listed = s.get("owner", "/incidents", agent_id=str(agent)).json()["data"]
    kinds = {i["kind"]: i for i in listed}
    assert kinds["failback"]["state"] == "done"
    assert kinds["failover"]["routing"]["state"] == "active"
    assert _incident(s, fid)["routing"]["target_kind"] == "primary"
