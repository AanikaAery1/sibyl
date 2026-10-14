"""``/incidents`` handler tests on PG17: operator actions, preconditions, 409 vocabulary, reads."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.worker.saga import runner
from sibyl_lane_s_world import SWorld

REASON = "handler test: operator decision with context"


def _agent(s: SWorld, **kw: Any) -> UUID:
    agent = s.agent(model=s.model(s.provider()), **kw)
    s.plan(agent)
    return agent


def _open(s: SWorld, agent: UUID, action: str, who: str = "owner", **extra: Any) -> Any:
    return s.post(
        who, "/incidents", {"agent_id": str(agent), "action": action, "reason": REASON, **extra}
    )


def _act(s: SWorld, incident: Any, action: str, who: str = "owner") -> Any:
    return s.post(who, f"/incidents/{incident}/actions", {"action": action, "reason": REASON})


def _type(resp: Any) -> str:
    return str(resp.json().get("type", "")).rsplit("/", 1)[-1]


def test_failover_to_a_chosen_step_is_inline_and_done(sworld: SWorld) -> None:
    s = sworld
    p2 = s.provider()
    agent = _agent(s, tier=3)
    steps = s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    resp = _open(s, agent, "failover", target={"step_id": str(steps["alt_provider"])})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["state"] == "done" and body["actor_kind"] == "human"
    assert body["routing"]["state"] == "failed_over"
    assert body["transition"]["trigger"] == "operator"
    assert "override.by_human" in s.audit_actions(s.a)
    assert _type(_open(s, agent, "failover")) == "invalid_transition"


def test_ad_hoc_model_target_and_unknown_step(sworld: SWorld) -> None:
    s = sworld
    p2 = s.provider()
    agent = _agent(s)
    resp = _open(
        s,
        agent,
        "failover",
        target={"kind": "model", "provider_id": str(p2), "model_id": str(s.model(p2))},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["routing"]["target_provider_id"] == str(p2)
    other = _agent(s)
    s.chain(other, [{"kind": "human_queue"}])
    bad = _open(s, other, "failover", target={"step_id": str(uuid4())})
    assert bad.status_code == 409 and _type(bad) == "target_not_viable"
    assert s.routing(other)["state"] == "active"  # the whole request rolled back
    assert s.sagas(other) == []


def test_degrade_recover_quarantine_release(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    assert _open(s, agent, "recover").status_code == 409
    d = _open(s, agent, "degrade")
    assert d.status_code == 201 and d.json()["routing"]["state"] == "degraded"
    assert _open(s, agent, "recover").json()["routing"]["state"] == "active"
    q = _open(s, agent, "quarantine")
    assert q.status_code == 201 and q.json()["routing"]["state"] == "quarantined"
    assert "quarantine.applied" in s.audit_actions(s.a)
    assert _open(s, agent, "degrade").status_code == 409
    r = _act(s, q.json()["id"], "release")
    assert r.status_code == 200, r.text
    assert s.routing(agent)["state"] == "active"
    assert "quarantine.released" in s.audit_actions(s.a)


def test_quarantine_needs_its_own_scope(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, group=s.a.group_id)
    resp = _open(s, agent, "quarantine", who="engineer")
    assert resp.status_code == 403 and _type(resp) == "forbidden"


def test_handoff_is_202_and_the_worker_builds_the_task(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, tier=2)
    resp = _open(s, agent, "handoff")
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["state"] == "running" and body["step"] == "create_handoff_tasks"
    assert body["routing"]["target_kind"] == "human_queue"
    s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id))
    after = s.get("owner", f"/incidents/{body['id']}").json()
    assert after["state"] == "done" and len(after["handoff_tasks"]) == 1
    assert after["handoff_tasks"][0]["fidelity"] == "request_only"


def test_saga_in_flight_and_cancel(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, tier=2)
    s.chain(agent, [{"kind": "human_queue"}])
    s.alert(agent)
    fid = s.run(runner.detect_tenant(s.worker_db, s.env(), s.a.id))[0]
    busy = _open(s, agent, "degrade")
    assert busy.status_code == 409 and _type(busy) == "saga_in_flight"
    assert busy.json()["incident_id"] == str(fid)
    cancelled = _act(s, fid, "cancel")
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["state"] == "cancelled"
    assert "failover.rolled_back" in s.audit_actions(s.a)
    assert _act(s, fid, "cancel").status_code == 409


def test_cancel_waiting_approval_returns_routing_to_degraded(sworld: SWorld) -> None:
    s = sworld
    backup = s.agent(tier=3)
    agent = _agent(s, tier=1)
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    s.alert(agent)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    assert s.routing(agent)["state"] == "awaiting_approval"
    resp = _act(s, fid, "cancel")
    assert resp.status_code == 200, resp.text
    assert resp.json()["routing"]["state"] == "degraded"
    assert resp.json()["approval"]["state"] == "cancelled"


def test_undo_requires_an_automated_latest_transition(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    d = _open(s, agent, "degrade")
    resp = _act(s, d.json()["id"], "undo")
    assert resp.status_code == 409 and _type(resp) == "nothing_to_undo"


def test_undo_of_a_superseded_transition_is_refused(sworld: SWorld) -> None:
    s = sworld
    p2 = s.provider()
    agent = _agent(s)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    q = _open(s, agent, "quarantine")
    assert q.status_code == 201
    resp = _act(s, fid, "undo")
    assert resp.status_code == 409 and _type(resp) == "nothing_to_undo"


def test_second_undo_trips_the_breaker(sworld: SWorld) -> None:
    s = sworld
    p2 = s.provider()
    agent = _agent(s, tier=3)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    for _ in range(2):
        s.alert(agent)
        fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
        assert _act(s, fid, "undo").status_code == 200
        s.admin.execute(
            "UPDATE sibyl.routing_state SET operator_hold_until = NULL WHERE agent_id = $1", agent
        )
    mode = s.val("SELECT preemptive_mode FROM sibyl.continuity_plan WHERE agent_id = $1", agent)
    assert mode == "approval"
    assert "config.changed" in s.audit_actions(s.a)
    labels = s.val(
        "SELECT count(*) FROM sibyl.label WHERE agent_id = $1 AND kind = 'failover_outcome'", agent
    )
    assert labels == 2


def test_fail_back_preconditions(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    d = _open(s, agent, "degrade")
    resp = _act(s, d.json()["id"], "fail_back")
    assert resp.status_code == 409 and _type(resp) == "invalid_transition"


def test_agent_kill_is_released_from_the_incident_unless_a_wider_switch_covers_it(
    sworld: SWorld,
) -> None:
    s = sworld
    agent = _agent(s)
    unrelated = s.provider()  # a provider switch that does not cover this agent
    resp = s.post(
        "owner",
        "/kill-switches",
        {
            "scope_kind": "provider",
            "scope_id": str(unrelated),
            "reason": "provider kill (no agents on it)",
        },
    )
    assert resp.status_code == 201
    k = _open(s, agent, "kill")
    assert k.status_code == 201, k.text
    assert k.json()["kind"] == "kill" and k.json()["routing"]["state"] == "killed"
    stale = _act(s, k.json()["id"], "release", who="owner-stale")
    assert stale.status_code == 403 and _type(stale) == "step_up_required"
    released = _act(s, k.json()["id"], "release")
    assert released.status_code == 200, released.text
    assert s.routing(agent)["state"] == "active"
    s.post("owner", f"/kill-switches/{resp.json()['id']}/release", {"reason": REASON})


def test_provider_kill_covering_an_agent_blocks_incident_release(sworld: SWorld) -> None:
    s = sworld
    p = s.provider()
    agent = s.agent(model=s.model(p))
    resp = s.post(
        "owner",
        "/kill-switches",
        {
            "scope_kind": "provider",
            "scope_id": str(p),
            "reason": "provider kill covering one agent",
        },
    )
    assert resp.status_code == 201 and resp.json()["affected_agent_ids"] == [str(agent)]
    kill_incident = s.sagas(agent)[-1]["id"]
    refused = _act(s, kill_incident, "release")
    assert refused.status_code == 409 and _type(refused) == "invalid_transition"
    assert (
        s.post(
            "owner", f"/kill-switches/{resp.json()['id']}/release", {"reason": REASON}
        ).status_code
        == 200
    )
    assert s.routing(agent)["state"] == "active"


def test_kill_release_needs_killswitch_release_scope(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    k = _open(s, agent, "kill")
    assert k.status_code == 201
    # engineer holds neither quarantine:act nor killswitch:release
    s.human("eng-all", s.a, ("engineer",))
    refused = _act(s, k.json()["id"], "release", who="eng-all")
    assert refused.status_code in (403, 404)
    assert s.routing(agent)["state"] == "killed"


def test_expected_routing_version_mismatch_is_stale(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    q = _open(s, agent, "quarantine").json()
    resp = s.post(
        "owner",
        f"/incidents/{q['id']}/actions",
        {"action": "release", "reason": REASON, "expected_routing_version": 1},
    )
    assert resp.status_code == 409 and _type(resp) == "stale_precondition"
    assert resp.json()["current"]["state"] == "quarantined"


def test_reason_is_required_and_bodies_are_strict(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    short = s.post(
        "owner", "/incidents", {"agent_id": str(agent), "action": "degrade", "reason": "short"}
    )
    assert short.status_code == 422
    extra = s.post(
        "owner",
        "/incidents",
        {"agent_id": str(agent), "action": "degrade", "reason": REASON, "x": 1},
    )
    assert extra.status_code == 422


def test_idempotent_replay_returns_the_same_incident(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    headers = s.idem("owner")
    body = {"agent_id": str(agent), "action": "degrade", "reason": REASON}
    first = s.client.post("/api/v1/incidents", json=body, headers=headers)
    second = s.client.post("/api/v1/incidents", json=body, headers=headers)
    assert first.status_code == second.status_code == 201
    assert second.headers.get("Idempotency-Replayed") == "true"
    assert first.json()["id"] == second.json()["id"]
    assert len(s.sagas(agent)) == 1


def test_list_filters_and_pagination(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s)
    _open(s, agent, "degrade")
    _open(s, agent, "recover")
    _open(s, agent, "quarantine")
    page = s.get("owner", "/incidents", agent_id=str(agent), limit=2).json()
    assert len(page["data"]) == 2 and page["has_more"] is True
    rest = s.get(
        "owner", "/incidents", agent_id=str(agent), limit=2, cursor=page["next_cursor"]
    ).json()
    assert len(rest["data"]) == 1 and rest["has_more"] is False
    kinds = [i["kind"] for i in page["data"] + rest["data"]]
    assert kinds == ["quarantine", "recover", "degrade"]
    assert (
        s.get("owner", "/incidents", agent_id=str(agent), kind="recover").json()["data"][0]["kind"]
        == "recover"
    )
    assert s.get("owner", "/incidents", agent_id=str(agent), open=True).json()["data"] == []
    mismatch = s.get(
        "owner", "/incidents", agent_id=str(agent), kind="degrade", cursor=page["next_cursor"]
    )
    assert mismatch.status_code == 400


@pytest.mark.parametrize("who", ["viewer", "auditor"])
def test_readers_can_read_but_not_act(sworld: SWorld, who: str) -> None:
    s = sworld
    agent = _agent(s)
    inc = _open(s, agent, "degrade").json()
    assert s.get(who, f"/incidents/{inc['id']}").status_code == 200
    assert _open(s, agent, "recover", who=who).status_code == 403
