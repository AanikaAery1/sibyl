"""``/kill-switches`` on PG17: scopes, break-glass (anchor, caps, never releases), D34, acks."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sibyl_control.core.ratelimit import RateDecision, RatePolicy
from sibyl_lane_s_world import SWorld

REASON = "kill switch test: stop the agent now"


def _type(resp: Any) -> str:
    return str(resp.json().get("type", "")).rsplit("/", 1)[-1]


def _pull(s: SWorld, who: str, scope_kind: str, scope_id: Any = None) -> Any:
    body: dict[str, Any] = {"scope_kind": scope_kind, "reason": REASON}
    if scope_id is not None:
        body["scope_id"] = str(scope_id)
    return s.post(who, "/kill-switches", body)


def _doc(raw: Any) -> dict[str, Any]:
    return dict(json.loads(raw) if isinstance(raw, str) else raw)


def _switch_rows(s: SWorld, agent: UUID, kind: str) -> list[Any]:
    return s.rows(
        "SELECT kill_switch_id, step_results FROM sibyl.failover WHERE tenant_id = $1"
        " AND agent_id = $2 AND kind = $3 ORDER BY created_at",
        s.a.id,
        agent,
        kind,
    )


def test_agent_kill_cancels_a_waiting_saga_and_releases(sworld: SWorld) -> None:
    s = sworld
    backup = s.agent(tier=2)
    agent = s.agent(tier=1, model=s.model(s.provider()))
    s.plan(agent)
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    from sibyl_control.worker.saga import runner

    s.alert(agent)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    assert s.routing(agent)["state"] == "awaiting_approval"
    head = s.head(s.a)
    resp = _pull(s, "owner", "agent", agent)
    assert resp.status_code == 201, resp.text
    ks = resp.json()
    assert ks["state"] == "pulled" and ks["affected_agent_ids"] == [str(agent)]
    assert ks["pulled_via_break_glass"] is False
    assert s.routing(agent)["state"] == "killed"
    saga = s.saga(fid)
    assert saga["state"] == "cancelled" and saga["error"] == "killed"
    assert (
        s.val("SELECT state FROM sibyl.approval WHERE id = $1", saga["approval_id"]) == "cancelled"
    )
    assert set(s.audit_actions(s.a, head)) == {"killswitch.pulled"}
    kill = _switch_rows(s, agent, "kill")
    assert [r["kill_switch_id"] for r in kill] == [UUID(ks["id"])]
    assert "kill_switch_id" not in _doc(kill[0]["step_results"])
    outbox = s.val(
        "SELECT count(*) FROM sibyl.outbox WHERE tenant_id = $1 AND event_type ="
        " 'killswitch.pulled'"
        " AND aggregate_id = $2",
        s.a.id,
        UUID(ks["id"]),
    )
    assert outbox == 1
    assert _type(_pull(s, "owner", "agent", agent)) == "already_pulled"
    rel = s.post("owner", f"/kill-switches/{ks['id']}/release", {"reason": "incident over, resume"})
    assert rel.status_code == 200, rel.text
    assert rel.json()["state"] == "released"
    assert s.routing(agent)["state"] == "active"
    release = _switch_rows(s, agent, "release")
    assert [r["kill_switch_id"] for r in release] == [UUID(ks["id"])]
    assert "kill_switch_id" not in _doc(release[0]["step_results"])
    assert (
        _type(s.post("owner", f"/kill-switches/{ks['id']}/release", {"reason": "again please"}))
        == "not_pulled"
    )


def test_provider_scope_kills_the_providers_agents(sworld: SWorld) -> None:
    s = sworld
    p, other = s.provider(), s.provider()
    on_p = [s.agent(model=s.model(p)) for _ in range(2)]
    off_p = s.agent(model=s.model(other))
    resp = _pull(s, "security_admin", "provider", p)
    assert resp.status_code == 201, resp.text
    assert sorted(resp.json()["affected_agent_ids"]) == sorted(map(str, on_p))
    assert s.routing(off_p)["state"] == "active"
    assert (
        s.post(
            "security_admin",
            f"/kill-switches/{resp.json()['id']}/release",
            {"reason": "provider back"},
        ).status_code
        == 200
    )


def test_overlapping_switches_keep_the_agent_killed_until_both_release(sworld: SWorld) -> None:
    s = sworld
    p = s.provider()
    agent = s.agent(model=s.model(p))
    by_agent = _pull(s, "owner", "agent", agent).json()
    by_provider = _pull(s, "owner", "provider", p).json()
    # already killed by the agent switch: coverage is recorded, no second transition
    assert by_provider["affected_agent_ids"] == [str(agent)]
    assert {r["kill_switch_id"] for r in _switch_rows(s, agent, "kill")} == {
        UUID(by_agent["id"]),
        UUID(by_provider["id"]),
    }
    transitions = s.val(
        "SELECT count(*) FROM sibyl.routing_transition WHERE agent_id = $1 AND to_state = 'killed'",
        agent,
    )
    assert transitions == 1
    s.post("owner", f"/kill-switches/{by_provider['id']}/release", {"reason": "provider fine now"})
    assert s.routing(agent)["state"] == "killed"
    s.post("owner", f"/kill-switches/{by_agent['id']}/release", {"reason": "agent fine now"})
    assert s.routing(agent)["state"] == "active"


def test_scope_validation(sworld: SWorld) -> None:
    s = sworld
    assert _pull(s, "owner", "agent").status_code == 422
    assert _pull(s, "owner", "tenant", s.a.group_id).status_code == 422
    assert _pull(s, "owner", "agent", s.a.group_id).status_code == 404
    short = s.post("owner", "/kill-switches", {"scope_kind": "tenant", "reason": "too short"})
    assert short.status_code == 422


def test_human_pull_needs_step_up_and_scope(sworld: SWorld) -> None:
    s = sworld
    agent = s.agent()
    stale = _pull(s, "owner-stale", "agent", agent)
    assert stale.status_code == 403 and _type(stale) == "step_up_required"
    assert _pull(s, "operator", "agent", agent).status_code == 403
    assert s.routing(agent)["state"] == "active"


def test_break_glass_pull_anchors_and_never_releases(sworld: SWorld) -> None:
    s = sworld
    key = s.key("breakglass", s.a, ["killswitch:pull"])
    agent = s.agent()
    head = s.head(s.a)
    resp = _pull(s, "breakglass", "agent", agent)
    assert resp.status_code == 201, resp.text
    ks = resp.json()
    assert ks["pulled_via_break_glass"] is True
    actions = s.audit_actions(s.a, head)
    assert "access.break_glass" in actions and "killswitch.pulled" in actions
    row = s.one(
        "SELECT actor_type, actor_key_id FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'killswitch.pulled' AND resource_type = 'kill_switch' AND resource_id = $2",
        s.a.id,
        UUID(ks["id"]),
    )
    assert row["actor_type"] == "api_key" and row["actor_key_id"] == key
    glass = s.one(
        "SELECT actor_type, actor_key_id, detail FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'access.break_glass' AND resource_id = $2",
        s.a.id,
        UUID(ks["id"]),
    )
    # B21: key-initiated break-glass records the key as the actor (core.audit.audit_actor).
    assert (glass["actor_type"], glass["actor_key_id"]) == ("api_key", key)
    anchors = s.val(
        "SELECT count(*) FROM sibyl.outbox WHERE tenant_id = $1 AND event_type = 'audit.anchor_now'"
        " AND aggregate_id = $2",
        s.a.id,
        UUID(ks["id"]),
    )
    assert anchors == 1
    transition = s.one(
        "SELECT actor_kind, actor_key_id FROM sibyl.routing_transition WHERE id = $1",
        s.routing(agent)["last_transition_id"],
    )
    assert transition["actor_kind"] == "api_key" and transition["actor_key_id"] == key
    release = s.post(
        "breakglass", f"/kill-switches/{ks['id']}/release", {"reason": "key tries to release"}
    )
    assert release.status_code == 403 and _type(release) == "break_glass_key_misuse"
    assert s.get("breakglass", "/kill-switches").status_code == 403
    s.post("owner", f"/kill-switches/{ks['id']}/release", {"reason": "human releases it"})


class _Capped:
    """Allows ``n`` hits per key, then refuses (break-glass caps)."""

    def __init__(self, n: int) -> None:
        self.n = n
        self.seen: dict[str, int] = {}

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        self.seen[key] = self.seen.get(key, 0) + 1
        ok = not key.startswith("breakglass:key:") or self.seen[key] <= self.n
        return RateDecision(ok, policy, 0, 60, 0 if ok else 60)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        return RateDecision(True, policy, 1, 0, 0)


def test_break_glass_caps_answer_429_and_are_audited(sworld: SWorld) -> None:
    s = sworld
    s.key("breakglass2", s.a, ["killswitch:pull"])
    services = s.client.app.state.services
    original = services.rate_limiter
    services.rate_limiter = _Capped(1)
    try:
        first = _pull(s, "breakglass2", "agent", s.agent())
        assert first.status_code == 201
        target = s.agent()
        head = s.head(s.a)
        second = _pull(s, "breakglass2", "agent", target)
        assert second.status_code == 429 and _type(second) == "break_glass_rate_limited"
        assert second.headers.get("Retry-After") == "60"
        assert s.audit_actions(s.a, head) == ["access.denied"]
    finally:
        services.rate_limiter = original
    s.post(
        "owner", f"/kill-switches/{first.json()['id']}/release", {"reason": "cleanup after caps"}
    )


def test_d34_applies_to_tenant_scope_only(sworld: SWorld) -> None:
    s = sworld
    s.agent()
    first = _pull(s, "owner", "tenant")
    assert first.status_code == 201
    s.post(
        "owner", f"/kill-switches/{first.json()['id']}/release", {"reason": "false alarm, resume"}
    )
    # A security_admin is not an owner: refused as the second tenant kill too.
    assert _type(_pull(s, "security_admin", "tenant")) == "second_owner_required"
    agent_kill = _pull(s, "owner", "agent", s.agent())  # agent scope: no D34
    assert agent_kill.status_code == 201
    s.post(
        "owner",
        f"/kill-switches/{agent_kill.json()['id']}/release",
        {"reason": "cleanup agent kill"},
    )
    s.admin.execute(
        "UPDATE sibyl.kill_switch SET pulled_at = now() - interval '11 minutes' WHERE id = $1",
        UUID(first.json()["id"]),
    )
    again = _pull(s, "owner", "tenant")
    assert again.status_code == 201, again.text
    s.post(
        "owner", f"/kill-switches/{again.json()['id']}/release", {"reason": "cleanup tenant kill"}
    )


def test_acks_are_idempotent_and_listed(sworld: SWorld) -> None:
    s = sworld
    gateway_key = s.key("gw1", s.a, ["gateway:proxy"])
    ks = _pull(s, "owner", "agent", s.agent()).json()
    body = {"gateway_id": "gw-a", "snapshot_version": ks["routing_version_at_pull"]}
    first = s.post("gw1", f"/kill-switches/{ks['id']}/acks", body)
    assert first.status_code == 201, first.text
    second = s.post("gw1", f"/kill-switches/{ks['id']}/acks", body)
    assert second.status_code == 200
    applied = s.val(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1 AND action ="
        " 'killswitch.applied'"
        " AND resource_id = $2",
        s.a.id,
        UUID(ks["id"]),
    )
    assert applied == 1
    actor = s.one(
        "SELECT actor_type, actor_id, actor_key_id, actor_session_id FROM sibyl.audit_events"
        " WHERE tenant_id = $1 AND action = 'killswitch.applied' AND resource_id = $2",
        s.a.id,
        UUID(ks["id"]),
    )
    assert dict(actor) == {
        "actor_type": "api_key",
        "actor_id": None,
        "actor_key_id": gateway_key,
        "actor_session_id": None,
    }
    listed = s.get("owner", "/kill-switches", state="pulled").json()["data"]
    mine = next(k for k in listed if k["id"] == ks["id"])
    assert mine["acks"][0]["gateway_id"] == "gw-a"
    assert s.post("owner", f"/kill-switches/{ks['id']}/acks", body).status_code == 403
    s.post("owner", f"/kill-switches/{ks['id']}/release", {"reason": "cleanup after ack"})
    assert json.dumps(listed)
