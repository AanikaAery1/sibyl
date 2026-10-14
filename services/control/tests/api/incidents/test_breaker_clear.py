"""B19 on PG17: an undo never clears the pre-emptive breaker; only the deliberate, audited
``POST /agents/{agent_id}/preemptive-breaker/clear`` (``routing:override``, step-up, group rule +
tenant-scoped role, reason) does."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sibyl_control.worker.saga import runner
from sibyl_lane_s_world import SWorld

REASON = "handler test: breaker reviewed, safe to re-arm"


def _type(resp: Any) -> str:
    return str(resp.json().get("type", "")).rsplit("/", 1)[-1]


def _tripped(s: SWorld, **kw: Any) -> UUID:
    agent = s.agent(model=s.model(s.provider()), **kw)
    s.plan(agent)
    s.admin.execute(
        "UPDATE sibyl.agent SET preemptive_breaker_tripped_at = now() - interval '1 hour'"
        " WHERE id = $1",
        agent,
    )
    return agent


def _clear(s: SWorld, agent: UUID, who: str = "owner", **headers: str) -> Any:
    return s.post(who, f"/agents/{agent}/preemptive-breaker/clear", {"reason": REASON}, **headers)


def _breaker(s: SWorld, agent: UUID) -> Any:
    return s.one(
        "SELECT preemptive_breaker_tripped_at, preemptive_breaker_cleared_at,"
        " preemptive_breaker_cleared_by_user_id FROM sibyl.agent WHERE id = $1",
        agent,
    )


def test_owner_clears_a_tripped_breaker_and_it_is_audited(sworld: SWorld) -> None:
    s = sworld
    agent = _tripped(s)
    resp = _clear(s, agent)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == str(agent) and body["cleared_by_user_id"] == str(s.users["owner"])
    assert resp.headers.get("X-Sibyl-Audit-Receipt")
    row = _breaker(s, agent)
    assert row["preemptive_breaker_tripped_at"] is None
    assert row["preemptive_breaker_cleared_by_user_id"] == s.users["owner"]
    audit = s.one(
        "SELECT actor_type, actor_id, reason, detail FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'preemptive.breaker_cleared' AND resource_id = $2",
        s.a.id,
        agent,
    )
    assert (audit["actor_type"], audit["actor_id"]) == ("human", s.users["owner"])
    assert audit["reason"] == REASON


def test_security_admin_may_clear(sworld: SWorld) -> None:
    s = sworld
    assert _clear(s, _tripped(s), who="approver").status_code == 200


def test_clear_needs_a_fresh_step_up(sworld: SWorld) -> None:
    s = sworld
    agent = _tripped(s)
    resp = _clear(s, agent, who="owner-stale")
    assert resp.status_code == 403 and _type(resp) == "step_up_required", resp.text
    assert _breaker(s, agent)["preemptive_breaker_tripped_at"] is not None


def test_group_limited_engineer_gets_403_in_group_and_404_outside(sworld: SWorld) -> None:
    s = sworld
    inside = _tripped(s, group=s.a.group_id)
    resp = _clear(s, inside, who="engineer")
    assert resp.status_code == 403 and _type(resp) == "forbidden", resp.text
    assert _breaker(s, inside)["preemptive_breaker_tripped_at"] is not None
    outside = _tripped(s)
    assert _clear(s, outside, who="engineer").status_code == 404


def test_readers_cannot_clear(sworld: SWorld) -> None:
    s = sworld
    agent = _tripped(s)
    resp = _clear(s, agent, who="viewer")
    assert resp.status_code == 403
    assert _breaker(s, agent)["preemptive_breaker_tripped_at"] is not None


def test_untripped_unknown_and_other_tenant_agents(sworld: SWorld) -> None:
    s = sworld
    armed = s.agent(model=s.model(s.provider()))
    resp = _clear(s, armed)
    assert resp.status_code == 409 and _type(resp) == "invalid_transition", resp.text
    assert _clear(s, uuid4()).status_code == 404
    foreign = s.agent(s.b, model=s.model(s.provider(s.b), s.b))
    assert _clear(s, foreign).status_code == 404


def test_reason_is_required_and_the_body_strict(sworld: SWorld) -> None:
    s = sworld
    agent = _tripped(s)
    path = f"/agents/{agent}/preemptive-breaker/clear"
    assert s.post("owner", path, {"reason": "short"}).status_code == 422
    assert s.post("owner", path, {}).status_code == 422
    assert s.post("owner", path, {"reason": REASON, "force": True}).status_code == 422
    assert _breaker(s, agent)["preemptive_breaker_tripped_at"] is not None


def test_idempotent_replay(sworld: SWorld) -> None:
    s = sworld
    agent = _tripped(s)
    headers = s.idem("owner")
    path = f"/api/v1/agents/{agent}/preemptive-breaker/clear"
    first = s.client.post(path, json={"reason": REASON}, headers=headers)
    second = s.client.post(path, json={"reason": REASON}, headers=headers)
    assert first.status_code == second.status_code == 200, (first.text, second.text)
    assert second.headers.get("Idempotency-Replayed") == "true"
    n = s.val(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'preemptive.breaker_cleared' AND resource_id = $2",
        s.a.id,
        agent,
    )
    assert n == 1


def test_an_undo_never_clears_the_breaker(sworld: SWorld) -> None:
    """B19: an undo is evidence toward a trip, never a clear."""
    s = sworld
    p2 = s.provider()
    agent = _tripped(s, tier=3)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    undo = s.post("owner", f"/incidents/{fid}/actions", {"action": "undo", "reason": REASON})
    assert undo.status_code == 200, undo.text
    row = _breaker(s, agent)
    assert row["preemptive_breaker_tripped_at"] is not None
    assert row["preemptive_breaker_cleared_at"] is None
