"""Lane AG-LIVE audit reads on PG17: ``occurred_after`` / ``occurred_before`` and ``order=desc``
on ``/audit/events`` (and ``order`` on ``/audit/anchors``), the ``agent_id`` filter that finds
every Action Gate row about an agent (escalated rows name it as their resource; approved, denied
and expired rows in ``detail.agent_id``), and ``GET /action-summary`` for the fleet view."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sibyl_ag_gate import REASON, TRANSFER_POLICY, Gate


def _hold(gate: Gate, agent: UUID, call_id: str, amount: int = 6000) -> dict[str, Any]:
    resp = gate.post("/held-actions", gate.hold_body(agent, call_id, {"amount": amount}), "keys")
    assert resp.status_code == 201, resp.text
    held: dict[str, Any] = resp.json()
    return held


def _act(gate: Gate, held: str, action: str = "approve", who: str = "operator") -> Any:
    return gate.post(f"/held-actions/{held}/actions", {"action": action, "reason": REASON}, who)


def _iso(at: datetime) -> str:
    return at.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _events(gate: Gate, who: str = "auditor", **params: Any) -> Any:
    return gate.get("/audit/events", who, **params)


def test_agent_filter_finds_escalated_approved_and_denied_rows(gate: Gate) -> None:
    agent, other = gate.agent(), gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    gate.approved_policy(other, TRANSFER_POLICY)
    first = _hold(gate, agent, "aud-1")
    second = _hold(gate, agent, "aud-2")
    _hold(gate, other, "aud-3")
    assert _act(gate, first["id"]).status_code == 200
    assert _act(gate, second["id"], "deny").status_code == 200
    resp = _events(gate, agent_id=str(agent), limit=50)
    assert resp.status_code == 200, resp.text
    actions = [e["action"] for e in resp.json()["data"]]
    assert actions.count("action.escalated") == 2
    assert "action.approved" in actions and "action.denied" in actions
    assert all(
        e["resource_id"] == str(agent) or e["detail"].get("agent_id") == str(agent)
        for e in resp.json()["data"]
    )
    escalated = _events(gate, agent_id=str(agent), action="action.escalated").json()["data"]
    assert len(escalated) == 2
    assert all(e["detail"]["agent_id"] == str(agent) for e in escalated)


def test_order_desc_and_paging(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    for i in range(3):
        _hold(gate, agent, f"order-{i}")
    asc = _events(gate, agent_id=str(agent), limit=50).json()["data"]
    desc = _events(gate, agent_id=str(agent), order="desc", limit=2).json()
    seqs = [e["seq"] for e in desc["data"]]
    assert seqs == sorted((e["seq"] for e in asc), reverse=True)[:2]
    more = _events(
        gate, agent_id=str(agent), order="desc", limit=2, cursor=desc["next_cursor"]
    ).json()
    assert more["data"] and more["data"][0]["seq"] < seqs[-1]
    mixed = _events(gate, agent_id=str(agent), order="asc", limit=2, cursor=desc["next_cursor"])
    assert mixed.status_code == 400 or mixed.status_code == 422
    assert _events(gate, order="sideways").status_code == 422


def test_occurred_window_filters(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    _hold(gate, agent, "when-1")
    now = datetime.now(UTC)
    recent = _events(gate, agent_id=str(agent), occurred_after=_iso(now - timedelta(minutes=5)))
    assert len(recent.json()["data"]) >= 1
    future = _events(gate, agent_id=str(agent), occurred_after=_iso(now + timedelta(minutes=5)))
    assert future.json()["data"] == []
    past = _events(gate, agent_id=str(agent), occurred_before=_iso(now - timedelta(minutes=5)))
    assert past.json()["data"] == []
    both = _events(
        gate,
        agent_id=str(agent),
        occurred_after=_iso(now - timedelta(minutes=5)),
        occurred_before=_iso(now + timedelta(minutes=5)),
    )
    assert len(both.json()["data"]) == len(recent.json()["data"])
    assert _events(gate, occurred_after="yesterday").status_code == 422


def test_anchors_order(gate: Gate) -> None:
    assert gate.get("/audit/anchors", "auditor", order="desc").status_code == 200
    assert gate.get("/audit/anchors", "auditor", order="up").status_code == 422


def _summary(gate: Gate, who: str = "viewer", **params: Any) -> Any:
    return gate.get("/action-summary", who, **params)


def test_summary_counts_per_agent_once_per_call(gate: Gate) -> None:
    agent, other = gate.agent(), gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    gate.approved_policy(other, TRANSFER_POLICY)
    approved = _hold(gate, agent, "sum-1")
    denied = _hold(gate, agent, "sum-2")
    _hold(gate, agent, "sum-3", amount=50000)  # the control plane's own block
    replay = gate.post("/held-actions", gate.hold_body(agent, "sum-3", {"amount": 50000}), "keys")
    assert replay.status_code == 200  # the same call: counted once
    _hold(gate, other, "sum-4")
    _act(gate, approved["id"])
    _act(gate, denied["id"], "deny")
    resp = _summary(gate, agent_id=str(agent))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["from"] and body["to"]
    rows = {r["agent_id"]: r for r in body["data"]}
    assert rows[str(agent)] == {
        "agent_id": str(agent),
        "blocked": 1,
        "escalated": 2,
        "approved": 1,
        "denied": 1,
        "expired": 0,
    }
    assert str(other) not in rows
    everyone = {r["agent_id"]: r for r in _summary(gate).json()["data"]}
    assert everyone[str(other)]["escalated"] == 1
    total = _summary(gate).json()["total"]
    assert total["escalated"] >= 3 and total["blocked"] >= 1


def test_summary_window_bounds(gate: Gate) -> None:
    now = datetime.now(UTC)
    later = _summary(
        gate, **{"from": _iso(now + timedelta(hours=1)), "to": _iso(now + timedelta(hours=2))}
    )
    assert later.status_code == 200 and later.json()["data"] == []
    after_now = _summary(gate, **{"from": _iso(now + timedelta(hours=1))})
    assert after_now.status_code == 422  # from after the default to (now)
    too_long = _summary(gate, **{"from": _iso(now - timedelta(days=40)), "to": _iso(now)})
    assert too_long.status_code == 422
    backwards = _summary(gate, **{"from": _iso(now), "to": _iso(now - timedelta(hours=1))})
    assert backwards.status_code == 422


def test_summary_authz(gate: Gate) -> None:
    """``actions:read`` is tenant-wide for every role holding it (0017 seeds), like the held
    actions list; keys have no route here."""
    assert _summary(gate, "keys").status_code == 403
    assert _summary(gate, "nobody").status_code == 403
    in_group = gate.agent(group=gate.w.a.group_id)
    outside = gate.agent()
    for agent in (in_group, outside):
        gate.approved_policy(agent, TRANSFER_POLICY)
        _hold(gate, agent, f"grp-{agent.hex[:6]}")
    for who in ("engineer", "auditor", "operator"):
        resp = _summary(gate, who)
        assert resp.status_code == 200, (who, resp.text)
        seen = {r["agent_id"] for r in resp.json()["data"]}
        assert {str(in_group), str(outside)} <= seen
    assert _summary(gate, agent_id=str(uuid4())).json()["data"] == []
    assert _summary(gate, "owner-b").json()["data"] == []  # another tenant sees none of it
