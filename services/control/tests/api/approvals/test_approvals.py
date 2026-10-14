"""``/approvals`` on PG17: read-only list/get with filters, group rule, decided via incidents."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from sibyl_lane_s_world import SWorld

REASON = "approval test: operator decision with context"


def _approval(s: SWorld, *, group: Any = None) -> dict[str, Any]:
    backup = s.agent(tier=2)
    agent = s.agent(tier=1, model=s.model(s.provider()), group=group)
    s.plan(agent)
    steps = s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    resp = s.post(
        "owner",
        "/incidents",
        {
            "agent_id": str(agent),
            "action": "failover",
            "target": {"step_id": str(steps["backup_agent"])},
            "reason": REASON,
        },
    )
    assert resp.status_code == 202, resp.text
    return {"agent": agent, "incident": resp.json()}


def test_list_and_get_with_filters(sworld: SWorld) -> None:
    s = sworld
    a = _approval(s)
    approval_id = a["incident"]["approval"]["id"]
    got = s.get("viewer", f"/approvals/{approval_id}")
    assert got.status_code == 200
    body = got.json()
    assert body["incident_id"] == a["incident"]["id"] and body["state"] == "pending"
    assert body["requested_action"] == "backup_agent_failover" and body["tier"] == 1
    listed = s.get("viewer", "/approvals", agent_id=str(a["agent"]), state="pending").json()["data"]
    assert [x["id"] for x in listed] == [approval_id]
    assert (
        s.get("viewer", "/approvals", agent_id=str(a["agent"]), state="approved").json()["data"]
        == []
    )
    assert s.get("viewer", "/approvals", tier=2, agent_id=str(a["agent"])).json()["data"] == []
    s.post(
        "approver",
        f"/incidents/{a['incident']['id']}/actions",
        {"action": "approve", "reason": REASON},
    )
    decided = s.get("viewer", f"/approvals/{approval_id}").json()
    assert decided["state"] == "approved" and decided["decided_by_user_id"] == str(
        s.users["approver"]
    )
    assert decided["decision_reason"] == REASON


def test_unknown_and_foreign_ids_are_404(sworld: SWorld) -> None:
    s = sworld
    a = _approval(s)
    assert s.get("owner", f"/approvals/{uuid4()}").status_code == 404
    assert s.get("owner-b", f"/approvals/{a['incident']['approval']['id']}").status_code == 404


def test_tier_out_of_range_is_422(sworld: SWorld) -> None:
    assert sworld.get("owner", "/approvals", tier=4).status_code == 422
