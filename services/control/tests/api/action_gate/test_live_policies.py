"""Lane AG-LIVE action policies on PG17: a stable ``policy_id`` across versions (the row ``id``
stays the version id), ``scope`` with a display label, ``change_note``, the approval trail,
``superseded_at``, the list filters (``policy_id``, ``agent_id``, ``state``,
``include_history``) and the draft simulate (an unsaved document; writes nothing)."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sibyl_ag_gate import REASON, TRANSFER_POLICY, Gate


def _type(resp: Any) -> str:
    return str(resp.json().get("type", ""))


def _create(gate: Gate, agent: UUID | None, **extra: Any) -> Any:
    body = {
        "name": "payments guard",
        "scope_kind": "agent" if agent is not None else "tenant",
        "scope_id": None if agent is None else str(agent),
        "document": TRANSFER_POLICY,
        "reason": REASON,
        **extra,
    }
    return gate.post("/action-policies", body)


def _name(gate: Gate, agent: UUID) -> str:
    return str(gate.w.admin.fetchval("SELECT name FROM sibyl.agent WHERE id = $1", agent))


def test_versions_share_a_stable_policy_id(gate: Gate) -> None:
    agent = gate.agent()
    first = _create(gate, agent, change_note="first cut of the payments guard").json()
    assert first["policy_id"] == first["id"] and first["version_no"] == 1
    assert first["change_note"] == "first cut of the payments guard"
    assert first["approvals"] == [] and first["superseded_at"] is None
    approved = gate.post(f"/action-policies/{first['id']}/approve", {"reason": REASON}, "approver")
    assert approved.status_code == 200, approved.text
    trail = approved.json()["approvals"]
    assert len(trail) == 1 and trail[0]["user_id"] == str(gate.w.a.users["approver"])
    assert trail[0]["reason"] == REASON and trail[0]["at"]
    second = _create(gate, agent, change_note="raise the review bar", based_on_id=first["id"])
    assert second.status_code == 201, second.text
    v2 = second.json()
    assert v2["policy_id"] == first["id"] and v2["id"] != first["id"] and v2["version_no"] == 2
    assert v2["document"]["policy_id"] == v2["id"]  # the enforcement identity is the version id
    assert gate.approve(v2["id"]).status_code == 200
    old = gate.get(f"/action-policies/{first['id']}").json()
    assert old["state"] == "superseded" and old["superseded_at"] and old["policy_id"] == first["id"]


def test_based_on_must_be_a_version_of_the_same_scope(gate: Gate) -> None:
    agent, other = gate.agent(), gate.agent()
    mine = _create(gate, agent).json()
    foreign = _create(gate, other, based_on_id=mine["id"])
    assert foreign.status_code == 422 and _type(foreign).endswith("/validation_failed")
    missing = _create(gate, agent, based_on_id=str(uuid4()))
    assert missing.status_code == 422


def test_scope_carries_a_display_label(gate: Gate) -> None:
    agent = gate.agent()
    created = _create(gate, agent).json()
    assert created["scope"] == {"kind": "agent", "id": str(agent), "label": _name(gate, agent)}
    group = gate.w.a.group_id
    by_group = gate.create_policy(TRANSFER_POLICY, scope_kind="agent_group", scope_id=group).json()
    group_name = gate.w.admin.fetchval("SELECT name FROM sibyl.agent_group WHERE id = $1", group)
    assert by_group["scope"] == {"kind": "agent_group", "id": str(group), "label": group_name}
    tenant = gate.create_policy(TRANSFER_POLICY, scope_kind="tenant").json()
    assert tenant["scope"] == {"kind": "tenant", "id": None, "label": "All agents"}
    listed = gate.get("/action-policies", policy_id=created["policy_id"]).json()["data"]
    assert listed[0]["scope"]["label"] == _name(gate, agent)


def test_list_filters_and_history(gate: Gate) -> None:
    agent = gate.agent()
    v1 = gate.approved_policy(agent, TRANSFER_POLICY)
    v2 = gate.approved_policy(agent, TRANSFER_POLICY)
    v3 = _create(gate, agent).json()["id"]  # a draft on top
    lineage = v1
    current = gate.get("/action-policies", policy_id=lineage).json()["data"]
    assert [p["id"] for p in current] == [v3, v2]  # superseded v1 is history
    everything = gate.get("/action-policies", policy_id=lineage, include_history="true").json()
    assert [p["id"] for p in everything["data"]] == [v3, v2, v1]
    superseded = gate.get("/action-policies", policy_id=lineage, state="superseded").json()
    assert [p["id"] for p in superseded["data"]] == [v1]
    by_agent = gate.get("/action-policies", agent_id=str(agent), state="draft").json()["data"]
    assert [p["id"] for p in by_agent] == [v3]
    other = gate.get("/action-policies", policy_id=str(uuid4())).json()["data"]
    assert other == []
    bad = gate.get("/action-policies", include_history="maybe")
    assert bad.status_code == 422


def test_paging_keeps_the_history_filter(gate: Gate) -> None:
    agent = gate.agent()
    lineage = gate.approved_policy(agent, TRANSFER_POLICY)
    for _ in range(3):
        gate.approved_policy(agent, TRANSFER_POLICY)
    first = gate.get("/action-policies", policy_id=lineage, include_history="true", limit=2).json()
    assert len(first["data"]) == 2 and first["has_more"] is True
    rest = gate.get(
        "/action-policies",
        policy_id=lineage,
        include_history="true",
        limit=2,
        cursor=first["next_cursor"],
    ).json()
    versions = [p["version_no"] for p in first["data"] + rest["data"]]
    assert versions == [4, 3, 2, 1]


DRAFT = {
    "schema": "sibyl-action-policy/1",
    "default_effect": "allow",
    "sensitive_tools": ["payments.*"],
    "rules": [
        {
            "rule_id": "huge",
            "tool": "payments.transfer",
            "when": {"gt": ["/amount", 1000]},
            "effect": "block",
            "reason": "the draft blocks anything over 1,000",
        }
    ],
}


def _simulate(gate: Gate, who: str = "auditor", **body: Any) -> Any:
    return gate.post("/action-policies/simulate", {"document": DRAFT, **body}, who)


def _rows(gate: Gate) -> tuple[int, int, int]:
    count = gate.w.admin.fetchval
    return (
        int(count("SELECT count(*) FROM sibyl.action_policy")),
        int(count("SELECT count(*) FROM sibyl.action_counter")),
        int(count("SELECT count(*) FROM sibyl.held_action")),
    )


def test_draft_simulate_decides_an_unsaved_document_and_writes_nothing(gate: Gate) -> None:
    before, head = _rows(gate), gate.head()
    big = _simulate(gate, tool="payments.transfer", args={"amount": 5000})
    assert big.status_code == 200, big.text
    body = big.json()
    assert body["effect"] == "block" and body["rule_id"] == "huge"
    assert body["matched_paths"] == ["/amount"] and body["sensitive"] is True
    assert body["policy_id"] is None and body["policy_state"] is None and body["evaluated_at"]
    small = _simulate(gate, tool="payments.transfer", args={"amount": 10}).json()
    assert small["effect"] == "escalate" and small["rule_id"] is None  # sensitive tool default
    assert _rows(gate) == before and gate.audit_since(head) == []


def test_draft_simulate_with_an_agent_replaces_that_scope_and_keeps_the_others(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)  # the draft takes this one's place
    resp = _simulate(gate, tool="payments.transfer", args={"amount": 6000}, agent_id=str(agent))
    assert resp.json()["effect"] == "block"  # the draft decides, not the approved escalate
    lenient = {**DRAFT, "rules": [], "sensitive_tools": []}
    tenant_scope = gate.post(
        "/action-policies/simulate",
        {
            "document": lenient,
            "tool": "payments.transfer",
            "args": {"amount": 6000},
            "agent_id": str(agent),
            "scope_kind": "tenant",
        },
        "auditor",
    ).json()
    assert tenant_scope["effect"] == "escalate"  # the agent's own approved policy still applies
    assert tenant_scope["rule_id"] == "needs_review"


def test_draft_simulate_refuses_a_bad_document_or_scope(gate: Gate) -> None:
    bad = gate.post(
        "/action-policies/simulate",
        {"document": {"rules": [{"rule_id": "x", "tool": "t", "effect": "maybe", "reason": "r"}]},
         "tool": "t", "args": {}},
        "auditor",
    )  # fmt: skip
    assert bad.status_code == 422 and _type(bad).endswith("/validation_failed")
    unknown = _simulate(gate, tool="t", args={}, agent_id=str(uuid4()))
    assert unknown.status_code == 404
    mismatch = _simulate(gate, tool="t", args={}, scope_kind="agent")
    assert mismatch.status_code == 422
    assert _simulate(gate, "keys", tool="t", args={}).status_code == 403


def test_saved_simulate_reports_the_policy_state(gate: Gate) -> None:
    policy = gate.create_policy(TRANSFER_POLICY, scope_id=gate.agent()).json()["id"]
    resp = gate.post(
        f"/action-policies/{policy}/simulate",
        {"tool": "payments.transfer", "args": {"amount": 100}},
        "viewer",
    ).json()
    assert resp["policy_state"] == "draft" and resp["evaluated_at"] and resp["sensitive"] is True
