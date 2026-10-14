"""Held actions on PG17: an enforcement key holds an escalated call (args scrubbed and sealed,
idempotent per call_id), humans approve or deny (four-eyes, no duplicate approver, step-up for
sensitive tools), the control plane's own block denies at once."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sibyl_ag_gate import REASON, TRANSFER_POLICY, Gate
from sibyl_schemas.canonical import canonical_sha256

SECRET = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"


def _hold(gate: Gate, agent: UUID, call_id: str, args: dict[str, Any], who: str = "keys") -> Any:
    return gate.post("/held-actions", gate.hold_body(agent, call_id, args), who)


def _act(gate: Gate, held: str, action: str, who: str) -> Any:
    return gate.post(f"/held-actions/{held}/actions", {"action": action, "reason": REASON}, who)


def _type(resp: Any) -> str:
    return str(resp.json().get("type", ""))


def test_a_key_holds_an_escalated_call_with_sealed_scrubbed_args(gate: Gate) -> None:
    agent = gate.agent()
    policy = gate.approved_policy(agent, TRANSFER_POLICY)
    args = {"amount": 7000, "note": f"token {SECRET}"}
    head = gate.head()
    resp = _hold(gate, agent, "call-1", args)
    assert resp.status_code == 201, resp.text
    held = resp.json()
    assert held["state"] == "pending" and held["decision"] is None
    assert held["policy_id"] == policy and held["rule_id"] == "needs_review"
    assert held["sensitive"] is True and held["approvals_required"] == 1
    assert held["args_sha256"] == canonical_sha256(args)
    assert held["held_action_id"] == held["id"]
    assert held["args"] is None and held["hold_timeout_s"] == 600
    assert gate.audit_since(head) == ["action.escalated"]
    ref = gate.w.admin.fetchrow(
        "SELECT kind, source_kind, source_id, uri FROM sibyl.payload_refs WHERE id = $1",
        UUID(held["args_payload_ref"]),
    )
    assert (ref["kind"], ref["source_kind"], str(ref["source_id"])) == (
        "action_args",
        "held_action",
        held["id"],
    )
    assert SECRET.encode() not in gate.blob.objects[ref["uri"]]
    human = gate.get(f"/held-actions/{held['id']}", "operator").json()
    assert human["args"]["amount"] == 7000 and SECRET not in human["args"]["note"]
    replay = _hold(gate, agent, "call-1", args)
    assert replay.status_code == 200 and replay.json()["id"] == held["id"]
    polled = gate.get(f"/held-actions/{held['id']}", "keys")
    assert polled.status_code == 200 and polled.json()["args"] is None


def test_a_bound_key_cannot_hold_or_read_another_agents_action(gate: Gate) -> None:
    agent, other = gate.agent(), gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    key = gate.bound_key(other)
    assert _hold(gate, agent, "call-bound", {"amount": 6000}, key).status_code == 404
    held = _hold(gate, agent, "call-bound", {"amount": 6000}).json()
    assert gate.get(f"/held-actions/{held['id']}", key).status_code == 404
    assert gate.get(f"/held-actions/{held['id']}", "keys-b").status_code == 404


def test_operator_approves_and_the_decision_is_allow(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "call-approve", {"amount": 6000}).json()
    head = gate.head()
    resp = _act(gate, held["id"], "approve", "operator")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["state"], body["decision"]) == ("approved", "allow")
    assert gate.audit_since(head) == ["action.approved"]
    again = _act(gate, held["id"], "deny", "approver")
    assert again.status_code == 409 and _type(again).endswith("/action_not_pending")


def test_four_eyes_needs_two_distinct_humans(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY, four_eyes=True)
    held = _hold(gate, agent, "call-4eyes", {"amount": 6000}).json()
    assert held["approvals_required"] == 2
    first = _act(gate, held["id"], "approve", "operator")
    assert first.status_code == 200 and first.json()["state"] == "pending"
    assert len(first.json()["approvals"]) == 1
    twice = _act(gate, held["id"], "approve", "operator")
    assert twice.status_code == 409 and _type(twice).endswith("/duplicate_approver")
    second = _act(gate, held["id"], "approve", "approver")
    assert second.status_code == 200, second.text
    assert (second.json()["state"], second.json()["decision"]) == ("approved", "allow")


def test_deny_ends_the_hold(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "call-deny", {"amount": 6000}).json()
    head = gate.head()
    resp = _act(gate, held["id"], "deny", "approver")
    assert (resp.json()["state"], resp.json()["decision"]) == ("denied", "deny")
    assert gate.audit_since(head) == ["action.denied"]


def test_sensitive_tools_need_a_fresh_step_up(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "call-stepup", {"amount": 6000}).json()
    stale = _act(gate, held["id"], "approve", "owner-stale")
    assert stale.status_code == 403 and _type(stale).endswith("/step_up_required")


def test_auditor_and_keys_cannot_decide(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "call-roles", {"amount": 6000}).json()
    assert _act(gate, held["id"], "approve", "auditor").status_code == 403
    assert _act(gate, held["id"], "approve", "keys").status_code == 403
    assert gate.get("/held-actions", "auditor", state="pending").status_code == 200


def test_the_control_planes_own_block_denies_at_once(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    head = gate.head()
    resp = _hold(gate, agent, "call-block", {"amount": 50000})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert (body["state"], body["decision"], body["server_effect"]) == ("denied", "deny", "block")
    assert gate.audit_since(head) == ["action.blocked"]


def test_list_filters(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    _hold(gate, agent, "call-list-1", {"amount": 6000})
    rows = gate.get("/held-actions", "viewer", agent_id=str(agent), state="pending").json()["data"]
    assert [r["call_id"] for r in rows] == ["call-list-1"]
    assert all(r["args"] is None for r in rows)


def test_list_accepts_several_states_and_pages_with_them(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    pending = _hold(gate, agent, "call-multi-1", {"amount": 6000}).json()
    _hold(gate, agent, "call-multi-2", {"amount": 6100})
    blocked = _hold(gate, agent, "call-multi-3", {"amount": 50000}).json()
    assert blocked["state"] == "denied"
    both = gate.get(
        "/held-actions", "viewer", agent_id=str(agent), state=["pending", "denied"]
    ).json()["data"]
    assert {r["call_id"] for r in both} == {"call-multi-1", "call-multi-2", "call-multi-3"}
    only = gate.get("/held-actions", "viewer", agent_id=str(agent), state="denied").json()
    assert [r["call_id"] for r in only["data"]] == ["call-multi-3"]
    first = gate.get(
        "/held-actions", "viewer", agent_id=str(agent), state=["denied", "pending"], limit=2
    )
    assert first.status_code == 200 and first.json()["has_more"] is True
    assert "state=denied&state=pending" in first.headers["link"]
    rest = gate.get(
        "/held-actions",
        "viewer",
        agent_id=str(agent),
        state=["pending", "denied"],  # order-insensitive: the same filter
        limit=2,
        cursor=first.json()["next_cursor"],
    )
    assert rest.status_code == 200, rest.text
    assert len(first.json()["data"]) + len(rest.json()["data"]) == 3
    assert pending["id"] in {r["id"] for r in first.json()["data"] + rest.json()["data"]}
    bad = gate.get("/held-actions", "viewer", state=["pending", "bogus"])
    assert bad.status_code == 422


def test_list_include_args_shows_scrubbed_args_to_deciders_only(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    _hold(gate, agent, "call-args-1", {"amount": 7000, "note": f"token {SECRET}"})

    def listed(who: str, **params: Any) -> Any:
        resp = gate.get("/held-actions", who, agent_id=str(agent), **params)
        assert resp.status_code == 200, (who, resp.text)
        [row] = resp.json()["data"]
        return row["args"]

    shown = listed("operator", include="args")
    assert shown["amount"] == 7000 and SECRET not in shown["note"]
    assert listed("operator") is None  # opt-in
    assert listed("viewer", include="args") is None  # actions:read without actions:decide
    assert listed("auditor", include="args") is None
    keys = gate.get("/held-actions", "keys", include="args")
    assert keys.status_code == 403  # enforcement keys poll one hold, they never list
    assert gate.get("/held-actions", "operator", include="bogus").status_code == 422
