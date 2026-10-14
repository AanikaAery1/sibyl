"""Action policies on PG17: create, validate, approve (tier-1 four-eyes), supersede, retire,
simulate (writes nothing) and the role matrix."""

from __future__ import annotations

from typing import Any

from sibyl_ag_gate import REASON, TRANSFER_POLICY, Gate


def _type(resp: Any) -> str:
    return str(resp.json().get("type", ""))


def test_create_returns_a_draft_with_its_normalised_document_and_rules(gate: Gate) -> None:
    agent = gate.agent()
    head = gate.head()
    resp = gate.create_policy(TRANSFER_POLICY, scope_id=agent)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["state"] == "draft" and body["version_no"] == 1
    assert body["scope_kind"] == "agent" and body["scope_id"] == str(agent)
    assert body["document"]["policy_id"] == body["id"] and body["document"]["version"] == 1
    assert [r["rule_id"] for r in body["rules"]] == ["over_limit", "needs_review", "small"]
    assert body["default_effect"] == "allow" and body["hold_timeout_s"] == 600
    assert resp.headers["etag"] and resp.headers["x-sibyl-audit-receipt"]
    assert gate.audit_since(head) == ["action_policy.created"]
    again = gate.get(f"/action-policies/{body['id']}")
    assert again.status_code == 200 and again.json()["document_sha256"] == body["document_sha256"]


def test_an_invalid_document_is_422(gate: Gate) -> None:
    bad = {"rules": [{"rule_id": "x", "tool": "t", "effect": "maybe", "reason": "r"}]}
    resp = gate.create_policy(bad, scope_id=gate.agent())
    assert resp.status_code == 422, resp.text
    unsafe = {"rules": [{"rule_id": "x", "tool": "t", "when": {"eval": "1"}, "effect": "allow",
                         "reason": "r"}]}  # fmt: skip
    assert gate.create_policy(unsafe, scope_id=gate.agent()).status_code == 422


def test_scope_checks(gate: Gate) -> None:
    tenant_with_id = gate.create_policy(TRANSFER_POLICY, scope_kind="tenant", scope_id=gate.agent())
    assert tenant_with_id.status_code == 422
    from uuid import uuid4

    assert gate.create_policy(TRANSFER_POLICY, scope_id=uuid4()).status_code == 404


def test_approve_then_approve_again_is_invalid_transition(gate: Gate) -> None:
    agent = gate.agent()
    policy = gate.create_policy(TRANSFER_POLICY, scope_id=agent).json()["id"]
    head = gate.head()
    ok = gate.approve(policy)
    assert ok.status_code == 200, ok.text
    assert ok.json()["state"] == "approved" and ok.json()["approved_by"]
    assert gate.audit_since(head) == ["action_policy.approved"]
    again = gate.approve(policy)
    assert again.status_code == 409 and _type(again).endswith("/invalid_transition")


def test_tier1_policy_needs_four_eyes(gate: Gate) -> None:
    agent = gate.agent(tier=1)
    created = gate.create_policy(TRANSFER_POLICY, scope_id=agent).json()
    assert created["approval_four_eyes"] is True
    self_approve = gate.approve(created["id"], "owner")
    assert self_approve.status_code == 409 and _type(self_approve).endswith("/self_approval")
    second = gate.approve(created["id"], "approver")
    assert second.status_code == 200, second.text


def test_a_new_version_supersedes_the_approved_one(gate: Gate) -> None:
    agent = gate.agent()
    first = gate.approved_policy(agent, TRANSFER_POLICY)
    second = gate.create_policy(TRANSFER_POLICY, scope_id=agent).json()
    assert second["version_no"] == 2
    assert gate.approve(second["id"]).status_code == 200
    old = gate.get(f"/action-policies/{first}").json()
    assert old["state"] == "superseded" and old["superseded_by"] == second["id"]
    listed = gate.get("/action-policies", agent_id=str(agent), state="approved").json()["data"]
    assert [p["id"] for p in listed] == [second["id"]]


def test_retire(gate: Gate) -> None:
    policy = gate.approved_policy(gate.agent(), TRANSFER_POLICY)
    head = gate.head()
    resp = gate.post(f"/action-policies/{policy}/retire", {"reason": REASON})
    assert resp.status_code == 200 and resp.json()["state"] == "retired"
    assert gate.audit_since(head) == ["action_policy.retired"]
    again = gate.post(f"/action-policies/{policy}/retire", {"reason": REASON})
    assert again.status_code == 409


def test_simulate_decides_and_writes_nothing(gate: Gate) -> None:
    policy = gate.create_policy(TRANSFER_POLICY, scope_id=gate.agent()).json()["id"]
    head = gate.head()
    cases = {15000: "block", 6000: "escalate", 100: "allow"}
    for amount, effect in cases.items():
        resp = gate.post(
            f"/action-policies/{policy}/simulate",
            {"tool": "payments.transfer", "args": {"amount": amount}},
            "auditor",
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["effect"] == effect, (amount, resp.json())
    unknown = gate.post(
        f"/action-policies/{policy}/simulate", {"tool": "payments.refund", "args": {}}, "viewer"
    )
    assert unknown.json()["effect"] == "escalate"  # sensitive tool, no rule matched
    assert gate.audit_since(head) == []


def test_role_matrix(gate: Gate) -> None:
    agent = gate.agent()
    assert gate.create_policy(TRANSFER_POLICY, scope_id=agent, who="operator").status_code == 403
    assert gate.create_policy(TRANSFER_POLICY, scope_id=agent, who="auditor").status_code == 403
    assert gate.create_policy(TRANSFER_POLICY, scope_id=agent, who="admin").status_code == 201
    created = gate.create_policy(TRANSFER_POLICY, scope_id=agent, who="approver")
    assert created.status_code == 201
    assert gate.get("/action-policies", "auditor").status_code == 200
    assert gate.get("/action-policies", "keys").status_code == 403


def test_group_and_tenant_scopes(gate: Gate) -> None:
    group = gate.w.a.group_id
    created = gate.create_policy(TRANSFER_POLICY, scope_kind="agent_group", scope_id=group)
    assert created.status_code == 201 and created.json()["scope_id"] == str(group)
    tenant = gate.create_policy(TRANSFER_POLICY, scope_kind="tenant")
    assert tenant.status_code == 201 and tenant.json()["scope_id"] is None
