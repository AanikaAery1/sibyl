"""Lane AG-LIVE held actions on PG17: ``on_behalf_of`` (the requester and the person the agent
acted for never approve), the decision ``history`` on single reads, ``matched_paths`` and
``four_eyes`` on the record."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_ag_gate import REASON, TRANSFER_POLICY, Gate


def _hold(gate: Gate, agent: UUID, call_id: str, amount: int = 6000, **extra: Any) -> Any:
    body = {**gate.hold_body(agent, call_id, {"amount": amount}), **extra}
    return gate.post("/held-actions", body, "keys")


def _act(gate: Gate, held: str, action: str, who: str, reason: str = REASON) -> Any:
    return gate.post(f"/held-actions/{held}/actions", {"action": action, "reason": reason}, who)


def _type(resp: Any) -> str:
    return str(resp.json().get("type", ""))


def _user(gate: Gate, who: str) -> str:
    return str(gate.w.a.users[who])


def _kinds(history: list[dict[str, Any]]) -> list[str]:
    return [entry["kind"] for entry in history]


def test_on_behalf_of_a_user_is_recorded_and_that_user_cannot_approve(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    operator = _user(gate, "operator")
    created = _hold(gate, agent, "obo-user", on_behalf_of={"kind": "user", "id": operator})
    assert created.status_code == 201, created.text
    held = created.json()
    assert held["on_behalf_of"] == {"kind": "user", "id": operator}
    head = gate.head()
    refused = _act(gate, held["id"], "approve", "operator", "my own transfer, approving it")
    assert refused.status_code == 409 and _type(refused).endswith("/self_approval")
    assert gate.audit_since(head) == ["access.denied"]
    after = gate.get(f"/held-actions/{held['id']}", "operator").json()
    assert after["state"] == "pending"
    refusal = after["history"][-1]
    assert refusal["kind"] == "refused" and refusal["code"] == "self_approval"
    assert refusal["user_id"] == operator and refusal["reason"] == "my own transfer, approving it"
    approved = _act(gate, held["id"], "approve", "approver")
    assert approved.status_code == 200, approved.text
    assert _kinds(approved.json()["history"]) == ["requested", "refused", "approved"]


def test_the_on_behalf_of_user_may_still_deny(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    operator = _user(gate, "operator")
    held = _hold(gate, agent, "obo-deny", on_behalf_of={"kind": "user", "id": operator}).json()
    denied = _act(gate, held["id"], "deny", "operator")
    assert denied.status_code == 200, denied.text
    assert (denied.json()["state"], denied.json()["decision"]) == ("denied", "deny")


def test_on_behalf_of_counts_against_four_eyes(gate: Gate) -> None:
    """Four-eyes: neither approver may be the person the agent acted for."""
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY, four_eyes=True)
    approver = _user(gate, "approver")
    held = _hold(gate, agent, "obo-4eyes", on_behalf_of={"kind": "user", "id": approver}).json()
    assert held["four_eyes"] is True and held["approvals_required"] == 2
    first = _act(gate, held["id"], "approve", "operator")
    assert first.status_code == 200 and first.json()["state"] == "pending"
    second = _act(gate, held["id"], "approve", "approver")
    assert second.status_code == 409 and _type(second).endswith("/self_approval")
    third = _act(gate, held["id"], "approve", "owner")
    assert third.status_code == 200 and third.json()["state"] == "approved"
    history = third.json()["history"]
    assert _kinds(history) == ["requested", "approval", "refused", "approved"]
    assert history[1]["approvals"] == 1 and history[3]["approvals"] == 2
    assert history[3]["step_up"] is True  # payments.* is sensitive


def test_an_external_on_behalf_of_is_kept_and_excludes_nobody(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    ref = {"kind": "external", "ref": "crm:customer/42"}
    held = _hold(gate, agent, "obo-ext", on_behalf_of=ref).json()
    assert held["on_behalf_of"] == ref
    stored = gate.w.admin.fetchrow(
        "SELECT on_behalf_of_kind, on_behalf_of_ref FROM sibyl.held_action WHERE id = $1",
        UUID(held["id"]),
    )
    assert tuple(stored) == ("external", "crm:customer/42")
    assert _act(gate, held["id"], "approve", "operator").status_code == 200


def test_a_malformed_on_behalf_of_is_422(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    bad = _hold(gate, agent, "obo-bad", on_behalf_of={"kind": "user", "id": "nope"})
    assert bad.status_code == 422 and _type(bad).endswith("/validation_failed")
    worse = _hold(gate, agent, "obo-worse", on_behalf_of={"kind": "external", "ref": "a\nb"})
    assert worse.status_code == 422


def test_no_on_behalf_of_is_null(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "obo-none").json()
    assert held["on_behalf_of"] is None


def test_history_records_request_duplicate_refusal_and_decision(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY, four_eyes=True)
    held = _hold(gate, agent, "hist-4eyes").json()
    assert _kinds(held["history"]) == ["requested"]
    assert held["history"][0]["key_id"] == str(gate.keys["keys"])
    assert held["history"][0]["user_id"] is None
    assert _act(gate, held["id"], "approve", "operator").status_code == 200
    dup = _act(gate, held["id"], "approve", "operator")
    assert dup.status_code == 409 and _type(dup).endswith("/duplicate_approver")
    denied = _act(gate, held["id"], "deny", "approver").json()
    history = denied["history"]
    assert _kinds(history) == ["requested", "approval", "refused", "denied"]
    assert history[2]["code"] == "duplicate_approver"
    assert history[3]["user_id"] == _user(gate, "approver") and history[3]["reason"] == REASON
    assert all(
        set(e) == {"at", "kind", "user_id", "key_id", "reason", "step_up", "code", "approvals"}
        for e in history
    )


def test_a_blocked_hold_starts_with_a_blocked_entry(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "hist-block", amount=50000).json()
    assert _kinds(held["history"]) == ["blocked"]
    assert held["matched_paths"] == ["/amount"]


def test_history_is_on_single_reads_only_and_matched_paths_everywhere(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "hist-list").json()
    assert held["matched_paths"] == ["/amount"] and held["four_eyes"] is False
    listed = gate.get("/held-actions", agent_id=str(agent)).json()["data"]
    assert [h["id"] for h in listed] == [held["id"]]
    assert "history" not in listed[0] and listed[0]["matched_paths"] == ["/amount"]
    single = gate.get(f"/held-actions/{held['id']}", "keys").json()
    assert _kinds(single["history"]) == ["requested"]


def test_refusals_stop_being_recorded_before_the_trail_is_full(gate: Gate) -> None:
    """Refused attempts are capped (48) so the decision and the expiry always fit; every refusal
    is still audited ``access.denied``."""
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    operator = _user(gate, "operator")
    held = _hold(gate, agent, "hist-cap", on_behalf_of={"kind": "user", "id": operator}).json()
    gate.w.admin.execute(
        "UPDATE sibyl.held_action SET history = history || $2::jsonb WHERE id = $1",
        UUID(held["id"]),
        json.dumps(held["history"] * 47),
    )
    for _ in range(2):
        resp = _act(gate, held["id"], "approve", "operator")
        assert resp.status_code == 409
    after = gate.get(f"/held-actions/{held['id']}").json()
    assert len(after["history"]) == 49 and after["history"][-1]["kind"] == "refused"
    approved = _act(gate, held["id"], "approve", "approver").json()
    assert len(approved["history"]) == 50 and approved["history"][-1]["kind"] == "approved"


def test_a_refusal_on_an_unknown_hold_records_nothing(gate: Gate) -> None:
    resp = _act(gate, "0192767f-0000-7000-8000-00000000dead", "approve", "operator")
    assert resp.status_code == 404


# --- B31: an on-behalf-of user must exist in the tenant (the hold fails closed) ----------------


def _holds(gate: Gate, agent: UUID) -> int:
    return int(
        gate.w.admin.fetchval("SELECT count(*) FROM sibyl.held_action WHERE agent_id = $1", agent)
    )


def test_an_unknown_on_behalf_of_user_is_422_and_nothing_is_held(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    ghost = "0192767f-0000-7000-8000-00000000dead"
    resp = _hold(gate, agent, "obo-ghost", on_behalf_of={"kind": "user", "id": ghost})
    assert resp.status_code == 422 and _type(resp).endswith("/validation_failed"), resp.text
    assert "on_behalf_of" in resp.json().get("detail", "")
    assert _holds(gate, agent) == 0


def test_a_user_of_another_tenant_is_422(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    foreign = str(gate.w.b.users["owner"])
    resp = _hold(gate, agent, "obo-foreign", on_behalf_of={"kind": "user", "id": foreign})
    assert resp.status_code == 422 and _type(resp).endswith("/validation_failed"), resp.text
    assert _holds(gate, agent) == 0


def test_an_external_ref_is_not_checked_against_users(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    ref = {"kind": "external", "ref": "0192767f-0000-7000-8000-00000000dead"}
    assert _hold(gate, agent, "obo-ext-uuid", on_behalf_of=ref).status_code == 201


# --- B32: a deactivated on-behalf-of user is refused exactly like an unknown one ---------------


def _user_with_status(gate: Gate, status: str) -> str:
    """A fresh user of tenant A in ``status`` (same issuer as the seeded operator)."""
    tag = uuid4().hex[:10]
    return str(
        gate.w.admin.fetchval(
            "INSERT INTO sibyl.app_user (tenant_id, oidc_issuer_id, subject, email, status)"
            " SELECT tenant_id, oidc_issuer_id, $3, $4, $5 FROM sibyl.app_user"
            " WHERE tenant_id = $1 AND id = $2 RETURNING id",
            gate.tenant,
            UUID(_user(gate, "operator")),
            f"b32-{tag}",
            f"b32-{tag}@example.test",
            status,
        )
    )


@pytest.mark.parametrize("status", ["disabled", "deprovisioned"])
def test_a_deactivated_on_behalf_of_user_is_422_like_an_unknown_user(
    gate: Gate, status: str
) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    unknown = {"kind": "user", "id": str(uuid4())}
    ghost = _hold(gate, agent, f"obo-b32-ghost-{status}", on_behalf_of=unknown)
    gone = _user_with_status(gate, status)
    resp = _hold(gate, agent, f"obo-b32-{status}", on_behalf_of={"kind": "user", "id": gone})
    assert resp.status_code == 422 and _type(resp).endswith("/validation_failed"), resp.text
    # indistinguishable from an unknown user: no hint that the account exists
    assert resp.json()["detail"] == ghost.json()["detail"]
    assert _holds(gate, agent) == 0


@pytest.mark.parametrize("status", ["invited", "active"])
def test_an_invited_or_active_on_behalf_of_user_is_held(gate: Gate, status: str) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    who = _user_with_status(gate, status)
    resp = _hold(gate, agent, f"obo-b32-ok-{status}", on_behalf_of={"kind": "user", "id": who})
    assert resp.status_code == 201, resp.text
