"""Object-rule cases the generated wall cannot derive from the contract alone.

The generated group rule only covers routes with an ``agent_id`` path parameter; these routes
load the object (incident, alert, audit row, erasure request) first and decide on it:

* lane S (lifted from ``test_contract_s_pg``): a foreign tenant's gateway key cannot ack another
  tenant's kill switch, and ``incidents:act`` is group-limited for engineers (an incident on an
  agent outside the engineer's group is 404; inside it the engineer may act);
* alerts: ``alerts:act`` is group-limited for engineers, and provider-scope alerts are
  tenant-wide resources a group-limited caller cannot reach (404);
* governance: ``audit:read`` is group-limited for engineers (rows about agents in their groups
  only); erasure is four-eyes (the requester cannot approve, 409 ``self_approval``) and a
  tenant-scope request is filed by an owner only (``owner_for_tenant_scope``).

Pending while the module is a stub.
"""

from __future__ import annotations

from typing import Any

import pytest
from sibyl_control.api.contract import operation

from ._cases import pending, world_call
from ._world_kit import REASON, Req, agent, provider
from .pg_world import ContractWorld
from .scenarios import SCENARIOS
from .scenarios_governance import agent_audit_seq, alert_row, anchor, erasure_request
from .scenarios_int3 import clear_req, tripped_agent
from .scenarios_lane_s import S_REASON, s_agent


def _type(resp: Any) -> str:
    body = resp.json()
    return str(body.get("type", "")) if isinstance(body, dict) else ""


def _require(op_id: str) -> Any:
    op = operation(op_id)
    if pending(op):
        pytest.xfail(f"{op.module} is still a 501 stub in this tree")
    return op


def test_ack_from_another_tenants_key_is_404(cworld: ContractWorld) -> None:
    op = _require("ackKillSwitch")
    req = SCENARIOS["ackKillSwitch"](cworld)
    assert world_call(cworld, op, req, "keys-b").status_code == 404


@pytest.mark.parametrize("op_id", ["openIncident", "actOnIncident"])
def test_out_of_group_engineer_gets_404(cworld: ContractWorld, op_id: str) -> None:
    op = _require(op_id)
    req = SCENARIOS[op_id](cworld)  # scenario agents have no group: outside the engineer's
    assert world_call(cworld, op, req, "engineer").status_code == 404


def test_in_group_engineer_may_act(cworld: ContractWorld) -> None:
    op = _require("openIncident")
    agent = s_agent(cworld, group=cworld.a.groups["g1"])
    body = {"agent_id": str(agent), "action": "degrade", "reason": S_REASON}
    resp = world_call(cworld, op, Req("/incidents", body), "engineer")
    assert resp.status_code == 201, resp.text


# --- alerts ------------------------------------------------------------------------------------


def test_out_of_group_engineer_cannot_act_on_an_alert(cworld: ContractWorld) -> None:
    op = _require("actOnAlert")
    req = SCENARIOS["actOnAlert"](cworld)  # the alert's agent has no group
    resp = world_call(cworld, op, req, "engineer")
    assert resp.status_code == 404, resp.text


def test_provider_alerts_are_out_of_reach_of_a_group_limited_engineer(
    cworld: ContractWorld,
) -> None:
    op = _require("actOnAlert")
    alert = alert_row(cworld, provider_id=provider(cworld))
    resp = world_call(cworld, op, Req(f"/alerts/{alert}/actions", {"action": "ack"}), "engineer")
    assert resp.status_code == 404, resp.text


def test_in_group_engineer_may_act_on_an_alert(cworld: ContractWorld) -> None:
    op = _require("actOnAlert")
    alert = alert_row(cworld, agent_id=s_agent(cworld, group=cworld.a.groups["g1"]))
    resp = world_call(cworld, op, Req(f"/alerts/{alert}/actions", {"action": "ack"}), "engineer")
    assert resp.status_code == 200, resp.text


# --- governance --------------------------------------------------------------------------------


def test_out_of_group_engineer_cannot_read_an_agent_audit_row(cworld: ContractWorld) -> None:
    op = _require("getAuditEvent")
    req = SCENARIOS["getAuditEvent"](cworld)  # a row about a fresh, ungrouped agent
    assert req.agent_id is not None
    resp = world_call(cworld, op, req, "engineer")
    assert resp.status_code == 404, resp.text
    listed = world_call(
        cworld,
        operation("listAuditEvents"),
        Req("/audit/events", params={"resource_id": req.agent_id}),
        "engineer",
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["data"] == []


def test_engineer_reads_audit_rows_of_agents_in_its_group(cworld: ContractWorld) -> None:
    op = _require("getAuditEvent")
    created = agent(cworld, agent_group_id=str(cworld.a.groups["g1"]))
    seq = agent_audit_seq(cworld, created["id"])
    resp = world_call(cworld, op, Req(f"/audit/events/{seq}"), "engineer")
    assert resp.status_code == 200, resp.text
    listed = world_call(cworld, operation("listAuditEvents"), Req("/audit/events"), "engineer")
    assert listed.status_code == 200, listed.text
    rows = listed.json()["data"]
    assert rows and {r["resource_type"] for r in rows} == {"agent"}


def test_requester_cannot_approve_their_own_erasure_request(cworld: ContractWorld) -> None:
    op = _require("actOnErasureRequest")
    request_id = erasure_request(cworld)  # filed by the owner
    body = {"action": "approve", "reason": REASON}
    resp = world_call(cworld, op, Req(f"/erasure-requests/{request_id}/actions", body), "owner")
    assert resp.status_code == 409, resp.text
    assert _type(resp).endswith("/self_approval")


def test_only_an_owner_files_a_tenant_scope_erasure(cworld: ContractWorld) -> None:
    op = _require("requestErasure")
    body = {"scope_kind": "tenant", "legal_basis": "tenant_offboarding", "reason": REASON}
    resp = world_call(cworld, op, Req("/erasure-requests", body), "admin")
    assert resp.status_code == 403, resp.text
    assert _type(resp).endswith("/forbidden")


def test_the_worlds_audit_chain_verifies_against_its_signed_anchors(cworld: ContractWorld) -> None:
    """The generated audit case accepts ``audit.verify_failed`` as a declared row; this pins
    that tenant A's real chain (every scenario's writes so far) walks clean and the anchors'
    signatures check out."""
    op = _require("verifyAuditChain")
    anchor(cworld)
    resp = world_call(cworld, op, Req("/audit/verifications", {}), "auditor")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True and body["first_break_seq"] is None, body
    assert body["anchors_checked"] >= 1 and body["rows"] >= 1, body


# --- INT-3: pre-emptive breaker clear (B19) ------------------------------------------------------


def test_out_of_group_engineer_cannot_clear_a_breaker(cworld: ContractWorld) -> None:
    op = _require("clearPreemptiveBreaker")
    resp = world_call(cworld, op, clear_req(tripped_agent(cworld)), "engineer")
    assert resp.status_code == 404, resp.text


def test_in_group_engineer_needs_a_tenant_role_to_clear(cworld: ContractWorld) -> None:
    """``tenant_role``: a group-limited ``routing:override`` grant never clears the breaker."""
    op = _require("clearPreemptiveBreaker")
    agent = tripped_agent(cworld, group=cworld.a.groups["g1"])
    resp = world_call(cworld, op, clear_req(agent), "engineer")
    assert resp.status_code == 403 and _type(resp).endswith("forbidden"), resp.text
    still = cworld.admin.fetchval(
        "SELECT preemptive_breaker_tripped_at IS NOT NULL FROM sibyl.agent"
        " WHERE tenant_id = $1 AND id = $2",
        cworld.a.id,
        agent,
    )
    assert still


def test_clearing_an_untripped_breaker_is_409(cworld: ContractWorld) -> None:
    op = _require("clearPreemptiveBreaker")
    resp = world_call(cworld, op, clear_req(s_agent(cworld)), "owner")
    assert resp.status_code == 409 and _type(resp).endswith("invalid_transition"), resp.text
