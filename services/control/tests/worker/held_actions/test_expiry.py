"""Held-action timeouts on PG17: a pending hold past ``hold_timeout_s`` is expired as deny by the
worker (as ``sibyl_worker``), audited and announced; a hold not yet due and a decided hold are
untouched; a human cannot decide it afterwards."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from sibyl_ag_gate import REASON, TRANSFER_POLICY, Gate, make_gate
from sibyl_control.worker import loops
from sibyl_control.worker.held_actions import expiry
from sibyl_lane_s_world import SWorld


@pytest.fixture(scope="module")
def gate(sworld: SWorld) -> Gate:
    return make_gate(sworld.w)


def _hold(gate: Gate, agent: UUID, call_id: str) -> dict[str, Any]:
    resp = gate.post("/held-actions", gate.hold_body(agent, call_id, {"amount": 6000}), "keys")
    assert resp.status_code == 201, resp.text
    held: dict[str, Any] = resp.json()
    return held


def _due(gate: Gate, held_id: str) -> None:
    gate.w.admin.execute(
        "UPDATE sibyl.held_action SET expires_at = now() - interval '1 s' WHERE id = $1",
        UUID(held_id),
    )


def test_a_timed_out_hold_is_denied_and_audited(sworld: SWorld, gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    due, later = _hold(gate, agent, "exp-due"), _hold(gate, agent, "exp-later")
    decided = _hold(gate, agent, "exp-decided")
    deny = gate.post(
        f"/held-actions/{decided['id']}/actions", {"action": "deny", "reason": REASON}, "approver"
    )
    assert deny.status_code == 200
    _due(gate, due["id"])
    head = gate.head()
    out = sworld.run(
        expiry.run_tenant(sworld.worker_db, sworld.env("held_actions:test"), gate.tenant)
    )
    assert [str(e.held_action_id) for e in out] == [due["id"]]
    row = gate.get(f"/held-actions/{due['id']}", "operator").json()
    assert (row["state"], row["decision"], row["resolved_by_timeout"]) == ("expired", "deny", True)
    assert gate.get(f"/held-actions/{later['id']}", "operator").json()["state"] == "pending"
    assert gate.audit_since(head) == ["action.expired"]
    event = gate.w.admin.fetchrow(
        "SELECT topic, payload FROM sibyl.outbox WHERE tenant_id = $1 AND event_type ="
        " 'action.expired' AND aggregate_id = $2",
        gate.tenant,
        UUID(due["id"]),
    )
    assert event["topic"] == "action"
    late = gate.post(
        f"/held-actions/{due['id']}/actions", {"action": "approve", "reason": REASON}, "operator"
    )
    assert late.status_code == 409


def test_a_due_but_unexpired_hold_cannot_be_approved(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    held = _hold(gate, agent, "exp-race")
    _due(gate, held["id"])
    resp = gate.post(
        f"/held-actions/{held['id']}/actions", {"action": "approve", "reason": REASON}, "operator"
    )
    assert resp.status_code == 409  # past its timeout: the default is deny


def test_the_loop_is_registered() -> None:
    spec = next(s for s in loops.LOOPS if s.name == "held_actions")
    assert loops.resolve_tick(spec) is not None and spec.interval_s == 5
