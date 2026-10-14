"""A-4 on PG17: a failover never lets in-flight work with a non-idempotent recorded side effect
continue on the new route by itself; that task goes to the operator queue with its ledger."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.worker.handoff.side_effects import HOLD_NEXT_ACTION
from sibyl_control.worker.saga import runner
from sibyl_lane_s_world import SWorld


def _ready_agent(s: SWorld, *, tier: int = 2) -> dict[str, Any]:
    """An agent with an approved chain whose first step is an alternate model (not humans)."""
    p, p2 = s.provider(), s.provider()
    agent = s.agent(tier=tier, model=s.model(p))
    s.plan(agent)
    s.chain(
        agent,
        [
            {"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)},
            {"kind": "human_queue"},
        ],
    )
    return {"agent": agent}


def _effects(s: SWorld, agent: UUID, task: UUID, effects: list[dict[str, Any]]) -> None:
    s.checkpoint(agent, task, side_effects=effects)


PAYMENT = {
    "kind": "payment",
    "target": "payments.transfer",
    "at": "2026-10-11T08:59:00Z",
    "idempotency_key": "pay-42",
    "assumed": False,
}


def _tick(s: SWorld) -> runner.TenantRun:
    return s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id))


def _handoffs(s: SWorld, saga: Any) -> list[Any]:
    return list(
        s.rows(
            "SELECT * FROM sibyl.handoff_task WHERE tenant_id = $1 AND failover_id = $2",
            s.a.id,
            saga,
        )
    )


def test_non_idempotent_side_effect_is_held_for_the_operator(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    held, safe, plain = uuid4(), uuid4(), uuid4()
    _effects(s, a["agent"], held, [PAYMENT])
    _effects(s, a["agent"], safe, [{**PAYMENT, "kind": "api_call", "idempotent": True}])
    s.checkpoint(a["agent"], plain)
    s.alert(a["agent"])
    run = _tick(s)
    saga = s.saga(run.detected[0])
    assert saga["state"] == "done"
    rs = s.routing(a["agent"])
    assert rs["state"] == "failed_over" and rs["target_kind"] != "human_queue"
    record = s.results(saga["id"])["create_handoff_tasks"]
    assert record["in_flight"] == 3
    assert record["continued_on_new_route"] == 2
    assert record["held_for_operator"] == [str(held)]
    ledger = sorted(record["side_effect_ledger"], key=lambda e: e["idempotent"])
    assert [(e["task_id"], e["kind"], e["idempotent"]) for e in ledger] == [
        (str(held), "payment", False),
        (str(safe), "api_call", True),
    ]
    assert ledger[0]["target"] == "payments.transfer"
    tasks = _handoffs(s, saga["id"])
    assert [t["task_id"] for t in tasks] == [held]
    task = tasks[0]
    assert task["state"] == "queued" and task["fidelity"] == "checkpoint"
    assert task["next_action"] == HOLD_NEXT_ACTION
    packet = task["packet"] if isinstance(task["packet"], dict) else json.loads(task["packet"])
    assert [e["kind"] for e in packet["side_effects"]] == ["payment"]
    assert [str(t) for t in record["created"]] == [str(task["id"])]
    assert "handoff.created" in s.audit_actions(s.a)


def test_idempotent_or_absent_side_effects_continue_on_the_new_route(sworld: SWorld) -> None:
    s = sworld
    a = _ready_agent(s)
    _effects(s, a["agent"], uuid4(), [{**PAYMENT, "idempotent": True}])
    s.checkpoint(a["agent"], uuid4())
    s.alert(a["agent"])
    saga = s.saga(_tick(s).detected[0])
    record = s.results(saga["id"])["create_handoff_tasks"]
    assert record["continued_on_new_route"] == 2
    assert record["held_for_operator"] == [] and record["created"] == []
    assert [e["idempotent"] for e in record["side_effect_ledger"]] == [True]
    assert _handoffs(s, saga["id"]) == []


def test_operator_failover_via_the_api_yields_to_the_worker_to_hold(sworld: SWorld) -> None:
    """The api drives the saga inline but may not build handoff tasks: it yields (202) and the
    worker holds the side-effecting task; nothing continues on the new route meanwhile."""
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(tier=2, model=s.model(p))
    s.plan(agent)
    steps = s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    held = uuid4()
    _effects(s, agent, held, [PAYMENT])
    resp = s.post(
        "owner",
        "/incidents",
        {
            "agent_id": str(agent),
            "action": "failover",
            "target": {"step_id": str(steps["alt_provider"])},
            "reason": "operator failover with a payment in flight",
        },
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    saga_id = body.get("incident_id") or body["id"]
    saga = s.saga(saga_id)
    assert saga["state"] == "running" and saga["step"] == "create_handoff_tasks"
    assert _handoffs(s, saga_id) == []
    _tick(s)
    assert s.saga(saga_id)["state"] == "done"
    assert [t["task_id"] for t in _handoffs(s, saga_id)] == [held]
    assert s.results(saga_id)["create_handoff_tasks"]["continued_on_new_route"] == 0


def test_human_queue_handoff_records_the_ledger_too(sworld: SWorld) -> None:
    s = sworld
    p = s.provider()
    agent = s.agent(tier=1, model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "human_queue"}])
    task = uuid4()
    _effects(s, agent, task, [PAYMENT])
    s.alert(agent, code="tool_loop")
    saga = s.saga(_tick(s).detected[0])
    record = s.results(saga["id"])["create_handoff_tasks"]
    assert record["held_for_operator"] == [str(task)]
    assert [e["kind"] for e in record["side_effect_ledger"]] == ["payment"]
    row = _handoffs(s, saga["id"])[0]
    assert row["next_action"] == HOLD_NEXT_ACTION
