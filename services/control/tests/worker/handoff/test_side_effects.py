"""A-4 (ACTION-GATE §4): recorded side effects that are not idempotent block auto-resume."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sibyl_control.worker.handoff.packet import PacketContext, TaskInput, build
from sibyl_control.worker.handoff.side_effects import (
    HOLD_NEXT_ACTION,
    is_idempotent,
    ledger,
    unsafe_to_resume,
)
from sibyl_schemas.jsonschema import iter_errors

TASK = UUID("019276a4-0000-7000-8000-000000000301")
CHECKPOINT = UUID("019276a4-0000-7000-8000-000000000302")
NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)


def _effect(**kw: object) -> dict[str, object]:
    return {"kind": "payment", "at": "2026-10-11T08:59:00Z", "assumed": False, **kw}


def _task(*effects: dict[str, object], doc: bool = True) -> TaskInput:
    if not doc:
        return TaskInput(task_id=TASK)
    return TaskInput(
        task_id=TASK,
        checkpoint_id=CHECKPOINT,
        checkpoint_seq=3,
        checkpoint_at=NOW,
        checkpoint_doc={"side_effects": list(effects)},
    )


def test_only_an_explicit_idempotent_true_is_idempotent() -> None:
    assert is_idempotent(_effect(idempotent=True))
    assert not is_idempotent(_effect())
    assert not is_idempotent(_effect(idempotent=False))
    assert not is_idempotent(_effect(idempotent="true"))  # truthy is not true
    # An idempotency key alone does not make a replay on another route safe: the new route
    # need not reuse the key.
    assert not is_idempotent(_effect(idempotency_key="pay-42"))


def test_a_task_without_recorded_side_effects_may_resume() -> None:
    assert not unsafe_to_resume(_task(doc=False))
    assert not unsafe_to_resume(_task())
    both = _task(_effect(idempotent=True), _effect(kind="api_call", idempotent=True))
    assert not unsafe_to_resume(both)


def test_any_non_idempotent_side_effect_blocks_resume() -> None:
    assert unsafe_to_resume(_task(_effect(idempotent=True), _effect(kind="message_sent")))
    assert unsafe_to_resume(_task(_effect(kind="unknown", assumed=True)))


def test_malformed_side_effect_entries_fail_closed() -> None:
    task = TaskInput(
        task_id=TASK, checkpoint_id=CHECKPOINT, checkpoint_doc={"side_effects": ["oops", 7]}
    )
    assert unsafe_to_resume(task)
    task = TaskInput(task_id=TASK, checkpoint_id=CHECKPOINT, checkpoint_doc={"side_effects": "x"})
    assert unsafe_to_resume(task)


def test_ledger_lists_every_side_effect_with_its_call_reference() -> None:
    entries = ledger(
        _task(
            _effect(
                target="payments.transfer",
                idempotency_key="pay-42",
                evidence_span_id="00f067aa0ba902b7",
            ),
            _effect(kind="api_call", idempotent=True, reversible=True),
        )
    )
    common = {
        "task_id": str(TASK),
        "checkpoint_id": str(CHECKPOINT),
        "checkpoint_seq": 3,
        "at": "2026-10-11T08:59:00Z",
        "assumed": False,
    }
    assert entries == [
        {
            **common,
            "kind": "payment",
            "idempotent": False,
            "target": "payments.transfer",
            "idempotency_key": "pay-42",
            "evidence_span_id": "00f067aa0ba902b7",
        },
        {**common, "kind": "api_call", "idempotent": True, "reversible": True},
    ]


def test_ledger_entries_are_bounded_and_malformed_entries_are_unknown() -> None:
    entries = ledger(_task(_effect(target="x" * 1000, kind="k" * 500)))
    assert len(entries[0]["target"]) == 256 and len(entries[0]["kind"]) == 64
    bad = TaskInput(task_id=TASK, checkpoint_id=CHECKPOINT, checkpoint_doc={"side_effects": [1]})
    assert ledger(bad)[0]["kind"] == "unknown" and ledger(bad)[0]["idempotent"] is False


def _ctx() -> PacketContext:
    return PacketContext(
        tenant_id=UUID("0192767f-0000-7000-8000-00000000a001"),
        agent_id=UUID("0192767f-0000-7000-8000-00000000c010"),
        agent_name="payments-agent",
        tier=1,
        rto_s=900,
        failure_mode="tool_failure",
        trigger_kind="rule",
        rule_code=None,
        alert_id=None,
        health_snapshot_id=None,
        policy_version=1,
        transition_id=None,
        owner="owner@example.com",
        on_call=None,
        business_process=None,
        reason="Detected by the rules engine.",
    )


def _doc_task(doc: Mapping[str, Any]) -> TaskInput:
    return TaskInput(
        task_id=TASK,
        checkpoint_id=CHECKPOINT,
        checkpoint_seq=1,
        checkpoint_at=NOW,
        checkpoint_doc=doc,
    )


def test_packet_keeps_side_effects_and_their_idempotent_flag() -> None:
    doc = {
        "goal": "Pay invoice 42",
        "completed_steps": [],
        "pending_steps": [{"index": 1, "step": "notify"}],
        "side_effects": [_effect(idempotent=True), _effect(kind="message_sent")],
    }
    built = build(
        _ctx(), _doc_task(doc), packet_id=UUID("019276a4-0000-7000-8000-000000000303"), now=NOW
    )
    assert built.fidelity == "checkpoint"
    assert [e["kind"] for e in built.packet["side_effects"]] == ["payment", "message_sent"]
    assert built.packet["side_effects"][0]["idempotent"] is True  # the schema carries it now
    packet = dict(built.packet)
    packet.pop("summary")
    assert iter_errors("sibyl-handoff/1", packet) == []


def test_held_packet_next_action_warns_about_side_effects() -> None:
    doc = {"side_effects": [_effect()], "pending_steps": [{"index": 1, "step": "notify"}]}
    built = build(
        _ctx(),
        _doc_task(doc),
        packet_id=UUID("019276a4-0000-7000-8000-000000000304"),
        now=NOW,
        side_effect_hold=True,
    )
    assert built.next_action == HOLD_NEXT_ACTION
    assert built.packet["next_action"] == HOLD_NEXT_ACTION
