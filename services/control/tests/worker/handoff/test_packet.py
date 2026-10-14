"""Control-plane packet assembly validates against the frozen ``sibyl-handoff/1`` schema."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sibyl_control.worker.handoff.packet import (
    PacketContext,
    TaskInput,
    build,
    checkpoint_age_p95,
    packet_digest,
)
from sibyl_schemas.jsonschema import iter_errors

FIXTURES = Path(__file__).resolve().parents[5] / "packages/sibyl-schemas/fixtures/checkpoint/valid"
NOW = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
PACKET_ID = UUID("019276a4-0000-7000-8000-000000000201")


def _ctx(**kw) -> PacketContext:
    base = {
        "tenant_id": UUID("0192767f-0000-7000-8000-00000000a001"),
        "agent_id": UUID("0192767f-0000-7000-8000-00000000c010"),
        "agent_name": "quote-assistant",
        "tier": 1,
        "rto_s": 900,
        "failure_mode": "infinite_loop",
        "trigger_kind": "rule",
        "rule_code": "tool_loop",
        "alert_id": None,
        "health_snapshot_id": None,
        "policy_version": 7,
        "transition_id": None,
        "owner": "admin@meridian.example.com",
        "on_call": "operator@meridian.example.com",
        "business_process": "Quote to cash",
        "reason": "Detected by the rules engine.",
    }
    base.update(kw)
    return PacketContext(**base)


def _checkpoint() -> dict:
    doc = json.loads((FIXTURES / "checkpoint_inline_state.json").read_text())
    doc.pop("state", None)
    return doc


def test_checkpoint_fidelity_packet_validates_and_copies_steps() -> None:
    doc = _checkpoint()
    task = TaskInput(
        task_id=UUID(doc["task_id"]),
        checkpoint_id=UUID(doc["checkpoint_id"]),
        checkpoint_seq=doc["seq"],
        checkpoint_at=NOW - timedelta(seconds=42),
        checkpoint_doc=doc,
        capture_mode="full",
    )
    built = build(_ctx(), task, packet_id=PACKET_ID, now=NOW)
    assert built.fidelity == "checkpoint"
    assert iter_errors("sibyl-handoff/1", built.packet) == []
    assert built.packet["goal"] == doc["goal"]
    assert built.packet["pending_steps"] == doc["pending_steps"]
    assert built.packet["provenance"]["checkpoint_age_s"] == 42
    assert built.packet["deadline"]["at"] == "2026-10-11T09:15:00Z"
    assert built.next_action.startswith("Send the drafted email")
    assert built.sha256 == packet_digest(built.packet)
    assert "state" not in json.dumps(built.packet["completed_steps"])


def test_request_only_packet_when_no_checkpoint() -> None:
    task = TaskInput(task_id=UUID("019276a0-9c1d-7e3f-9a52-1b2c3d4e5f60"))
    built = build(_ctx(trigger_kind="operator", rule_code=None), task, packet_id=PACKET_ID, now=NOW)
    assert built.fidelity == "request_only"
    assert built.packet["pending_steps"] == []
    assert built.packet["reason"]["trigger"] == {"kind": "operator"}
    assert iter_errors("sibyl-handoff/1", built.packet) == []


def test_invalid_checkpoint_doc_degrades_to_request_only() -> None:
    doc = _checkpoint()
    doc["completed_steps"] = [{"bogus": True}]
    task = TaskInput(
        task_id=UUID(doc["task_id"]),
        checkpoint_id=UUID(doc["checkpoint_id"]),
        checkpoint_seq=1,
        checkpoint_at=NOW,
        checkpoint_doc=doc,
    )
    built = build(_ctx(), task, packet_id=PACKET_ID, now=NOW)
    assert built.fidelity == "request_only"


def test_original_input_ref_only_for_tenant_blob_keys() -> None:
    ctx = _ctx()
    row = {
        "uri": f"tenant/{ctx.tenant_id}/2026-10-11/span/abc.bin",
        "sha256": b"\x01" * 32,
        "size_bytes": 120,
        "content_type": "application/json",
    }
    task = TaskInput(task_id=UUID("019276a0-9c1d-7e3f-9a52-1b2c3d4e5f60"), first_input=row)
    built = build(ctx, task, packet_id=PACKET_ID, now=NOW)
    assert built.packet["original_input"]["ref"]["ref"].startswith(f"blob://{ctx.tenant_id}/")
    other = TaskInput(task_id=task.task_id, first_input={**row, "uri": "elsewhere/x"})
    assert build(ctx, other, packet_id=PACKET_ID, now=NOW).packet["original_input"] == {}


def test_rpo_p95() -> None:
    tasks = [
        TaskInput(task_id=UUID(int=i), checkpoint_at=NOW - timedelta(seconds=i * 10))
        for i in range(1, 21)
    ]
    assert checkpoint_age_p95(tasks, NOW) == 190
    assert checkpoint_age_p95([TaskInput(task_id=UUID(int=1))], NOW) is None
