"""`checkpoint()` and `handoff.packet()/request()` (API §8.2, §9).

Checkpoints ride `/v1/events` as `payload_inline` (`application/vnd.sibyl.checkpoint+json`)
in the critical lane; the state is scrubbed and validated against `sibyl-checkpoint/1` on the
exporter thread. Handoff packets are `sibyl_schemas.models.HandoffPacket` instances
(validated on construction) whose free text is scrubbed before it is stored.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import ValidationError
from sibyl_schemas.models import Checkpoint, HandoffPacket
from sibyl_schemas.values import INLINE_STATE_MAX_BYTES, PAYLOAD_INLINE_MAX_BYTES

from sibyl import _state
from sibyl._emit import envelope, scrub_text
from sibyl._ids import NIL_UUID, rfc3339, uuid7
from sibyl._run import AgentRun, current_run
from sibyl._scrub import ScrubContext, redaction_record, to_json
from sibyl._types import FailureMode, SideEffect, Step
from sibyl._version import __version__

log = logging.getLogger("sibyl")
CHECKPOINT_TYPE = "application/vnd.sibyl.checkpoint+json"
HANDOFF_TYPE = "application/vnd.sibyl.handoff+json"
DEFAULT_STATE_SCHEMA = "app:unspecified/v1"
_REASON_MIN, _REASON_MAX = 20, 1000
_ACTION_MIN, _ACTION_MAX = 5, 300


def _step(item: Step | str) -> Step:
    return item if isinstance(item, Step) else Step(item)


def _completed(items: Sequence[Step | str], at: str) -> list[dict[str, Any]]:
    out = []
    for n, raw in enumerate(items):
        step = _step(raw)
        entry: dict[str, Any] = {
            "index": step.index if step.index is not None else n,
            "step": step.step[:128],
            "started_at": at,
            "ended_at": at,
            "assumed": False,
        }
        if step.tool_name:
            entry["tool_name"] = step.tool_name
        if step.output is not None:
            entry["output"] = {"preview": to_json(step.output)[:4096]}
        out.append(entry)
    return out


def _pending(items: Sequence[Step | str], offset: int) -> list[dict[str, Any]]:
    out = []
    for n, raw in enumerate(items):
        step = _step(raw)
        entry: dict[str, Any] = {
            "index": step.index if step.index is not None else offset + n,
            "step": step.step[:128],
        }
        if step.description:
            entry["description"] = step.description[:1000]
        if step.inputs_needed:
            entry["inputs_needed"] = list(step.inputs_needed)
        if step.blocked_on:
            entry["blocked_on"] = step.blocked_on
        out.append(entry)
    return out


def _side_effects(items: Sequence[SideEffect], at: str) -> list[dict[str, Any]]:
    out = []
    for effect in items:
        entry: dict[str, Any] = {"kind": effect.kind, "at": at, "assumed": False}
        if effect.target:
            entry["target"] = effect.target[:256]
        if effect.idempotency_key:
            entry["idempotency_key"] = effect.idempotency_key[:256]
        if effect.reversible is not None:
            entry["reversible"] = effect.reversible
        out.append(entry)
    return out


# ------------------------------------------------------------------ checkpoint


def checkpoint(
    state: Mapping[str, Any] | Any,
    *,
    step: str | None = None,
    step_index: int | None = None,
    completed: Sequence[Step | str] = (),
    pending: Sequence[Step | str] = (),
    side_effects: Sequence[SideEffect] = (),
    state_schema: str | None = None,
    run: AgentRun | None = None,
) -> UUID:
    """Record resumable task state; returns the checkpoint id. Never blocks or raises."""
    checkpoint_id = uuid7()
    client = _state.get()
    run = run or current_run()
    if client is None or run is None:
        _state.warn_once("checkpoint", "checkpoint() outside init()/sibyl.agent() is ignored")
        return checkpoint_id
    run.steps += 1
    run.checkpoint_seq += 1
    at = rfc3339(client.clock.time())
    index = step_index if step_index is not None else max(len(completed), run.checkpoint_seq - 1)
    prev = run.latest_checkpoint["checkpoint_id"] if run.latest_checkpoint else None
    doc: dict[str, Any] = {
        "schema": "sibyl-checkpoint/1",
        "checkpoint_id": str(checkpoint_id),
        "task_id": str(run.task_id),
        "seq": run.checkpoint_seq,
        "step_index": index,
        "created_at": at,
        "state_schema": (state_schema or DEFAULT_STATE_SCHEMA)[:200],
        "completed_steps": _completed(completed, at),
        "pending_steps": _pending(pending, index + 1),
        "side_effects": _side_effects(side_effects, at),
        "provenance": {
            "sdk_version": __version__,
            "trace_id": run.trace_id,
            "span_id": run.span_id or "0" * 16,
        },
    }
    if step:
        doc["step_name"] = step[:128]
    if run.goal:
        doc["goal"] = run.goal[:2000]
    if prev:
        doc["provenance"]["prev_checkpoint_id"] = prev
    run.latest_checkpoint = doc
    mode = client.capture_mode
    raw_state = state

    def build() -> dict[str, Any] | None:
        ctx = ScrubContext(
            part="state", agent_id=client.agent_id, task_id=run.task_id, call_id=None
        )
        scrubbed = client.scrub.run(to_json(raw_state), ctx, mode)
        try:
            inline = json.loads(scrubbed.text) if scrubbed.text is not None else {}
        except ValueError:
            inline = {"value": scrubbed.text}
        if not isinstance(inline, dict):
            inline = {"value": inline}
        shipped = json.dumps(inline, separators=(",", ":"), ensure_ascii=False)
        full = {
            **doc,
            "tenant_id": str(client.tenant_id or NIL_UUID),
            "agent_id": str(client.agent_id or NIL_UUID),
            "state": inline,
            "state_bytes": len(shipped.encode("utf-8")),
            "state_sha256": hashlib.sha256(shipped.encode("utf-8")).hexdigest(),
            "redaction": {
                "capture_mode": scrubbed.mode,
                "profile": redaction_record(scrubbed.secrets_scrubbed, scrubbed.rules),
                "fields_redacted": [] if scrubbed.text is not None else ["state"],
            },
        }
        if full["state_bytes"] <= INLINE_STATE_MAX_BYTES:
            try:
                Checkpoint.model_validate(full)
            except ValidationError as exc:
                log.warning("sibyl: checkpoint dropped (invalid sibyl-checkpoint/1): %s", exc)
                return None
        data = json.dumps(full, separators=(",", ":"), ensure_ascii=False)
        if len(data.encode("utf-8")) > PAYLOAD_INLINE_MAX_BYTES:
            log.warning("sibyl: checkpoint dropped: larger than the 4 MiB inline payload")
            return None
        attrs = {
            "state_bytes": full["state_bytes"],
            "payload_inline": {
                "encoding": "utf8",
                "data": data,
                "content_type": CHECKPOINT_TYPE,
                "parts": ["state"],
            },
        }
        return {
            "attrs": attrs,
            "capture_mode": scrubbed.mode,
            "redaction_profile": redaction_record(scrubbed.secrets_scrubbed, scrubbed.rules),
        }

    attrs: dict[str, Any] = {
        "checkpoint_id": str(checkpoint_id),
        "seq": run.checkpoint_seq,
        "step_index": index,
        "state_bytes": 0,
        "state_schema": doc["state_schema"],
        "completed_count": len(completed),
        "pending_count": len(pending),
        "side_effects_count": len(side_effects),
    }
    if step:
        attrs["step_name"] = step[:128]
    if prev:
        attrs["prev_checkpoint_id"] = prev
    client.emit_event(
        envelope(
            client,
            "checkpoint",
            attrs,
            task_id=str(run.task_id),
            trace_id=run.trace_id,
            span_id=run.span_id,
            deferred=build,
        ),
        critical=True,
    )
    return checkpoint_id


# ------------------------------------------------------------------ handoff


def _fit(text: str, low: int, high: int, filler: str) -> str:
    text = text.strip()
    if len(text) < low:
        text = f"{text} {filler}".strip()
    return text[:high]


class handoff:
    @staticmethod
    def packet(
        *,
        reason: str,
        failure_mode: FailureMode,
        next_action: str,
        goal: str | None = None,
        pending: Sequence[Step | str] | None = None,
        deadline: datetime | None = None,
        run: AgentRun | None = None,
        from_checkpoint: UUID | Literal["latest"] | None = "latest",
    ) -> HandoffPacket:
        """Assemble a `sibyl-handoff/1` packet (validated). Short texts are padded, long ones
        truncated to the schema bounds rather than raising into the app."""
        client = _state.get()
        run = run or current_run()
        now = client.clock.time() if client else datetime.now().timestamp()
        at = rfc3339(now)
        mode = client.capture_mode if client else "full"
        task_id = run.task_id if run else uuid7()
        texts = {
            "reason": reason,
            "next_action": next_action,
            "goal": goal or (run.goal if run else None) or reason,
        }
        secrets, rules = 0, []
        if client is not None:
            for key, value in texts.items():
                scrubbed, found, fired = scrub_text(
                    client, value, "comment", mode="full", task_id=task_id
                )
                texts[key] = scrubbed or ""
                secrets += found
                rules.extend(fired)
        latest = run.latest_checkpoint if run and from_checkpoint is not None else None
        if (
            latest
            and isinstance(from_checkpoint, UUID)
            and (latest["checkpoint_id"] != str(from_checkpoint))
        ):
            latest = None
        fidelity = "checkpoint" if latest else "request_only"
        pending_steps: list[dict[str, Any]] = []
        if fidelity == "checkpoint" and latest is not None:
            pending_steps = (
                _pending(pending, 0) if pending is not None else list(latest["pending_steps"])
            )
        snapshot = client.snapshot if client else None
        body: dict[str, Any] = {
            "schema": "sibyl-handoff/1",
            "packet_id": str(uuid7(now)),
            "tenant_id": str(client.tenant_id or NIL_UUID) if client else NIL_UUID,
            "agent_id": str(client.agent_id or NIL_UUID) if client else NIL_UUID,
            "agent_name": (run.name if run else (client.agent_name() if client else "agent"))[:128],
            "task_id": str(task_id),
            "created_at": at,
            "fidelity": fidelity,
            "goal": _fit(texts["goal"], 1, 2000, "(goal not stated)"),
            "original_input": {},
            "completed_steps": list(latest["completed_steps"]) if latest else [],
            "pending_steps": pending_steps,
            "reason": {
                "plain_language": _fit(
                    texts["reason"],
                    _REASON_MIN,
                    _REASON_MAX,
                    "(reported by the agent through the Sibyl SDK)",
                ),
                "failure_mode": failure_mode,
                "trigger": {"kind": "sdk_explicit"},
            },
            "next_action": _fit(texts["next_action"], _ACTION_MIN, _ACTION_MAX, "(see reason)"),
            "deadline": {
                "at": rfc3339(deadline.timestamp()) if deadline else at,
                "derived_from": "task_deadline" if deadline else "tier_rto",
            },
            "accountability": {
                "owner": "pending",
                "line": "Filled by the control plane from the registry",
            },
            "redaction": {"capture_mode": mode, "profile": redaction_record(secrets, rules)},
            "provenance": {
                "assembled_by": "sdk",
                "sdk_version": __version__,
                "trace_ids": [run.trace_id] if run and run.trace_id else [],
                "policy_version": snapshot.policy_version if snapshot else 0,
            },
        }
        if latest:
            body["side_effects"] = list(latest["side_effects"])
            body["provenance"]["checkpoint_id"] = latest["checkpoint_id"]
            body["provenance"]["checkpoint_seq"] = latest["seq"]
        if run:
            body["sidecar"] = {"model_calls": run.model_calls, "tool_calls": run.tool_calls}
        return HandoffPacket.model_validate(body)

    @staticmethod
    def request(packet: HandoffPacket, *, run: AgentRun | None = None) -> UUID:
        """Emit `handoff.requested(trigger=sdk_explicit, assembled_by=sdk)`; needs
        `handoff:write` (logs once otherwise). Returns the packet id."""
        return request(packet, run=run)


def request(packet: HandoffPacket, *, run: AgentRun | None = None) -> UUID:
    packet_id = UUID(packet.packet_id)
    client = _state.get()
    run = run or current_run()
    if client is None:
        _state.warn_once("handoff", "handoff.request() before init() is ignored")
        return packet_id
    if client.has_scope("handoff:write") is False:
        _state.warn_once("handoff_scope", "API key lacks handoff:write; handoff not sent")
        return packet_id
    data = packet.model_dump_json(by_alias=True, exclude_unset=False)
    attrs: dict[str, Any] = {
        "packet_id": packet.packet_id,
        "trigger": "sdk_explicit",
        "fidelity": packet.fidelity.value,
        "assembled_by": "sdk",
        "failure_mode": packet.reason.failure_mode.value,
        "reason_preview": packet.reason.plain_language[:280],
        "payload_inline": {"encoding": "utf8", "data": data, "content_type": HANDOFF_TYPE},
    }
    seq = getattr(packet.provenance, "checkpoint_seq", None)
    if isinstance(seq, int):
        attrs["checkpoint_seq"] = seq
    client.emit_event(
        envelope(
            client,
            "handoff.requested",
            attrs,
            task_id=packet.task_id,
            trace_id=run.trace_id if run else None,
            span_id=run.span_id if run else None,
        ),
        critical=True,
    )
    return packet_id
