"""The normaliser's unit of work: one would-be event from either wire encoding.

Both entry points (OTLP spans/log records and ``/v1/events`` elements) are reduced to a
``Candidate`` holding a wire-shaped ``sibyl-event/1`` dict (no ``observed_at``/``ingest``, no
``payload_inline``) plus an optional decoded ``Content`` body. Everything downstream (identity,
scrub, capture, sealing, derivation, envelope, validation, routing) is shared.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Which attrs key carries the PayloadRef for each event type, and how the body is stored.
PAYLOAD_SLOTS: dict[str, tuple[str, str, str]] = {
    # event type: (attrs key, payload_refs.kind, payload_refs.source_kind)
    "gen_ai.request": ("payload", "span_content", "event"),
    "tool.call": ("payload", "span_content", "event"),
    "checkpoint": ("state_ref", "checkpoint_state", "checkpoint"),
    "handoff.requested": ("packet_ref", "handoff_packet", "packet"),
    "handoff.completed": ("note_ref", "comment", "comment"),
    "handoff.returned": ("note_ref", "comment", "comment"),
    "feedback": ("comment_ref", "comment", "comment"),
}


@dataclass
class Content:
    data: bytes
    content_type: str
    parts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Reject:
    reason: str  # events_rejected.reason
    detail: str | None = None


@dataclass
class Candidate:
    index: int
    event: dict[str, Any] | None
    content: Content | None = None
    agent_ref: str | None = None  # explicit identity claim (span attr / event agent_id)
    agent_via: str = "span_attr"
    env: str | None = None
    trace_hex: str | None = None
    span_hex: str | None = None
    instrumentor: str | None = None
    sdk_version: str | None = None
    reject: Reject | None = None
    warnings: list[str] = field(default_factory=list)
    dead_letter: str | None = None  # raw-only (not an event, not a rejection)
    event_id_hint: str | None = None  # the client's event_id, echoed on a rejection

    def fail(self, reason: str, detail: str | None = None) -> None:
        if self.reject is None:
            self.reject = Reject(reason, detail[:500] if detail else None)

    @property
    def ok(self) -> bool:
        return self.reject is None and self.dead_letter is None and self.event is not None
