"""OTLP log records → candidates. Only four ``event.name``s are accepted (API.md §4.1):

* ``gen_ai.client.inference.operation.details`` (semconv 1.37) and the legacy
  ``gen_ai.content.prompt`` / ``gen_ai.content.completion`` (warned) become ``gen_ai.request``
  contributions when they carry the call's GenAI attributes; otherwise they are raw-only.
* ``sibyl.sdk.buffer`` opens an ``observation.gap``; ``sibyl.sdk.replay`` closes one.

Every other record (free-text logs included) is raw-only ``dead_letter``, never a rejection.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ..ids import deterministic_uuid7
from ..otlp.model import LogRecord, Scope, Span
from .candidate import Candidate
from .fields import as_int, as_str, as_uuid, json_value, rfc3339_ns
from .semconv import span_candidate

CONTENT_EVENTS = (
    "gen_ai.client.inference.operation.details",
    "gen_ai.content.prompt",
    "gen_ai.content.completion",
)
GAP_EVENTS = ("sibyl.sdk.buffer", "sibyl.sdk.replay")
ACCEPTED_EVENT_NAMES = CONTENT_EVENTS + GAP_EVENTS


def event_name(record: LogRecord) -> str:
    return record.event_name or as_str(record.attributes.get("event.name")) or ""


def _content_candidate(
    index: int,
    tenant_id: UUID,
    record: LogRecord,
    name: str,
    scope: Scope,
    resource: dict[str, Any],
) -> Candidate:
    attrs = dict(record.attributes)
    if name != CONTENT_EVENTS[0]:
        key = "gen_ai.input.messages" if name.endswith("prompt") else "gen_ai.output.messages"
        attrs.setdefault(
            key, record.body if isinstance(record.body, str) else json_value(record.body)
        )
    ts = record.time_ns or record.observed_ns
    latency_ns = int((as_int(attrs.get("sibyl.latency_ms"), minimum=0) or 0) * 1_000_000)
    pseudo = Span(
        record.trace_id, record.span_id, b"", name, 0, ts - latency_ns, ts, attrs, 0, "", ()
    )
    cand = span_candidate(index, tenant_id, pseudo, scope, resource, "")
    if cand.dead_letter is not None or (cand.reject and cand.reject.reason == "missing_required"):
        out = Candidate(
            index=index, event=None, trace_hex=record.trace_id.hex(), span_hex=record.span_id.hex()
        )
        out.dead_letter = f"{name} without the call's GenAI attributes"
        return out
    if name != CONTENT_EVENTS[0]:
        cand.warnings.append(f"legacy log event {name} accepted")
    if not latency_ns:
        cand.warnings.append("content log event has no latency; latency_ms recorded as 0")
    return cand


def _gap_candidate(
    index: int, tenant_id: UUID, record: LogRecord, name: str, resource: dict[str, Any]
) -> Candidate:
    attrs = record.attributes
    ts = record.time_ns or record.observed_ns
    emitter = (
        as_str(attrs.get("sibyl.emitter_id"))
        or f"otel:{as_str(resource.get('service.name')) or 'unknown'}"
    )
    dropped = as_int(attrs.get("sibyl.sdk.dropped_spans"), minimum=0) or as_int(
        attrs.get("events_dropped"), minimum=0
    )
    replayed = as_int(attrs.get("events_replayed"), minimum=0)
    if name == "sibyl.sdk.buffer":
        gap = {"cause": "buffer_dropped" if dropped else "ingest_backpressure", "status": "open"}
    else:
        gap = {
            "cause": "ingest_backpressure",
            "status": "closed_with_loss" if dropped else "closed",
        }
        gap["gap_end"] = rfc3339_ns(ts)
    gap_start_ns = as_int(attrs.get("sibyl.gap.start_unix_nano"), minimum=1) or ts
    body: dict[str, Any] = {"emitter_id": emitter, "gap_start": rfc3339_ns(gap_start_ns), **gap}
    if dropped is not None:
        body["events_dropped"] = dropped
    if replayed is not None:
        body["events_replayed"] = replayed
    cand = Candidate(
        index=index,
        event=None,
        trace_hex=record.trace_id.hex() or None,
        span_hex=record.span_id.hex() or None,
    )
    cand.env = as_str(resource.get("sibyl.env"))
    cand.agent_ref = as_str(attrs.get("sibyl.agent_id"))
    if not ts:
        cand.fail("missing_required", "missing time_unix_nano")
        return cand
    cand.event = {
        "schema": "sibyl-event/1",
        "event_id": str(deterministic_uuid7(ts // 1_000_000, tenant_id, emitter, name, str(ts))),
        "type": "observation.gap",
        "tenant_id": str(tenant_id),
        "agent_id": None,
        "task_id": as_uuid(attrs.get("sibyl.task_id")),
        "call_id": None,
        "ts": rfc3339_ns(ts),
        "source": "sdk",
        "emitter_id": emitter,
        "seq": as_int(attrs.get("sibyl.seq"), minimum=0) or 0,
        "capture_mode": "metadata",
        "redaction_profile": {
            "id": "secrets_only",
            "version": 1,
            "rules_fired": [],
            "secrets_scrubbed": 0,
        },
        "policy_state": {"state": "not_applicable"},
        "attrs": body,
    }
    if len(record.trace_id) == 16 and any(record.trace_id):
        cand.event["trace_id"] = record.trace_id.hex()
    return cand


def log_candidate(
    index: int, tenant_id: UUID, record: LogRecord, scope: Scope, resource: dict[str, Any]
) -> Candidate:
    name = event_name(record)
    if name in CONTENT_EVENTS:
        return _content_candidate(index, tenant_id, record, name, scope, resource)
    if name in GAP_EVENTS:
        return _gap_candidate(index, tenant_id, record, name, resource)
    cand = Candidate(
        index=index,
        event=None,
        trace_hex=record.trace_id.hex() or None,
        span_hex=record.span_id.hex() or None,
    )
    cand.dead_letter = "event.name not accepted on /v1/otlp/logs"
    return cand
