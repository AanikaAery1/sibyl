"""Steps 9-10: build the canonical envelope, fit ``attrs``/``ingest`` into their DB budgets,
validate against ``sibyl-event/1`` and produce the ``events`` row (span → row mapping §4.5)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from functools import cache
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter, ValidationError
from sibyl_schemas.jsonschema import load_schema
from sibyl_schemas.models import Event

from ..config import NORMALISER_VERSION, SEMCONV_VERSION, IngestConfig
from .candidate import PAYLOAD_SLOTS
from .fields import parse_ts, rfc3339
from .jsonb_size import jsonb_size
from .scrubbing import rule_ids
from .wire_events import classify_errors

_KEEP_ALWAYS = frozenset(slot for slot, _kind, _src in PAYLOAD_SLOTS.values())
_MAX_STRING = 512


@cache
def event_adapter() -> TypeAdapter[Any]:
    return TypeAdapter(Event)


@cache
def required_attrs(event_type: str) -> frozenset[str]:
    name = {"handoff.completed": "handoff_resolved", "handoff.returned": "handoff_resolved"}.get(
        event_type, event_type.replace(".", "_")
    )
    definition = load_schema("sibyl-event/1")["$defs"].get(f"attrs_{name}", {})
    return frozenset(definition.get("required", ()))


def _size(value: Any) -> int:
    return jsonb_size(value)


def _shorten(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _MAX_STRING:
        return value[: _MAX_STRING - 1] + "…"
    if isinstance(value, dict):
        return {k: _shorten(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shorten(v) for v in value]
    return value


def fit_attrs(
    event_type: str, attrs: dict[str, Any], budget: int
) -> tuple[dict[str, Any], list[str]]:
    """Shrink ``attrs`` to the budget: shorten long strings, then drop the largest optional keys."""
    if _size(attrs) <= budget:
        return attrs, []
    notes = ["attrs over the 4 KB budget: long strings shortened"]
    attrs = _shorten(attrs)
    keep = required_attrs(event_type) | _KEEP_ALWAYS
    while _size(attrs) > budget:
        optional = [k for k in attrs if k not in keep]
        if not optional:
            raise ValueError("attrs exceed 4 KB even without optional members")
        largest = max(optional, key=lambda k: _size(attrs[k]))
        attrs = {k: v for k, v in attrs.items() if k != largest}
        notes.append(f"attrs.{largest} dropped to fit 4 KB")
    return attrs, notes


def ingest_block(
    instrumentor: str | None, sdk_version: str | None, warnings: list[str], budget: int
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "normaliser_version": NORMALISER_VERSION,
        "semconv_version": SEMCONV_VERSION,
    }
    if instrumentor:
        block["instrumentor"] = instrumentor[:120]
    if sdk_version:
        block["sdk_version"] = sdk_version[:40]
    kept: list[str] = []
    for warning in dict.fromkeys(warnings):
        trial = {**block, "warnings": [*kept, warning[:160]]}
        if _size(trial) > budget:
            break
        kept.append(warning[:160])
    if kept:
        block["warnings"] = kept
    return block


def validate_canonical(event: dict[str, Any]) -> tuple[str, str] | None:
    try:
        event_adapter().validate_python(event)
    except ValidationError as exc:
        return classify_errors(exc)
    return None


@dataclass(frozen=True)
class RowContext:
    tenant_id: UUID
    api_key_id: UUID
    observed_at: datetime
    raw_ref_id: UUID | None
    profile_hash: bytes
    cfg: IngestConfig


EVENT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("tenant_id", "uuid"),
    ("event_id", "uuid"),
    ("ts", "timestamptz"),
    ("observed_at", "timestamptz"),
    ("event_type", "text"),
    ("source", "text"),
    ("schema_version", "text"),
    ("agent_id", "uuid"),
    ("agent_version_id", "uuid"),
    ("task_id", "uuid"),
    ("call_id", "uuid"),
    ("trace_id", "uuid"),
    ("span_id", "bytea"),
    ("parent_span_id", "bytea"),
    ("emitter_id", "text"),
    ("seq", "int8"),
    ("provider", "text"),
    ("model", "text"),
    ("response_model", "text"),
    ("status", "text"),
    ("error_type", "text"),
    ("error_class", "text"),
    ("http_status", "int2"),
    ("latency_ms", "int4"),
    ("ttfb_ms", "int4"),
    ("tokens_in", "int4"),
    ("tokens_out", "int4"),
    ("cost_usd", "numeric"),
    ("policy_state", "text"),
    ("policy_version", "int8"),
    ("route_decision", "text"),
    ("capture_mode", "text"),
    ("redaction_profile_hash", "bytea"),
    ("api_key_id", "uuid"),
    ("payload_ref_id", "uuid"),
    ("payload_sha256", "bytea"),
    ("payload_bytes", "int8"),
    ("raw_ref_id", "uuid"),
    ("normaliser_version", "text"),
    ("semconv_version", "text"),
    ("ingest", "text"),
    ("attrs", "text"),
    ("scrub_late_hits", "int4"),
    ("scrub_rules_fired", "text"),  # JSON array text; the insert unpacks it into text[]
)
_EVENT_STATUSES = frozenset({"ok", "error", "handed_off", "cancelled"})


_HASH_KEYS = {"input": "input_sha256", "output": "output_sha256", "system": "system_sha256"}
_HASH_KEYS_BACK = {v: k for k, v in _HASH_KEYS.items()}


def to_row_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    """Storage form of ``attrs``. CONFLICT (raised to the chair): ``sibyl.has_content_key``
    (G0 fix, recursive) refuses the nested keys ``input``/``output`` that ``sibyl-event/1``
    uses in ``content_hashes``; rows store them as ``*_sha256`` and ``from_row_attrs`` inverts."""
    hashes = attrs.get("content_hashes")
    if not isinstance(hashes, dict):
        return attrs
    return {**attrs, "content_hashes": {_HASH_KEYS.get(k, k): v for k, v in hashes.items()}}


def from_row_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    """Inverse of ``to_row_attrs`` for readers that rebuild ``sibyl-event/1`` from rows."""
    hashes = attrs.get("content_hashes")
    if not isinstance(hashes, dict):
        return attrs
    return {**attrs, "content_hashes": {_HASH_KEYS_BACK.get(k, k): v for k, v in hashes.items()}}


def _uuid(value: Any) -> UUID | None:
    return UUID(value) if isinstance(value, str) else None


def _int(value: Any) -> int | None:
    return round(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def event_row(
    event: dict[str, Any],
    ctx: RowContext,
    *,
    agent_version_id: UUID | None,
    error_class: str | None,
    cost: Decimal | None,
    payload: tuple[UUID, bytes, int] | None,
) -> tuple[Any, ...]:
    attrs = event["attrs"]
    usage = attrs.get("usage") or {}
    status = attrs.get("status")
    if event["type"] == "task.outcome" and attrs.get("outcome") == "handed_off":
        status = "handed_off"
    route = attrs.get("route") or {}
    policy = event["policy_state"]
    return (
        ctx.tenant_id,
        UUID(event["event_id"]),
        parse_ts(event["ts"]),
        ctx.observed_at,
        event["type"],
        event["source"],
        event["schema"],
        _uuid(event.get("agent_id")),
        agent_version_id,
        _uuid(event.get("task_id")),
        _uuid(event.get("call_id")),
        UUID(hex=event["trace_id"]) if event.get("trace_id") else None,
        bytes.fromhex(event["span_id"]) if event.get("span_id") else None,
        bytes.fromhex(event["parent_span_id"]) if event.get("parent_span_id") else None,
        event["emitter_id"],
        event["seq"],
        attrs.get("provider"),
        attrs.get("request_model"),
        attrs.get("response_model"),
        status if status in _EVENT_STATUSES else None,
        attrs.get("error_type"),
        error_class,
        attrs.get("http_status"),
        _int(attrs.get("latency_ms", attrs.get("duration_ms"))),
        _int(attrs.get("ttfb_ms")),
        usage.get("input_tokens"),
        usage.get("output_tokens"),
        cost,
        policy["state"],
        policy.get("policy_version"),
        route.get("decision"),
        event["capture_mode"],
        ctx.profile_hash,
        ctx.api_key_id,
        payload[0] if payload else None,
        payload[1] if payload else None,
        payload[2] if payload else None,
        ctx.raw_ref_id,
        NORMALISER_VERSION,
        (event.get("ingest") or {}).get("semconv_version", SEMCONV_VERSION),
        json.dumps(event.get("ingest") or {}, ensure_ascii=False, separators=(",", ":")),
        json.dumps(to_row_attrs(attrs), ensure_ascii=False, separators=(",", ":")),
        *scrub_columns(event.get("redaction_profile")),
    )


def scrub_columns(profile: Any) -> tuple[int, str]:
    """``events.scrub_late_hits`` (ingest's own hits, 0 when it found none) and
    ``events.scrub_rules_fired`` (as JSON array text) from the canonical redaction record."""
    record = profile if isinstance(profile, dict) else {}
    late = record.get("late_hits")
    late_hits = late if isinstance(late, int) and not isinstance(late, bool) and late > 0 else 0
    rules = record.get("rules_fired")
    return late_hits, json.dumps(rule_ids(rules if isinstance(rules, list) else None))


def stamp(event: dict[str, Any], observed_at: datetime, block: dict[str, Any]) -> dict[str, Any]:
    return {**event, "observed_at": rfc3339(observed_at), "ingest": block}
