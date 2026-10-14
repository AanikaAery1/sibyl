"""``POST /v1/events`` bodies → candidates (``sibyl-event-wire/1``, api/ai-engineer.md §1.7).

The body is parsed with ``parse_json_strict`` (duplicate keys refused); batch-level faults are
problems (400 ``unsupported_schema`` / ``batch_too_large``, 422 ``validation_failed``), while a
bad element is a per-event rejection. ``attrs.payload_inline`` is lifted out into the
candidate's ``Content`` before anything is stored; ``tenant_id`` is overwritten with the key's
tenant (never trusted) and wire-sent ``cost_usd`` on ``gen_ai.request`` is discarded (cost is
computed at ingest).
"""

from __future__ import annotations

import base64
import binascii
from functools import cache
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter, ValidationError
from sibyl_schemas.canonical import CanonicalizationError, parse_json_strict
from sibyl_schemas.models import WireEvent

from ...core.problems import ProblemError
from ..config import EVENT_SCHEMA, IngestConfig
from .candidate import Candidate, Content
from .fields import not_nil


@cache
def wire_adapter() -> TypeAdapter[Any]:
    return TypeAdapter(WireEvent)


def classify_errors(exc: ValidationError) -> tuple[str, str]:
    """Map pydantic errors onto ``events_rejected.reason`` plus a safe detail (no values)."""
    errors = exc.errors(include_url=False, include_input=False)
    first = errors[0]
    kinds = {e["type"] for e in errors}
    if kinds & {"union_tag_invalid", "union_tag_not_found"}:
        reason = "unknown_type"
    elif kinds == {"missing"}:
        reason = "missing_required"
    else:
        reason = "schema_invalid"
    loc = "/".join(str(p) for p in first.get("loc", ())[1:]) or "/"
    return reason, f"{loc}: {first.get('msg', 'invalid')}"[:500]


def parse_batch(body: bytes, declared_schema: str | None, cfg: IngestConfig) -> list[Any]:
    if declared_schema is not None and declared_schema.strip() != EVENT_SCHEMA:
        raise ProblemError(
            "unsupported_schema",
            f"X-Sibyl-Schema must be {EVENT_SCHEMA}",
            extensions={"supported": [EVENT_SCHEMA]},
        )
    try:
        doc = parse_json_strict(body, max_bytes=cfg.max_decoded_bytes, max_depth=64)
    except CanonicalizationError as exc:
        raise ProblemError(
            "validation_failed", f"body is not valid JSON: {str(exc)[:200]}"
        ) from None
    if not isinstance(doc, dict):
        raise ProblemError("validation_failed", "body must be a JSON object")
    if doc.get("schema") != EVENT_SCHEMA:
        raise ProblemError(
            "unsupported_schema",
            f"schema must be {EVENT_SCHEMA}",
            extensions={"supported": [EVENT_SCHEMA]},
        )
    extra = set(doc) - {"schema", "events"}
    events = doc.get("events")
    if extra or not isinstance(events, list) or not events:
        raise ProblemError("validation_failed", "body must be {schema, events[1..1000]}")
    if len(events) > cfg.max_events:
        raise ProblemError("batch_too_large", f"at most {cfg.max_events} events per request")
    return events


def _content(inline: dict[str, Any]) -> Content:
    data = inline["data"]
    if inline["encoding"] == "base64":
        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("attrs/payload_inline/data is not valid base64") from None
    else:
        raw = data.encode("utf-8", errors="surrogatepass")
    return Content(raw, inline["content_type"], tuple(inline.get("parts") or ()))


def event_candidate(index: int, element: Any, tenant_id: UUID) -> Candidate:
    cand = Candidate(index=index, event=None)
    if not isinstance(element, dict):
        cand.fail("schema_invalid", "event must be an object")
        return cand
    event_id = element.get("event_id")
    cand.trace_hex = element.get("trace_id") if isinstance(element.get("trace_id"), str) else None
    try:
        wire_adapter().validate_python(element)
    except ValidationError as exc:
        reason, detail = classify_errors(exc)
        cand.fail(reason, detail)
        cand.event_id_hint = event_id[:64] if isinstance(event_id, str) else None
        return cand
    event = dict(element)
    attrs = dict(event["attrs"])
    inline = attrs.pop("payload_inline", None)
    if event["type"] == "gen_ai.request" and ("cost_usd" in attrs or "cost_source" in attrs):
        attrs.pop("cost_usd", None)
        attrs.pop("cost_source", None)
        cand.warnings.append("wire cost_usd ignored; cost is computed at ingest")
    event["attrs"] = attrs
    if event.get("tenant_id") != str(tenant_id):
        event["tenant_id"] = str(tenant_id)
    if inline is not None:
        try:
            cand.content = _content(inline)
        except ValueError as exc:
            cand.fail("schema_invalid", str(exc))
            return cand
    cand.event = event
    cand.event_id_hint = event["event_id"]
    cand.agent_ref = not_nil(event.get("agent_id"))
    cand.agent_via = "span_attr"
    return cand
