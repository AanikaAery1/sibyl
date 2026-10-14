"""Derive `sibyl-event-wire/1` from `sibyl-event/1`.

The wire variant is what clients POST to `/v1/events` (API §4.1, api/ai-engineer.md §1.7):
the canonical envelope minus the ingest-authored fields (`observed_at`, `ingest`, which a
client must not send), with `attrs.payload_inline` allowed wherever the canonical attrs
carry a `PayloadRef`. Ingest scrubs, encrypts and replaces `payload_inline` with a
`PayloadRef` before the row is written; it never reaches storage.

The committed `sibyl-event-wire-1.json` must equal `build_wire_schema(sibyl-event-1.json)`
(drift test), so the two can never disagree on anything but those rules.
"""

from __future__ import annotations

import copy
from typing import Any, Final

WIRE_ID: Final = "https://sibyl.dev/schemas/sibyl-event-wire/1"
INGEST_AUTHORED: Final = ("observed_at", "ingest")
PAYLOAD_INLINE_MAX_CHARS: Final = 4 * 1024 * 1024
_PAYLOAD_REF: Final = "#/$defs/payload_ref"

PAYLOAD_INLINE_DEF: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["encoding", "data", "content_type"],
    "description": (
        "Wire-only body (≤ 4 MiB). Checkpoints and handoff packets ride here as "
        "application/vnd.sibyl.checkpoint+json / application/vnd.sibyl.handoff+json."
    ),
    "properties": {
        "encoding": {"enum": ["utf8", "base64"], "x-sibyl-enum": "PayloadEncoding"},
        "data": {"type": "string", "maxLength": PAYLOAD_INLINE_MAX_CHARS},
        "content_type": {"type": "string", "minLength": 1, "maxLength": 128},
        "parts": {"type": "array", "items": {"$ref": "#/$defs/payload_part"}},
    },
}


def _references_payload_ref(prop: Any) -> bool:
    return isinstance(prop, dict) and prop.get("$ref") == _PAYLOAD_REF


def build_wire_schema(event_schema: dict[str, Any]) -> dict[str, Any]:
    """Return the wire-variant schema for a `sibyl-event/1` schema document."""
    wire = copy.deepcopy(event_schema)
    wire["$id"] = WIRE_ID
    wire["title"] = "sibyl-event-wire/1 (POST /v1/events element)"
    wire["description"] = (
        "sibyl-event/1 as sent by clients: no observed_at or ingest (ingest-authored), and "
        "attrs.payload_inline allowed where the canonical attrs carry a PayloadRef. "
        "$defs/batch is the request body {schema, events[]}."
    )
    for name in INGEST_AUTHORED:
        wire["properties"].pop(name)
    wire["required"] = [name for name in wire["required"] if name not in INGEST_AUTHORED]

    defs = wire["$defs"]
    parts = defs["payload_ref"]["properties"]["parts"]["items"]
    defs["payload_part"] = copy.deepcopy(parts)
    defs["payload_inline"] = copy.deepcopy(PAYLOAD_INLINE_DEF)
    for name, definition in defs.items():
        if not name.startswith("attrs_"):
            continue
        props = definition.get("properties", {})
        if any(_references_payload_ref(prop) for prop in props.values()):
            props["payload_inline"] = {"$ref": "#/$defs/payload_inline"}

    defs["batch"] = {
        "title": "POST /v1/events body",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema", "events"],
        "properties": {
            "schema": {"const": "sibyl-event/1"},
            "events": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1000,
                "items": {"$ref": "#"},
            },
        },
    }
    return wire
