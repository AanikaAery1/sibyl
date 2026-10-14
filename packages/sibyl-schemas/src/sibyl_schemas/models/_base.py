"""Model base classes and constrained scalar types shared by every document model.

Models are strict (no `"1"` → `1` coercion, booleans are not numbers), forbid unknown
keys, are frozen, and use `MISSING` for keys that may be absent but never `null`, so the
model accepts and rejects exactly what the hand-written JSON Schema does. Enum fields are
validated in lax mode so the wire strings map onto the `StrEnum` value sets.

Python-side field names differ from wire names only where the wire name is a keyword or
starts with a digit (`schema` → `schema_`, `from` → `from_`, `15m` → `m15`); both spellings
validate, serialisation uses the wire name.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    Strict,
    StringConstraints,
    WithJsonSchema,
)

from sibyl_schemas._enums import RULE_ID_PATTERN
from sibyl_schemas._formats import (
    FEATURE_SNAPSHOT_REF_PATTERN,
    SHA256_PATTERN,
    SPAN_ID_PATTERN,
    TRACE_ID_PATTERN,
    UUID_PATTERN,
    UUIDV7_PATTERN,
    is_rfc3339,
)

type Lax[T] = Annotated[T, Strict(False)]
"""Enum fields: accept the wire string for a `StrEnum` member under strict models."""

type KeyedMap[K, V] = Annotated[
    dict[K, V], Field(json_schema_extra={"additionalProperties": False})
]
"""Dict with pattern-constrained keys. Pydantic exports `patternProperties`, which alone
would admit non-matching keys; closing `additionalProperties` keeps the exported schema
as strict as validation."""


class WireModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_by_name=True,
        validate_by_alias=True,
        serialize_by_alias=True,
    )


class OpenWireModel(WireModel):
    """For the few objects whose schema leaves `additionalProperties` open."""

    model_config = ConfigDict(extra="allow")


def _rfc3339(value: str) -> str:
    if not is_rfc3339(value):
        raise ValueError("not an RFC 3339 date-time with offset")
    return value


Uuid = Annotated[str, StringConstraints(pattern=UUID_PATTERN)]
UuidV7 = Annotated[str, StringConstraints(pattern=UUIDV7_PATTERN)]
Sha256Hex = Annotated[str, StringConstraints(pattern=SHA256_PATTERN)]
TraceId = Annotated[str, StringConstraints(pattern=TRACE_ID_PATTERN)]
SpanId = Annotated[str, StringConstraints(pattern=SPAN_ID_PATTERN)]
RuleIdStr = Annotated[str, StringConstraints(pattern=RULE_ID_PATTERN)]
FeatureSnapshotRef = Annotated[str, StringConstraints(pattern=FEATURE_SNAPSHOT_REF_PATTERN)]
Timestamp = Annotated[
    str,
    AfterValidator(_rfc3339),
    WithJsonSchema({"type": "string", "format": "date-time"}),
]
NonNegInt = Annotated[int, Field(ge=0)]
PosInt = Annotated[int, Field(ge=1)]
NonNegNum = Annotated[float, Field(ge=0)]
UnitInterval = Annotated[float, Field(ge=0, le=1)]
TierInt = Annotated[int, Field(ge=1, le=3)]


def inline_local_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a pydantic-exported schema with `#/$defs/*` refs inlined.

    Needed when a model's schema is embedded inside another document (conditional
    `if/then` rules), where its own `$defs` would no longer be reachable.
    """
    defs: dict[str, Any] = schema.get("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                target = resolve(defs[ref.removeprefix("#/$defs/")])
                extra = {k: resolve(v) for k, v in node.items() if k != "$ref"}
                return {**target, **extra}
            return {k: resolve(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(item) for item in node]
        return node

    result: dict[str, Any] = resolve(schema)
    return result
