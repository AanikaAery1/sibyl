"""Small helpers for writing JSON Schema / OpenAPI fragments compactly."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Schema = dict[str, Any]


def ref(name: str) -> Schema:
    return {"$ref": f"#/components/schemas/{name}"}


def ro(schema: Schema) -> Schema:
    """Mark a property server-owned (readOnly). ``$ref`` siblings are legal in 3.1."""
    return {**schema, "readOnly": True}


def nullable(schema: Schema) -> Schema:
    if "$ref" in schema:
        return {"oneOf": [schema, {"type": "null"}]}
    kind = schema.get("type", "string")
    kinds = kind if isinstance(kind, list) else [kind]
    return {**schema, "type": [*kinds, "null"]}


def string(**kw: Any) -> Schema:
    return {"type": "string", **kw}


def integer(**kw: Any) -> Schema:
    return {"type": "integer", **kw}


def boolean(**kw: Any) -> Schema:
    return {"type": "boolean", **kw}


def array(items: Schema, **kw: Any) -> Schema:
    return {"type": "array", "items": items, **kw}


def enum(*values: str, **kw: Any) -> Schema:
    return {"type": "string", "enum": list(values), **kw}


def obj(
    props: dict[str, Schema],
    required: tuple[str, ...] | list[str] = (),
    **kw: Any,
) -> Schema:
    """A response/resource object: open to additive fields (API.md §2.7)."""
    out: Schema = {"type": "object", "properties": props}
    if required:
        out["required"] = list(required)
    out.update(kw)
    return out


def body_obj(
    props: dict[str, Schema],
    required: tuple[str, ...] | list[str] = (),
    **kw: Any,
) -> Schema:
    """A request body: closed, unknown fields are a 422."""
    return {**obj(props, required, **kw), "additionalProperties": False}


def free_object(description: str, **kw: Any) -> Schema:
    """An object whose shape is owned by a sibyl-schemas document or is open by design."""
    return {"type": "object", "additionalProperties": True, "description": description, **kw}


UUID = ref("Uuid")
TS = ref("Timestamp")
N_UUID = ref("NullableUuid")
N_TS = ref("NullableTimestamp")
REASON = ref("Reason")


@dataclass(frozen=True)
class Q:
    """A query or header parameter."""

    name: str
    schema: Schema
    required: bool = False
    location: str = "query"
    description: str = ""


@dataclass(frozen=True)
class ActionRule:
    """Per-action authorization and audit for ``POST …/actions`` routes (API.md §6.3)."""

    scope: str
    audit: tuple[str, ...]
    step_up: str | None = None
    rules: tuple[str, ...] = ()
    note: str = ""
    scope_any: tuple[str, ...] = ()


@dataclass(frozen=True)
class Op:
    """One control-plane operation: one row (or one method of one row) of API.md §5."""

    method: str
    path: str
    op_id: str
    module: str
    summary: str
    scope: str
    audit: tuple[str, ...] = ()  # empty => "none"
    scope_any: tuple[str, ...] = ()
    key_scopes: tuple[str, ...] = ()
    key_only: bool = False
    step_up: str | None = None  # "always" | "conditional"
    step_up_note: str = ""
    rules: tuple[str, ...] = ()
    idem: bool = False
    if_match: str | None = None  # "required" | "required_or_star"
    paged: bool = False
    query: tuple[Q, ...] = ()
    body: str | None = None
    body_required: bool = True
    ok: tuple[tuple[int, str | None, str], ...] = ((200, None, "OK"),)
    problems: dict[int, tuple[str, ...]] = field(default_factory=dict)
    audit_when: str = "always"  # always | conditional | worker
    audit_note: str = ""
    per_action: dict[str, ActionRule] | None = None
    rate: str | None = None
    server: str = "api"  # api | ingest | root
    content: str = "application/json"
    etag_out: bool = False
    ok_headers: tuple[tuple[str, str], ...] = ()  # (response header, components/headers name)
    description: str = ""
    page_extra: tuple[tuple[str, Schema], ...] = ()  # extra page-envelope members (paged ops)
