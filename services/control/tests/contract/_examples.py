"""Build minimal valid request instances and concrete paths from the OpenAPI document."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from sibyl_control.api.contract import ContractOperation, load_document

_PATTERN_EXAMPLES = {
    r"^[a-z0-9][a-z0-9-]{1,62}$": "billing-agent",
    r"^[a-z][a-z0-9_]{2,40}$": "custom_rule",
    r"^[a-z][a-z_]{2,40}$": "reads_data",
    r"^[0-9a-f]{64}$": "0" * 64,
    r"^[0-9a-f]{32}$": "0" * 32,
    r"^-?[0-9]+\.[0-9]{4}$": "10.0000",
    "^https://": "https://api.example.com/v1",
    r"^[A-Za-z0-9._:-]{1,160}$": "call_contract-1",  # D48 Action Gate call ids
    r"^[0-9]{1,30}(\.[0-9]{1,18})?$": "1",  # D48 Action Gate counter amounts
}


def _resolve(schema: dict[str, Any]) -> dict[str, Any]:
    doc = load_document()
    while "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        schema = doc["components"]["schemas"][name]
    return schema


def example(schema: dict[str, Any]) -> Any:
    schema = _resolve(schema)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    if "oneOf" in schema:
        return example(schema["oneOf"][0])
    if "allOf" in schema:
        merged: dict[str, Any] = {}
        for part in schema["allOf"]:
            merged.update(example(part))
        return merged
    kind = schema.get("type", "object")
    if isinstance(kind, list):
        kind = next(k for k in kind if k != "null")
    if kind == "object":
        props = schema.get("properties", {})
        out = {name: example(props[name]) for name in schema.get("required", [])}
        if not out and schema.get("minProperties") and props:
            name = next(iter(props))
            out[name] = example(props[name])
        return out
    if kind == "array":
        return [example(schema["items"]) for _ in range(schema.get("minItems", 0))]
    if kind == "integer":
        return schema.get("minimum", 1)
    if kind == "boolean":
        return True
    if kind == "number":
        return 1
    return _string(schema)


def _string(schema: dict[str, Any]) -> str:
    fmt = schema.get("format")
    if fmt == "uuid":
        return str(uuid4())
    if fmt == "date-time":
        return "2026-10-10T09:00:00Z"
    if fmt == "date":
        return "2026-10-10"
    if fmt == "email":
        return "admin@meridian.example"
    if fmt == "uri":
        return "https://api.example.com/v1"
    if "pattern" in schema and schema["pattern"] in _PATTERN_EXAMPLES:
        return _PATTERN_EXAMPLES[schema["pattern"]]
    length = max(schema.get("minLength", 0), 24)
    return ("contract test value " * 8)[:length]


def request_body(op: ContractOperation) -> Any | None:
    if op.request_schema is None:
        return None
    return example({"$ref": f"#/components/schemas/{op.request_schema}"})


def concrete_path(op: ContractOperation) -> str:
    path = op.mount_path
    for param in op.path_params:
        schema = _resolve(param["schema"])
        value = example(schema)
        path = path.replace("{" + param["name"] + "}", str(value))
    return path


def required_query(op: ContractOperation) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for param in op.raw.get("parameters", []):
        if "$ref" in param or param.get("in") != "query" or not param.get("required"):
            continue
        value = example(param["schema"])
        out[param["name"]] = ",".join(map(str, value)) if isinstance(value, list) else value
    if not out.get("ids") and any(p.get("name") == "ids" for p in op.raw.get("parameters", [])):
        out["ids"] = str(uuid4())
    return out
