"""OTLP/JSON (``application/json``) into the shared model.

Follows the OTLP/HTTP JSON encoding: lowerCamelCase keys (snake_case also accepted, as the
protobuf JSON mapping allows), trace/span ids as hex (base64 of the right length is accepted
too, since protobuf's generic JSON printer emits that), 64-bit integers as strings or numbers,
enums as integers. Parsing goes through ``parse_json_strict`` (duplicate keys refused).
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Any

from sibyl_schemas.canonical import CanonicalizationError, parse_json_strict

from .context import DecodeContext, OtlpDecodeError
from .model import (
    AnyBytes,
    LogBatch,
    LogRecord,
    ResourceLogs,
    ResourceSpans,
    Scope,
    ScopeLogs,
    ScopeSpans,
    Span,
    SpanEvent,
    TraceBatch,
)

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 64
_HEX = re.compile(r"^[0-9a-fA-F]*$")
_CAMEL = re.compile(r"_([a-z])")


def _get(obj: Mapping[str, Any], name: str, default: Any = None) -> Any:
    """``name`` is snake_case; the lowerCamelCase spelling wins when both are present."""
    camel = _CAMEL.sub(lambda m: m.group(1).upper(), name)
    if camel in obj:
        return obj[camel]
    return obj.get(name, default)


def _obj(value: Any, what: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise OtlpDecodeError(f"{what} must be an object")
    return value


def _list(value: Any, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise OtlpDecodeError(f"{what} must be an array")
    return value


def _str(value: Any, what: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise OtlpDecodeError(f"{what} must be a string")
    return value


def _int(value: Any, what: str) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise OtlpDecodeError(f"{what} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,20}", value):
        return int(value)
    raise OtlpDecodeError(f"{what} must be an integer")


_SPAN_KINDS = {
    f"SPAN_KIND_{n}": i
    for i, n in enumerate(("UNSPECIFIED", "INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER"))
}
_STATUS_CODES = {"STATUS_CODE_UNSET": 0, "STATUS_CODE_OK": 1, "STATUS_CODE_ERROR": 2}
_SEVERITY_PREFIX = "SEVERITY_NUMBER_"
_SEVERITIES = {"UNSPECIFIED": 0} | {
    f"{level}{suffix}": base + offset
    for base, level in (
        (1, "TRACE"),
        (5, "DEBUG"),
        (9, "INFO"),
        (13, "WARN"),
        (17, "ERROR"),
        (21, "FATAL"),
    )
    for offset, suffix in enumerate(("", "2", "3", "4"))
}


def _enum(value: Any, names: Mapping[str, int], what: str, prefix: str = "") -> int:
    if isinstance(value, str) and not re.fullmatch(r"-?[0-9]+", value):
        key = value.removeprefix(prefix)
        if key not in names:
            raise OtlpDecodeError(f"{what} has unknown value {value[:40]!r}")
        return names[key]
    return _int(value, what)


def _id(value: Any, size: int, what: str) -> bytes:
    raw = _str(value, what)
    if not raw:
        return b""
    if len(raw) == size * 2 and _HEX.match(raw):
        return bytes.fromhex(raw)
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        decoded = b""
    if len(decoded) == size:
        return decoded
    raise OtlpDecodeError(f"{what} must be {size * 2} hex characters")


def _any_value(ctx: DecodeContext, value: Any, depth: int) -> Any:
    ctx.check_depth(depth)
    obj = _obj(value, "AnyValue")
    if "stringValue" in obj or "string_value" in obj:
        return ctx.string(_str(_get(obj, "string_value"), "stringValue"))
    if "boolValue" in obj or "bool_value" in obj:
        flag = _get(obj, "bool_value")
        if not isinstance(flag, bool):
            raise OtlpDecodeError("boolValue must be a boolean")
        return flag
    if "intValue" in obj or "int_value" in obj:
        return _int(_get(obj, "int_value"), "intValue")
    if "doubleValue" in obj or "double_value" in obj:
        number = _get(obj, "double_value")
        if isinstance(number, bool) or not isinstance(number, int | float | str):
            raise OtlpDecodeError("doubleValue must be a number")
        try:
            return float(number)
        except ValueError:
            raise OtlpDecodeError("doubleValue must be a number") from None
    if "arrayValue" in obj or "array_value" in obj:
        values = _list(_get(_obj(_get(obj, "array_value"), "arrayValue"), "values"), "values")
        return [_any_value(ctx, v, depth + 1) for v in values]
    if "kvlistValue" in obj or "kvlist_value" in obj:
        values = _list(_get(_obj(_get(obj, "kvlist_value"), "kvlistValue"), "values"), "values")
        return dict(_key_value(ctx, kv, depth + 1) for kv in values)
    if "bytesValue" in obj or "bytes_value" in obj:
        try:
            return AnyBytes(base64.b64decode(_str(_get(obj, "bytes_value"), "bytesValue")))
        except (binascii.Error, ValueError):
            raise OtlpDecodeError("bytesValue must be base64") from None
    return None


def _key_value(ctx: DecodeContext, kv: Any, depth: int) -> tuple[str, Any]:
    obj = _obj(kv, "KeyValue")
    return _str(obj.get("key"), "key"), _any_value(ctx, obj.get("value"), depth)


def _attributes(ctx: DecodeContext, value: Any) -> dict[str, Any]:
    return ctx.attributes(_key_value(ctx, kv, 1) for kv in _list(value, "attributes"))


def _scope(ctx: DecodeContext, value: Any) -> Scope:
    obj = _obj(value, "scope")
    return Scope(
        _str(obj.get("name"), "scope.name"),
        _str(obj.get("version"), "scope.version"),
        _attributes(ctx, obj.get("attributes")),
    )


def _span(ctx: DecodeContext, value: Any) -> Span:
    ctx.count_item()
    obj = _obj(value, "span")
    status = _obj(obj.get("status"), "status")
    events = tuple(
        SpanEvent(
            _str(_obj(e, "event").get("name"), "event.name"),
            _int(_get(e, "time_unix_nano"), "event.timeUnixNano"),
            _attributes(ctx, e.get("attributes")),
        )
        for e in _list(obj.get("events"), "events")
    )
    return Span(
        _id(_get(obj, "trace_id"), 16, "traceId"),
        _id(_get(obj, "span_id"), 8, "spanId"),
        _id(_get(obj, "parent_span_id"), 8, "parentSpanId"),
        _str(obj.get("name"), "span.name"),
        _enum(obj.get("kind"), _SPAN_KINDS, "span.kind"),
        _int(_get(obj, "start_time_unix_nano"), "startTimeUnixNano"),
        _int(_get(obj, "end_time_unix_nano"), "endTimeUnixNano"),
        _attributes(ctx, obj.get("attributes")),
        _enum(status.get("code"), _STATUS_CODES, "status.code"),
        _str(status.get("message"), "status.message"),
        events,
    )


def _parse(body: bytes) -> Mapping[str, Any]:
    if not body.strip():
        return {}
    try:
        doc = parse_json_strict(body, max_bytes=MAX_JSON_BYTES, max_depth=MAX_JSON_DEPTH)
    except CanonicalizationError as exc:
        if "deep" in str(exc).lower():
            raise OtlpDecodeError("OTLP JSON body nests too deeply") from None
        raise OtlpDecodeError(f"OTLP JSON body is invalid: {exc}") from None
    return _obj(doc, "request")


def decode_traces_json(body: bytes, ctx: DecodeContext) -> TraceBatch:
    doc = _parse(body)
    resources = []
    for rs in _list(_get(doc, "resource_spans"), "resourceSpans"):
        rs_obj = _obj(rs, "resourceSpans[]")
        scopes = tuple(
            ScopeSpans(
                _scope(ctx, ss.get("scope")),
                tuple(_span(ctx, s) for s in _list(ss.get("spans"), "spans")),
                _str(_get(ss, "schema_url"), "schemaUrl"),
            )
            for ss in (
                _obj(x, "scopeSpans[]") for x in _list(_get(rs_obj, "scope_spans"), "scopeSpans")
            )
        )
        resource = _attributes(ctx, _obj(rs_obj.get("resource"), "resource").get("attributes"))
        resources.append(
            ResourceSpans(resource, scopes, _str(_get(rs_obj, "schema_url"), "schemaUrl"))
        )
    return TraceBatch(tuple(resources), ctx.warnings())


def _log_record(ctx: DecodeContext, value: Any) -> LogRecord:
    ctx.count_item()
    obj = _obj(value, "logRecord")
    body = _any_value(ctx, obj.get("body"), 1) if obj.get("body") is not None else None
    return LogRecord(
        _int(_get(obj, "time_unix_nano"), "timeUnixNano"),
        _int(_get(obj, "observed_time_unix_nano"), "observedTimeUnixNano"),
        _enum(_get(obj, "severity_number"), _SEVERITIES, "severityNumber", _SEVERITY_PREFIX),
        _str(_get(obj, "severity_text"), "severityText"),
        body,
        _attributes(ctx, obj.get("attributes")),
        _str(_get(obj, "event_name"), "eventName"),
        _id(_get(obj, "trace_id"), 16, "traceId"),
        _id(_get(obj, "span_id"), 8, "spanId"),
    )


def decode_logs_json(body: bytes, ctx: DecodeContext) -> LogBatch:
    doc = _parse(body)
    resources = []
    for rl in _list(_get(doc, "resource_logs"), "resourceLogs"):
        rl_obj = _obj(rl, "resourceLogs[]")
        scopes = tuple(
            ScopeLogs(
                _scope(ctx, sl.get("scope")),
                tuple(_log_record(ctx, r) for r in _list(_get(sl, "log_records"), "logRecords")),
                _str(_get(sl, "schema_url"), "schemaUrl"),
            )
            for sl in (
                _obj(x, "scopeLogs[]") for x in _list(_get(rl_obj, "scope_logs"), "scopeLogs")
            )
        )
        resource = _attributes(ctx, _obj(rl_obj.get("resource"), "resource").get("attributes"))
        resources.append(
            ResourceLogs(resource, scopes, _str(_get(rl_obj, "schema_url"), "schemaUrl"))
        )
    return LogBatch(tuple(resources), ctx.warnings())
