"""``ExportTraceServiceRequest`` / ``ExportLogsServiceRequest`` from protobuf bytes.

Field numbers follow opentelemetry-proto v1 (trace.proto, logs.proto, common.proto,
resource.proto). Unknown fields are skipped, so newer senders stay compatible.
"""

from __future__ import annotations

from typing import Any

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
from .wire import (
    FIXED64,
    LEN,
    VARINT,
    WireError,
    as_int64,
    double,
    expect,
    fields,
    fixed64,
    text,
)

Buf = memoryview


def _any_value(ctx: DecodeContext, buf: Buf, start: int, end: int, depth: int) -> Any:
    ctx.check_depth(depth)
    value: Any = None
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, LEN, "string_value")
            value = ctx.string(text(buf, a, b))
        elif number == 2:
            expect(wt, VARINT, "bool_value")
            value = bool(a)
        elif number == 3:
            expect(wt, VARINT, "int_value")
            value = as_int64(a)
        elif number == 4:
            expect(wt, FIXED64, "double_value")
            value = double(buf, a)
        elif number == 5:
            expect(wt, LEN, "array_value")
            value = [
                _any_value(ctx, buf, x, y, depth + 1)
                for n, w, x, y in fields(buf, a, b)
                if n == 1 and _is_len(w)
            ]
        elif number == 6:
            expect(wt, LEN, "kvlist_value")
            value = dict(_key_values(ctx, buf, a, b, 1, depth + 1))
        elif number == 7:
            expect(wt, LEN, "bytes_value")
            value = AnyBytes(bytes(buf[a:b]))
    return value


def _is_len(wire_type: int) -> bool:
    expect(wire_type, LEN, "repeated message")
    return True


def _key_value(ctx: DecodeContext, buf: Buf, start: int, end: int, depth: int) -> tuple[str, Any]:
    key, value = "", None
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, LEN, "KeyValue.key")
            key = text(buf, a, b)
        elif number == 2:
            expect(wt, LEN, "KeyValue.value")
            value = _any_value(ctx, buf, a, b, depth)
    return key, value


def _key_values(
    ctx: DecodeContext, buf: Buf, start: int, end: int, field_no: int, depth: int
) -> list[tuple[str, Any]]:
    return [
        _key_value(ctx, buf, a, b, depth)
        for n, wt, a, b in fields(buf, start, end)
        if n == field_no and _is_len(wt)
    ]


def _attributes(
    ctx: DecodeContext, buf: Buf, start: int, end: int, field_no: int
) -> dict[str, Any]:
    return ctx.attributes(_key_values(ctx, buf, start, end, field_no, 1))


def _resource(ctx: DecodeContext, buf: Buf, start: int, end: int) -> dict[str, Any]:
    return _attributes(ctx, buf, start, end, 1)


def _scope(ctx: DecodeContext, buf: Buf, start: int, end: int) -> Scope:
    name = version = ""
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, LEN, "scope.name")
            name = text(buf, a, b)
        elif number == 2:
            expect(wt, LEN, "scope.version")
            version = text(buf, a, b)
    return Scope(name, version, _attributes(ctx, buf, start, end, 3))


def _status(buf: Buf, start: int, end: int) -> tuple[int, str]:
    code, message = 0, ""
    for number, wt, a, b in fields(buf, start, end):
        if number == 2:
            expect(wt, LEN, "status.message")
            message = text(buf, a, b)
        elif number == 3:
            expect(wt, VARINT, "status.code")
            code = a
    return code, message


def _event(ctx: DecodeContext, buf: Buf, start: int, end: int) -> SpanEvent:
    name, time_ns = "", 0
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, FIXED64, "event.time")
            time_ns = fixed64(buf, a)
        elif number == 2:
            expect(wt, LEN, "event.name")
            name = text(buf, a, b)
    return SpanEvent(name, time_ns, _attributes(ctx, buf, start, end, 3))


def _span(ctx: DecodeContext, buf: Buf, start: int, end: int) -> Span:
    ctx.count_item()
    ids = {1: b"", 2: b"", 4: b""}
    name, kind, start_ns, end_ns = "", 0, 0, 0
    status = (0, "")
    events: list[SpanEvent] = []
    for number, wt, a, b in fields(buf, start, end):
        if number in ids:
            expect(wt, LEN, "span id")
            ids[number] = bytes(buf[a:b])
        elif number == 5:
            expect(wt, LEN, "span.name")
            name = text(buf, a, b)
        elif number == 6:
            expect(wt, VARINT, "span.kind")
            kind = a
        elif number in (7, 8):
            expect(wt, FIXED64, "span time")
            if number == 7:
                start_ns = fixed64(buf, a)
            else:
                end_ns = fixed64(buf, a)
        elif number == 11:
            expect(wt, LEN, "span.event")
            events.append(_event(ctx, buf, a, b))
        elif number == 15:
            expect(wt, LEN, "span.status")
            status = _status(buf, a, b)
    attrs = _attributes(ctx, buf, start, end, 9)
    return Span(ids[1], ids[2], ids[4], name, kind, start_ns, end_ns, attrs, *status, tuple(events))


def _scope_spans(ctx: DecodeContext, buf: Buf, start: int, end: int) -> ScopeSpans:
    scope, spans, schema_url = Scope(), [], ""
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, LEN, "scope")
            scope = _scope(ctx, buf, a, b)
        elif number == 2:
            expect(wt, LEN, "span")
            spans.append(_span(ctx, buf, a, b))
        elif number == 3:
            expect(wt, LEN, "schema_url")
            schema_url = text(buf, a, b)
    return ScopeSpans(scope, tuple(spans), schema_url)


def _resource_spans(ctx: DecodeContext, buf: Buf, start: int, end: int) -> ResourceSpans:
    resource: dict[str, Any] = {}
    scopes: list[ScopeSpans] = []
    schema_url = ""
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, LEN, "resource")
            resource = _resource(ctx, buf, a, b)
        elif number == 2:
            expect(wt, LEN, "scope_spans")
            scopes.append(_scope_spans(ctx, buf, a, b))
        elif number == 3:
            expect(wt, LEN, "schema_url")
            schema_url = text(buf, a, b)
    return ResourceSpans(resource, tuple(scopes), schema_url)


def decode_traces_pb(body: bytes, ctx: DecodeContext) -> TraceBatch:
    buf = memoryview(body)
    try:
        resources = tuple(
            _resource_spans(ctx, buf, a, b)
            for n, wt, a, b in fields(buf, 0, len(buf))
            if n == 1 and _is_len(wt)
        )
    except WireError as exc:
        raise OtlpDecodeError(f"malformed OTLP protobuf: {exc}") from None
    return TraceBatch(resources, ctx.warnings())


def _log_record(ctx: DecodeContext, buf: Buf, start: int, end: int) -> LogRecord:
    ctx.count_item()
    time_ns = observed_ns = severity = 0
    severity_text = event_name = ""
    body: Any = None
    ids = {9: b"", 10: b""}
    for number, wt, a, b in fields(buf, start, end):
        if number in (1, 11):
            expect(wt, FIXED64, "log time")
            if number == 1:
                time_ns = fixed64(buf, a)
            else:
                observed_ns = fixed64(buf, a)
        elif number == 2:
            expect(wt, VARINT, "severity_number")
            severity = a
        elif number == 3:
            expect(wt, LEN, "severity_text")
            severity_text = text(buf, a, b)
        elif number == 5:
            expect(wt, LEN, "body")
            body = _any_value(ctx, buf, a, b, 1)
        elif number in ids:
            expect(wt, LEN, "log id")
            ids[number] = bytes(buf[a:b])
        elif number == 12:
            expect(wt, LEN, "event_name")
            event_name = text(buf, a, b)
    attrs = _attributes(ctx, buf, start, end, 6)
    return LogRecord(
        time_ns, observed_ns, severity, severity_text, body, attrs, event_name, ids[9], ids[10]
    )


def _scope_logs(ctx: DecodeContext, buf: Buf, start: int, end: int) -> ScopeLogs:
    scope, records, schema_url = Scope(), [], ""
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, LEN, "scope")
            scope = _scope(ctx, buf, a, b)
        elif number == 2:
            expect(wt, LEN, "log_record")
            records.append(_log_record(ctx, buf, a, b))
        elif number == 3:
            expect(wt, LEN, "schema_url")
            schema_url = text(buf, a, b)
    return ScopeLogs(scope, tuple(records), schema_url)


def _resource_logs(ctx: DecodeContext, buf: Buf, start: int, end: int) -> ResourceLogs:
    resource: dict[str, Any] = {}
    scopes: list[ScopeLogs] = []
    schema_url = ""
    for number, wt, a, b in fields(buf, start, end):
        if number == 1:
            expect(wt, LEN, "resource")
            resource = _resource(ctx, buf, a, b)
        elif number == 2:
            expect(wt, LEN, "scope_logs")
            scopes.append(_scope_logs(ctx, buf, a, b))
        elif number == 3:
            expect(wt, LEN, "schema_url")
            schema_url = text(buf, a, b)
    return ResourceLogs(resource, tuple(scopes), schema_url)


def decode_logs_pb(body: bytes, ctx: DecodeContext) -> LogBatch:
    buf = memoryview(body)
    try:
        resources = tuple(
            _resource_logs(ctx, buf, a, b)
            for n, wt, a, b in fields(buf, 0, len(buf))
            if n == 1 and _is_len(wt)
        )
    except WireError as exc:
        raise OtlpDecodeError(f"malformed OTLP protobuf: {exc}") from None
    return LogBatch(resources, ctx.warnings())
