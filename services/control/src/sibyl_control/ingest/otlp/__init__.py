"""OTLP/HTTP decoding (protobuf and JSON) and response encoding for the ingest routes."""

from __future__ import annotations

import json

from .context import MAX_ATTRIBUTES, MAX_STRING_CHARS, DecodeContext, OtlpDecodeError, TooManyItems
from .jsonfmt import decode_logs_json, decode_traces_json
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
from .protobuf import decode_logs_pb, decode_traces_pb
from .wire import encode_len, encode_uint

PROTOBUF = "application/x-protobuf"
JSON = "application/json"
DEFAULT_MAX_SPANS = 2000
DEFAULT_MAX_LOG_RECORDS = 1000

__all__ = [
    "JSON",
    "MAX_ATTRIBUTES",
    "MAX_STRING_CHARS",
    "PROTOBUF",
    "AnyBytes",
    "LogBatch",
    "LogRecord",
    "OtlpDecodeError",
    "ResourceLogs",
    "ResourceSpans",
    "Scope",
    "ScopeLogs",
    "ScopeSpans",
    "Span",
    "SpanEvent",
    "TooManyItems",
    "TraceBatch",
    "decode_logs",
    "decode_traces",
    "encode_logs_response",
    "encode_traces_response",
    "media_type",
]


def media_type(content_type: str | None) -> str:
    """``application/x-protobuf`` or ``application/json``; anything else is refused."""
    base = (content_type or "").split(";", 1)[0].strip().lower()
    if base in (PROTOBUF, "application/protobuf"):
        return PROTOBUF
    if base == JSON:
        return JSON
    raise OtlpDecodeError(f"unsupported content type {base or '(none)'!r}")


def decode_traces(
    body: bytes, *, content_type: str | None, max_items: int = DEFAULT_MAX_SPANS
) -> TraceBatch:
    ctx = DecodeContext(max_items)
    if media_type(content_type) == PROTOBUF:
        return decode_traces_pb(body, ctx)
    return decode_traces_json(body, ctx)


def decode_logs(
    body: bytes, *, content_type: str | None, max_items: int = DEFAULT_MAX_LOG_RECORDS
) -> LogBatch:
    ctx = DecodeContext(max_items)
    if media_type(content_type) == PROTOBUF:
        return decode_logs_pb(body, ctx)
    return decode_logs_json(body, ctx)


def _encode_response(count_field: str, rejected: int, message: str, *, protobuf: bool) -> bytes:
    if protobuf:
        if not rejected and not message:
            return b""
        inner = b""
        if rejected:
            inner += encode_uint(1, rejected)
        if message:
            inner += encode_len(2, message.encode("utf-8"))
        return encode_len(1, inner)
    if not rejected and not message:
        return b"{}"
    partial = {count_field: str(rejected), "errorMessage": message}
    return json.dumps({"partialSuccess": partial}, separators=(",", ":")).encode()


def encode_traces_response(rejected: int, message: str, *, protobuf: bool) -> bytes:
    """``ExportTraceServiceResponse``; fully accepted → empty message (OTLP spec)."""
    return _encode_response("rejectedSpans", rejected, message, protobuf=protobuf)


def encode_logs_response(rejected: int, message: str, *, protobuf: bool) -> bytes:
    return _encode_response("rejectedLogRecords", rejected, message, protobuf=protobuf)
