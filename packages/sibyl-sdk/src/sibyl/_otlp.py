"""OTLP/HTTP JSON encoding of spans and log records (OTLP spec 1.x JSON mapping).

Trace and span ids are lowercase hex, 64-bit integers and nanosecond timestamps are
decimal strings, enum fields are integers, as the OTLP JSON protobuf mapping requires.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sibyl._spans import Span

SEMCONV_VERSION: Final = "1.37.0"
SCHEMA_URL: Final = f"https://opentelemetry.io/schemas/{SEMCONV_VERSION}"
SCOPE_NAME: Final = "sibyl-sdk"
SEVERITY_INFO: Final = 9


@dataclass(frozen=True)
class LogRecord:
    event_name: str
    time_ns: int
    attributes: Mapping[str, Any]
    body: str | None = None
    trace_id: str | None = None
    span_id: str | None = None

    @property
    def approx_bytes(self) -> int:
        return 128 + len(self.event_name) + sum(len(k) + 16 for k in self.attributes)


def any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, (list, tuple)):
        return {"arrayValue": {"values": [any_value(item) for item in value]}}
    return {"stringValue": str(value)}


def key_values(attributes: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"key": key, "value": any_value(value)} for key, value in attributes.items()]


def _scope(version: str) -> dict[str, Any]:
    return {
        "name": SCOPE_NAME,
        "version": version,
        "attributes": key_values(
            {"sibyl.schema.version": "1", "sibyl.semconv.version": SEMCONV_VERSION}
        ),
    }


def encode_span(span: Span) -> dict[str, Any]:
    encoded: dict[str, Any] = {
        "traceId": span.trace_id,
        "spanId": span.span_id,
        "name": span.name,
        "kind": span.kind,
        "startTimeUnixNano": str(span.start_ns),
        "endTimeUnixNano": str(span.end_ns if span.end_ns is not None else span.start_ns),
        "attributes": key_values(span.attributes),
        "status": {"code": span.status_code},
    }
    if span.parent_span_id:
        encoded["parentSpanId"] = span.parent_span_id
    if span.status_message:
        encoded["status"]["message"] = span.status_message
    return encoded


def traces_request(
    spans: Sequence[Span], resource: Mapping[str, Any], version: str
) -> dict[str, Any]:
    """`ExportTraceServiceRequest`; an empty span list is the R28 heartbeat."""
    scope_spans: list[dict[str, Any]] = [
        {
            "scope": _scope(version),
            "schemaUrl": SCHEMA_URL,
            "spans": [encode_span(span) for span in spans],
        }
    ]
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": key_values(resource)},
                "schemaUrl": SCHEMA_URL,
                "scopeSpans": scope_spans if spans else [],
            }
        ]
    }


def encode_log(record: LogRecord) -> dict[str, Any]:
    attributes = {"event.name": record.event_name, **record.attributes}
    encoded: dict[str, Any] = {
        "timeUnixNano": str(record.time_ns),
        "observedTimeUnixNano": str(record.time_ns),
        "severityNumber": SEVERITY_INFO,
        "severityText": "INFO",
        "eventName": record.event_name,
        "attributes": key_values(attributes),
    }
    if record.body is not None:
        encoded["body"] = {"stringValue": record.body}
    if record.trace_id:
        encoded["traceId"] = record.trace_id
    if record.span_id:
        encoded["spanId"] = record.span_id
    return encoded


def logs_request(
    records: Iterable[LogRecord], resource: Mapping[str, Any], version: str
) -> dict[str, Any]:
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": key_values(resource)},
                "schemaUrl": SCHEMA_URL,
                "scopeLogs": [
                    {
                        "scope": _scope(version),
                        "schemaUrl": SCHEMA_URL,
                        "logRecords": [encode_log(record) for record in records],
                    }
                ],
            }
        ]
    }
