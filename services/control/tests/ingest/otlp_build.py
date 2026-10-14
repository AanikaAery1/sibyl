"""Build OTLP/JSON export requests for tests (hex ids, string int64s, as the spec says)."""

from __future__ import annotations

import json
import secrets
import time
from typing import Any


def av(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, list):
        return {"arrayValue": {"values": [av(v) for v in value]}}
    if isinstance(value, dict):
        return {"kvlistValue": {"values": [{"key": k, "value": av(v)} for k, v in value.items()]}}
    return {"stringValue": value}


def kv(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"key": k, "value": av(v)} for k, v in attrs.items()]


def span(
    attrs: dict[str, Any],
    *,
    name: str = "chat",
    trace: str | None = None,
    span_id: str | None = None,
    duration_ms: float = 120.0,
    error: bool = False,
    end_ns: int | None = None,
) -> dict[str, Any]:
    end = end_ns or time.time_ns() - 1_000_000_000
    out: dict[str, Any] = {
        "traceId": trace or secrets.token_hex(16),
        "spanId": span_id or secrets.token_hex(8),
        "name": name,
        "kind": 3,
        "startTimeUnixNano": str(end - int(duration_ms * 1e6)),
        "endTimeUnixNano": str(end),
        "attributes": kv(attrs),
    }
    if error:
        out["status"] = {"code": 2, "message": "boom"}
    return out


def chat_attrs(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "gen_ai.operation.name": "chat",
        "gen_ai.provider.name": "openai",
        "gen_ai.request.model": "gpt-5-mini",
        "gen_ai.response.model": "gpt-5-mini",
        "gen_ai.usage.input_tokens": 1000,
        "gen_ai.usage.output_tokens": 500,
    }
    base.update(extra)
    return base


def traces(
    spans: list[dict[str, Any]], *, resource: dict[str, Any] | None = None, scope: str = "sibyl-sdk"
) -> bytes:
    doc = {
        "resourceSpans": [
            {
                "resource": {"attributes": kv(resource or {"service.name": "svc"})},
                "scopeSpans": [
                    {
                        "scope": {"name": scope, "version": "0.1.0"},
                        "spans": spans,
                        "schemaUrl": "https://opentelemetry.io/schemas/1.37.0",
                    }
                ],
            }
        ]
    }
    return json.dumps(doc).encode()


def logs(records: list[dict[str, Any]], *, resource: dict[str, Any] | None = None) -> bytes:
    doc = {
        "resourceLogs": [
            {
                "resource": {"attributes": kv(resource or {"service.name": "svc"})},
                "scopeLogs": [{"scope": {"name": "sibyl-sdk"}, "logRecords": records}],
            }
        ]
    }
    return json.dumps(doc).encode()


def log_record(event_name: str, attrs: dict[str, Any], *, body: Any = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "timeUnixNano": str(time.time_ns() - 1_000_000_000),
        "eventName": event_name,
        "attributes": kv(attrs),
    }
    if body is not None:
        record["body"] = av(body)
    return record
