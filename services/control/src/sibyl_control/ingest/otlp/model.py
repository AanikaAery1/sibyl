"""Decoded OTLP model shared by the protobuf and JSON decoders.

Attribute values are plain Python: ``str``, ``bool``, ``int``, ``float``, ``list``, ``dict``
(kvlist), ``AnyBytes`` (bytes_value) or ``None`` (empty AnyValue). Ids are raw bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Attributes = dict[str, Any]

STATUS_UNSET, STATUS_OK, STATUS_ERROR = 0, 1, 2


@dataclass(frozen=True, slots=True)
class AnyBytes:
    data: bytes


@dataclass(frozen=True, slots=True)
class Scope:
    name: str = ""
    version: str = ""
    attributes: Attributes = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SpanEvent:
    name: str
    time_ns: int
    attributes: Attributes


@dataclass(frozen=True, slots=True)
class Span:
    trace_id: bytes
    span_id: bytes
    parent_span_id: bytes
    name: str
    kind: int
    start_ns: int
    end_ns: int
    attributes: Attributes
    status_code: int
    status_message: str
    events: tuple[SpanEvent, ...]


@dataclass(frozen=True, slots=True)
class ScopeSpans:
    scope: Scope
    spans: tuple[Span, ...]
    schema_url: str


@dataclass(frozen=True, slots=True)
class ResourceSpans:
    resource: Attributes
    scopes: tuple[ScopeSpans, ...]
    schema_url: str


@dataclass(frozen=True, slots=True)
class LogRecord:
    time_ns: int
    observed_ns: int
    severity_number: int
    severity_text: str
    body: Any
    attributes: Attributes
    event_name: str
    trace_id: bytes
    span_id: bytes


@dataclass(frozen=True, slots=True)
class ScopeLogs:
    scope: Scope
    records: tuple[LogRecord, ...]
    schema_url: str


@dataclass(frozen=True, slots=True)
class ResourceLogs:
    resource: Attributes
    scopes: tuple[ScopeLogs, ...]
    schema_url: str


@dataclass(frozen=True, slots=True)
class TraceBatch:
    resources: tuple[ResourceSpans, ...]
    warnings: tuple[str, ...] = ()

    @property
    def span_count(self) -> int:
        return sum(len(ss.spans) for rs in self.resources for ss in rs.scopes)


@dataclass(frozen=True, slots=True)
class LogBatch:
    resources: tuple[ResourceLogs, ...]
    warnings: tuple[str, ...] = ()

    @property
    def record_count(self) -> int:
        return sum(len(sl.records) for rl in self.resources for sl in rl.scopes)
