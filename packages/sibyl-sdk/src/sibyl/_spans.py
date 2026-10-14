"""Minimal span model and context propagation.

The SDK ships its own span model plus an OTLP/JSON encoder instead of `opentelemetry-sdk`
so the only runtime dependencies stay `sibyl-schemas`, `httpx` and `cryptography`. Ending a
span is O(1) on the caller's thread: it is handed to the exporter's ring buffer.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Final

from sibyl._ids import new_span_id, new_trace_id

AttrValue = str | bool | int | float | list[str] | list[int] | list[float] | list[bool]

KIND_INTERNAL: Final = 1
KIND_CLIENT: Final = 3
STATUS_UNSET: Final = 0
STATUS_OK: Final = 1
STATUS_ERROR: Final = 2


@dataclass(frozen=True)
class SpanContext:
    trace_id: str
    span_id: str


_CURRENT: ContextVar[SpanContext | None] = ContextVar("sibyl_current_span", default=None)


def current_context() -> SpanContext | None:
    return _CURRENT.get()


@contextmanager
def use_context(ctx: SpanContext) -> Iterator[None]:
    token = _CURRENT.set(ctx)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def _size(value: object) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, list):
        return sum(_size(item) for item in value)
    return 8


class Span:
    """A mutable span until `end()`; afterwards it belongs to the exporter."""

    __slots__ = (
        "_on_end",
        "approx_bytes",
        "attributes",
        "content",
        "critical",
        "end_ns",
        "kind",
        "name",
        "parent_span_id",
        "span_id",
        "start_ns",
        "status_code",
        "status_message",
        "trace_id",
    )

    def __init__(
        self,
        name: str,
        *,
        kind: int = KIND_INTERNAL,
        parent: SpanContext | None = None,
        critical: bool = False,
        on_end: Callable[[Span], None] | None = None,
        start_ns: int | None = None,
    ) -> None:
        self.name = name
        self.kind = kind
        self.trace_id = parent.trace_id if parent else new_trace_id()
        self.parent_span_id = parent.span_id if parent else None
        self.span_id = new_span_id()
        self.start_ns = start_ns if start_ns is not None else time.time_ns()
        self.end_ns: int | None = None
        self.attributes: dict[str, AttrValue] = {}
        self.status_code = STATUS_UNSET
        self.status_message: str | None = None
        self.critical = critical
        self.content: list[tuple[str, str, Any]] = []
        """Deferred `(attribute, scrub part, value)`: scrubbed on the exporter thread."""
        self.approx_bytes = 128 + len(name)
        self._on_end = on_end

    @property
    def context(self) -> SpanContext:
        return SpanContext(self.trace_id, self.span_id)

    def set(self, key: str, value: Any) -> None:
        if value is None or self.end_ns is not None:
            return
        if isinstance(value, tuple):
            value = list(value)
        self.attributes[key] = value
        self.approx_bytes += len(key) + _size(value)

    def add_content(self, attribute: str, part: str, value: Any) -> None:
        if self.end_ns is None and value is not None:
            self.content.append((attribute, part, value))
            self.approx_bytes += _size(value) if isinstance(value, str) else 256

    def set_many(self, values: dict[str, Any]) -> None:
        for key, value in values.items():
            self.set(key, value)

    def set_error(self, error_type: str, message: str | None = None) -> None:
        self.status_code = STATUS_ERROR
        self.status_message = message[:256] if message else None
        self.set("error.type", error_type)

    def end(self, end_ns: int | None = None) -> None:
        if self.end_ns is not None:
            return
        self.end_ns = end_ns if end_ns is not None else time.time_ns()
        if self.status_code == STATUS_UNSET:
            self.status_code = STATUS_OK
        if self._on_end is not None:
            self._on_end(self)

    @property
    def duration_ms(self) -> float:
        end = self.end_ns if self.end_ns is not None else time.time_ns()
        return max(0.0, (end - self.start_ns) / 1e6)
