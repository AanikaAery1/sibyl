"""Exporter building blocks: queued items, drop-oldest ring lanes, Retry-After parsing."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Final, Literal

from sibyl._otlp import LogRecord
from sibyl._spans import Span

ItemKind = Literal["span", "event", "log"]
MAX_RETRY_AFTER_S: Final = 3600.0


@dataclass(frozen=True)
class QueuedItem:
    kind: ItemKind
    payload: Span | LogRecord | dict[str, Any]
    size: int


class Lane:
    """Bounded FIFO by item count and bytes; overflow evicts the oldest items."""

    def __init__(self, max_items: int, max_bytes: int) -> None:
        self._items: deque[QueuedItem] = deque()
        self._bytes = 0
        self.max_items = max_items
        self.max_bytes = max_bytes

    def __len__(self) -> int:
        return len(self._items)

    @property
    def bytes(self) -> int:
        return self._bytes

    def push(self, item: QueuedItem) -> list[QueuedItem]:
        self._items.append(item)
        self._bytes += item.size
        evicted: list[QueuedItem] = []
        while self._items and (len(self._items) > self.max_items or self._bytes > self.max_bytes):
            old = self._items.popleft()
            self._bytes -= old.size
            evicted.append(old)
        return evicted

    def take(self, limit: int) -> list[QueuedItem]:
        taken: list[QueuedItem] = []
        while self._items and len(taken) < limit:
            item = self._items.popleft()
            self._bytes -= item.size
            taken.append(item)
        return taken

    def clear(self) -> list[QueuedItem]:
        return self.take(len(self._items))


def retry_after_seconds(headers: Mapping[str, str], now_epoch: float) -> float | None:
    """`Retry-After` as delta-seconds or an HTTP-date; capped; None if absent or garbage."""
    raw = headers.get("retry-after")
    if raw is None:
        return None
    raw = raw.strip()
    if raw.isdigit():
        return min(float(raw), MAX_RETRY_AFTER_S)
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(when.timestamp() - now_epoch, MAX_RETRY_AFTER_S))
