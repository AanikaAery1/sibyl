"""Identifiers and time helpers: uuidv7, W3C trace/span ids, RFC 3339 timestamps, clocks."""

from __future__ import annotations

import os
import re
import secrets
import time
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
NIL_UUID = "00000000-0000-0000-0000-000000000000"


class Clock(Protocol):
    """Wall clock (epoch seconds) plus a monotonic clock; injectable for tests."""

    def time(self) -> float: ...
    def monotonic(self) -> float: ...


class SystemClock:
    def time(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()


SYSTEM_CLOCK = SystemClock()


def uuid7(at: float | None = None) -> UUID:
    """RFC 9562 version-7 UUID: 48-bit unix ms, version, 12 + 62 random bits."""
    millis = int((time.time() if at is None else at) * 1000) & ((1 << 48) - 1)
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    value = (millis << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return UUID(int=value)


def new_trace_id() -> str:
    return os.urandom(16).hex()


def new_span_id() -> str:
    return os.urandom(8).hex()


def is_uuid(text: str) -> bool:
    return bool(_UUID_RE.match(text))


def rfc3339(epoch_s: float) -> str:
    """Millisecond RFC 3339 with `Z` (the fixture spelling)."""
    moment = datetime.fromtimestamp(epoch_s, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def parse_rfc3339(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
