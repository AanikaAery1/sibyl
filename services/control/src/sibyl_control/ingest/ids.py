"""UUIDv7 helpers, including the deterministic span event id (API.md §4.3 layer 2).

A replayed span must yield the same ``event_id``: the 48-bit time field comes from the span
end time and the 74 "random" bits from ``sha256(tenant ‖ trace_id ‖ span_id ‖ source)[0:10]``.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from uuid import UUID


def _assemble(ms: int, rand: bytes) -> UUID:
    ms &= (1 << 48) - 1
    raw = bytearray(ms.to_bytes(6, "big") + rand[:10])
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return UUID(bytes=bytes(raw))


def uuid7(at: datetime | None = None) -> UUID:
    ms = int(at.timestamp() * 1000) if at is not None else int(datetime.now().timestamp() * 1000)
    return _assemble(ms, os.urandom(10))


def deterministic_uuid7(ms: int, *parts: str | bytes | UUID) -> UUID:
    digest = hashlib.sha256()
    for part in parts:
        raw = (
            part.bytes
            if isinstance(part, UUID)
            else part
            if isinstance(part, bytes)
            else part.encode()
        )
        digest.update(len(raw).to_bytes(4, "big") + raw)
    return _assemble(ms, digest.digest()[:10])


def span_event_id(
    tenant_id: UUID, trace_id: bytes, span_id: bytes, source: str, end_ns: int
) -> UUID:
    return deterministic_uuid7(end_ns // 1_000_000, tenant_id, trace_id, span_id, source)
