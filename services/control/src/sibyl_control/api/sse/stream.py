"""The per-connection outbox projection behind ``GET /api/v1/events/stream`` (API.md §7, R60).

* Event id = the outbox cursor ``<xid>|<id>``; resume reads ``sibyl.outbox_read`` strictly after
  it and strictly below the commit horizon, so a late-committing transaction is never skipped.
* A reader task fills a bounded buffer (1,000 frames). When it overflows the stream ends with
  ``event: reset`` ``{"reason":"slow_consumer"}`` instead of dropping silently.
* Rows the caller may not see still advance the cursor; the next heartbeat carries an ``id:``
  line so a reconnect resumes past them.
* Every heartbeat (``: ping``, 15 s) re-resolves the principal: a revoked or expired session or
  key ends the stream. Connections also end after ``max_lifetime_s`` and reconnect.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sibyl_schemas.values import SSE_EVENT_TOPIC

from ...core.db import Database
from .hub import NotifyHub

NIL = UUID(int=0)
STREAMABLE_EVENTS = frozenset(event.value for event in SSE_EVENT_TOPIC)
"""Worker-facing outbox events (``job.requested``, ``agent.discovered``,
``audit.anchor_now``) are never streamed, whatever the caller may otherwise see."""
READ_BATCH = 500


@dataclass(frozen=True)
class Cursor:
    xid: int
    id: UUID

    def __str__(self) -> str:
        return f"{self.xid}|{self.id}"


@dataclass(frozen=True)
class StreamConfig:
    buffer: int = 1000
    heartbeat_s: float = 15.0
    poll_s: float = 2.0
    retry_ms: int = 3000
    max_lifetime_s: float = 3600.0


@dataclass(frozen=True)
class Visibility:
    """Which rows this caller receives (all checks are on refs, never content)."""

    topics: frozenset[str] | None  # None = every topic the caller may see
    event_types: frozenset[str] | None
    agent_id: UUID | None  # ?agent_id= filter or a bound key's agent
    agents: frozenset[UUID] | None  # group-scoped human: in-scope agents (None = all)

    def admits(self, row: Any) -> bool:
        if row["event_type"] not in STREAMABLE_EVENTS:
            return False
        if self.topics is not None and row["topic"] not in self.topics:
            return False
        if self.event_types is not None and row["event_type"] not in self.event_types:
            return False
        refs = agent_refs(row)
        if not refs:  # tenant-level row (snapshot.issued, graph.changed …): versions only
            return True
        if self.agent_id is not None and self.agent_id not in refs:
            return False
        return self.agents is None or bool(refs & self.agents)


def agent_refs(row: Any) -> set[UUID]:
    payload = row["payload"] or {}
    refs: set[UUID] = set()
    if row["aggregate_kind"] == "agent":
        refs.add(row["aggregate_id"])
    candidates: list[Any] = [payload.get("agent_id")]
    candidates += list(payload.get("affected_agent_ids") or [])
    if payload.get("scope_kind") == "agent":
        candidates.append(payload.get("scope_id"))
    for value in candidates:
        with contextlib.suppress(TypeError, ValueError):
            if value:
                refs.add(UUID(str(value)))
    return refs


def frame(*, event: str | None = None, data: Any = None, id_: str | None = None) -> bytes:
    lines = []
    if id_ is not None:
        lines.append(f"id: {id_}")
    if event is not None:
        lines.append(f"event: {event}")
    if data is not None:
        lines.append("data: " + json.dumps(data, separators=(",", ":"), default=str))
    return ("\n".join(lines) + "\n\n").encode()


def reset(reason: str, oldest: Cursor | None = None) -> bytes:
    data: dict[str, Any] = {"reason": reason}
    if oldest is not None:
        data["oldest"] = str(oldest)
    return frame(event="reset", data=data)


_READ_SQL = (
    "SELECT xid::text::numeric AS xid_n, id, topic, event_type, aggregate_kind, aggregate_id,"
    " payload"
    " FROM sibyl.outbox_read($1::text::xid8, $2, $3, $4)"
)


async def read_after(
    db: Database, tenant: UUID, after: Cursor, topics: Iterable[str] | None, limit: int
) -> list[Any]:
    async with db.tenant_tx(tenant, readonly=True) as conn:
        rows: list[Any] = await conn.fetch(
            _READ_SQL, str(after.xid), after.id, limit, list(topics) if topics is not None else None
        )
    return rows


async def head_cursor(conn: Any, tenant: UUID) -> Cursor:
    """The newest row below the commit horizon (a real row, so a resume can be verified)."""
    row = await conn.fetchrow(
        "SELECT xid::text::numeric AS xid_n, id FROM sibyl.outbox WHERE tenant_id = $1"
        " AND xid < sibyl.commit_horizon() ORDER BY xid DESC, id DESC LIMIT 1",
        tenant,
    )
    return Cursor(int(row["xid_n"]), row["id"]) if row is not None else Cursor(0, NIL)


async def oldest_cursor(conn: Any, tenant: UUID) -> Cursor | None:
    row = await conn.fetchrow(
        "SELECT xid::text::numeric AS xid_n, id FROM sibyl.outbox WHERE tenant_id = $1"
        " ORDER BY xid, id LIMIT 1",
        tenant,
    )
    return Cursor(int(row["xid_n"]), row["id"]) if row is not None else None


Revalidate = Callable[[], Awaitable[bool]]


class OutboxStream:
    def __init__(
        self,
        db: Database,
        hub: NotifyHub,
        tenant: UUID,
        start: Cursor,
        visibility: Visibility,
        *,
        db_topics: Iterable[str] | None,
        revalidate: Revalidate,
        config: StreamConfig,
        announce: bool,
    ) -> None:
        self._db = db
        self._hub = hub
        self._tenant = tenant
        self._cursor = start
        self._sent = start if announce else None
        self._vis = visibility
        self._topics = list(db_topics) if db_topics is not None else None
        self._revalidate = revalidate
        self._config = config
        self._announce = announce
        self._queue: asyncio.Queue[tuple[Cursor, bytes]] = asyncio.Queue(config.buffer)
        self._overflow = asyncio.Event()

    async def _reader(self) -> None:
        sub = self._hub.subscribe(self._tenant)
        try:
            after = self._cursor
            while True:
                sub.wake.clear()
                rows = await read_after(self._db, self._tenant, after, self._topics, READ_BATCH)
                for row in rows:
                    after = Cursor(int(row["xid_n"]), row["id"])
                    if self._vis.admits(row):
                        payload = frame(
                            id_=str(after), event=row["event_type"], data=row["payload"]
                        )
                        try:
                            self._queue.put_nowait((after, payload))
                        except asyncio.QueueFull:
                            self._overflow.set()
                            return
                    else:
                        self._cursor = after  # skipped rows still move the resume point
                if len(rows) == READ_BATCH:
                    continue
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(sub.wake.wait(), self._config.poll_s)
        finally:
            self._hub.unsubscribe(sub)

    async def frames(self) -> AsyncIterator[bytes]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._config.max_lifetime_s
        opening = f"retry: {self._config.retry_ms}\n"
        if self._announce:
            opening += f"id: {self._cursor}\n"
        yield (opening + "\n").encode()
        reader = asyncio.create_task(self._reader(), name="sibyl-sse-reader")
        try:
            while loop.time() < deadline:
                if self._overflow.is_set() and self._queue.empty():
                    yield reset("slow_consumer")
                    return
                try:
                    cursor, payload = await asyncio.wait_for(
                        self._next(), min(self._config.heartbeat_s, deadline - loop.time())
                    )
                except TimeoutError:
                    if reader.done() and not self._overflow.is_set():
                        reader.result()  # surface a reader failure
                    if not await self._revalidate():
                        return
                    yield self._heartbeat()
                    continue
                if cursor is None:
                    continue
                self._sent = cursor
                self._cursor = max(self._cursor, cursor, key=lambda c: (c.xid, c.id.bytes))
                yield payload
        finally:
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reader

    async def _next(self) -> tuple[Cursor | None, bytes]:
        getter = asyncio.ensure_future(self._queue.get())
        overflow = asyncio.ensure_future(self._overflow.wait())
        try:
            done, _ = await asyncio.wait({getter, overflow}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (getter, overflow):
                if not task.done():
                    task.cancel()
        if getter in done:
            return getter.result()
        return None, b""

    def _heartbeat(self) -> bytes:
        if self._sent is None or (self._cursor.xid, self._cursor.id.bytes) > (
            self._sent.xid,
            self._sent.id.bytes,
        ):
            self._sent = self._cursor
            if self._cursor.id != NIL:
                return f"id: {self._cursor}\n: ping\n\n".encode()
        return b": ping\n\n"
