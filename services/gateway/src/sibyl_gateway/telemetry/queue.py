"""Bounded, non-blocking telemetry queue and the batch sender to ingest ``POST /v1/events``.

The hot path only calls ``offer()``: an O(1) append that never awaits and never raises. When
the queue is full the event is dropped and counted (``telemetry.dropped``), so a slow or
unreachable ingest can never add latency to a proxied call. A background task drains batches
(≤ 500 events or every ``flush_s``) and retries a failed batch with capped backoff.
In-memory only: a disk spill is a follow-up (credentials are never part of these events).

B-03: every batch is split by ``tenant_id`` and each part goes with its own tenant's ingest
key (ingest files events under the key's tenant). A part whose tenant has no key raises
``UnroutableTelemetry`` and is dropped and counted (``unroutable``), never retried and never
posted under another tenant's key.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import deque
from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger("sibyl.gateway.telemetry")
Sink = Callable[[Sequence[dict[str, Any]]], Awaitable[None]]
KeyFor = Callable[[Any], str | None]


class UnroutableTelemetry(Exception):
    """No ingest key belongs to this batch's tenant (fail closed: drop, do not retry)."""


def by_tenant(batch: Sequence[dict[str, Any]]) -> Iterator[list[dict[str, Any]]]:
    """The batch split by ``tenant_id``, in first-seen order, each part in offer order."""
    parts: dict[Any, list[dict[str, Any]]] = {}
    for event in batch:
        parts.setdefault(event.get("tenant_id"), []).append(event)
    yield from parts.values()


@dataclass
class TelemetryStats:
    offered: int = 0
    dropped: int = 0
    sent: int = 0
    failed_batches: int = 0
    unroutable: int = 0


class TelemetryQueue:
    def __init__(
        self,
        sink: Sink | None,
        *,
        max_events: int = 10_000,
        batch_size: int = 500,
        flush_s: float = 1.0,
        max_retries: int = 5,
    ) -> None:
        self._sink = sink
        self._buffer: deque[dict[str, Any]] = deque()
        self._max = max_events
        self._batch = batch_size
        self._flush_s = flush_s
        self._retries = max_retries
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.stats = TelemetryStats()

    def offer(self, event: dict[str, Any]) -> bool:
        """Never blocks, never raises; ``False`` when the event was dropped."""
        self.stats.offered += 1
        if len(self._buffer) >= self._max:
            self.stats.dropped += 1
            return False
        self._buffer.append(event)
        if len(self._buffer) >= self._batch:
            self._wake.set()
        return True

    def pending(self) -> list[dict[str, Any]]:
        return list(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)

    def start(self) -> None:
        if self._task is None and self._sink is not None:
            self._task = asyncio.create_task(self._run(), name="sibyl-telemetry")

    async def stop(self, *, drain_timeout_s: float = 2.0) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self._sink is not None and self._buffer:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.flush(), drain_timeout_s)

    async def flush(self) -> None:
        while self._buffer:
            batch = [self._buffer.popleft() for _ in range(min(self._batch, len(self._buffer)))]
            parts = list(by_tenant(batch))
            for n, part in enumerate(parts):
                try:
                    await self._deliver(part)
                except asyncio.CancelledError:
                    # _deliver put its own part back; keep the parts not yet tried as well
                    for event in reversed([e for later in parts[n + 1 :] for e in later]):
                        self._buffer.appendleft(event)
                    raise

    async def _run(self) -> None:
        while True:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self._flush_s)
            self._wake.clear()
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("telemetry flush failed")

    async def _deliver(self, batch: list[dict[str, Any]]) -> None:
        assert self._sink is not None
        delay = 0.2
        for attempt in range(self._retries + 1):
            try:
                await self._sink(batch)
                self.stats.sent += len(batch)
                return
            except asyncio.CancelledError:
                for event in reversed(batch):
                    self._buffer.appendleft(event)
                raise
            except UnroutableTelemetry:
                self.stats.unroutable += len(batch)
                self.stats.dropped += len(batch)
                log.warning("telemetry for a tenant without an ingest key dropped: %d", len(batch))
                return
            except Exception as exc:
                self.stats.failed_batches += 1
                if attempt == self._retries:
                    self.stats.dropped += len(batch)
                    log.warning("telemetry batch of %d dropped: %s", len(batch), type(exc).__name__)
                    return
                await asyncio.sleep(delay)
                delay = min(delay * 2, 5.0)


class HttpIngestSink:
    """``POST {ingest}/v1/events`` with an ``ingest:write`` key (never logged)."""

    def __init__(self, base_url: str, key: str | KeyFor, client: httpx.AsyncClient) -> None:
        """``key``: one key for a single-tenant gateway, or the tenant -> key resolver (B-03);
        a batch passed to a resolving sink carries one tenant (the queue splits them)."""
        self._url = base_url.rstrip("/") + "/v1/events"
        self._key_for: KeyFor = (lambda _tenant: key) if isinstance(key, str) else key
        self._client = client

    def __repr__(self) -> str:
        return f"HttpIngestSink(url={self._url!r})"

    async def __call__(self, batch: Sequence[dict[str, Any]]) -> None:
        tenants = {event.get("tenant_id") for event in batch}
        key = self._key_for(next(iter(tenants))) if len(tenants) == 1 else None
        if key is None:
            raise UnroutableTelemetry(f"{len(batch)} events")
        resp = await self._client.post(
            self._url,
            json={"schema": "sibyl-event/1", "events": list(batch)},
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        if resp.status_code >= 500 or resp.status_code == 429:
            raise RuntimeError(f"ingest answered {resp.status_code}")
        if resp.status_code >= 400:
            log.warning("ingest refused a telemetry batch: %s", resp.status_code)
