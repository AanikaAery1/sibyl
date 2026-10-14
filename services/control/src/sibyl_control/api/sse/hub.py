"""One ``LISTEN sibyl_policy, sibyl_outbox`` connection per process, fanned out per tenant.

The outbox trigger NOTIFYs a constant per-tenant payload (the tenant id) on exactly two
channels after commit. The hub only *wakes* the streams of that tenant; every stream then reads
``sibyl.outbox_read`` itself, so a lost NOTIFY costs at most one poll interval (the streams also
poll every ``poll_s``). If the LISTEN connection drops, the hub wakes every subscriber and
reconnects with backoff.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from ...core.outbox import OUTBOX_CHANNEL, POLICY_CHANNEL

log = logging.getLogger("sibyl.sse")
CHANNELS = (POLICY_CHANNEL, OUTBOX_CHANNEL)
RECONNECT_BACKOFF_S = (0.5, 1.0, 2.0, 5.0)


@dataclass(eq=False)
class Subscription:
    tenant_id: UUID
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    notified: int = 0


Connect = Callable[[], Awaitable[Any]]


class NotifyHub:
    def __init__(self, connect: Connect) -> None:
        self._connect = connect
        self._subs: dict[UUID, set[Subscription]] = {}
        self._task: asyncio.Task[None] | None = None
        self._conn: Any = None
        self._ready = asyncio.Event()
        self.notifications = 0

    @property
    def listening(self) -> bool:
        return self._ready.is_set()

    async def start(self, timeout_s: float = 5.0) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="sibyl-sse-hub")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._ready.wait(), timeout_s)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        await self._close()

    def subscribe(self, tenant_id: UUID) -> Subscription:
        sub = Subscription(tenant_id)
        self._subs.setdefault(tenant_id, set()).add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        subs = self._subs.get(sub.tenant_id)
        if subs is not None:
            subs.discard(sub)
            if not subs:
                self._subs.pop(sub.tenant_id, None)

    def _on_notify(self, _conn: Any, _pid: int, _channel: str, payload: str) -> None:
        self.notifications += 1
        try:
            tenant = UUID(payload)
        except ValueError:
            return
        for sub in self._subs.get(tenant, ()):
            sub.notified += 1
            sub.wake.set()

    def _wake_all(self) -> None:
        for subs in self._subs.values():
            for sub in subs:
                sub.wake.set()

    async def _close(self) -> None:
        conn, self._conn = self._conn, None
        self._ready.clear()
        if conn is not None:
            with contextlib.suppress(Exception):
                await conn.close()

    async def _run(self) -> None:
        attempt = 0
        while True:
            try:
                self._conn = await self._connect()
                for channel in CHANNELS:
                    await self._conn.add_listener(channel, self._on_notify)
                lost = asyncio.Event()
                self._conn.add_termination_listener(lambda _conn, ev=lost: ev.set())
                self._ready.set()
                attempt = 0
                self._wake_all()  # anything committed while we were not listening
                while not self._conn.is_closed():  # termination listener, plus a liveness check
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(lost.wait(), 5.0)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("sse hub LISTEN connection failed; reconnecting", exc_info=True)
            await self._close()
            self._wake_all()
            await asyncio.sleep(RECONNECT_BACKOFF_S[min(attempt, len(RECONNECT_BACKOFF_S) - 1)])
            attempt += 1
