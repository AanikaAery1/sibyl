"""Worker NOTIFY wake-ups (lane U CR to INT-1): ``LoopSpec.channel`` loops run early on a NOTIFY.

A loop with a 1-hour interval on ``sibyl_outbox`` ticks again as soon as the channel fires; a
loop without a channel does not; a failing loop ignores wake-ups (its back-off holds); the
listener reconnects after the connection dies and wakes everything after reconnecting.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from sibyl_control.worker import main as worker_main
from sibyl_control.worker.loops import LoopContext, LoopSpec
from sibyl_control.worker.main import LoopRunner, listen_for_wakeups

HOUR = 3600.0


def _runner(specs: list[LoopSpec], ticks: dict[str, Any]) -> LoopRunner:
    runner = LoopRunner(specs, lambda spec: LoopContext(spec.name, None, None, logging.getLogger()))
    runner._ticks.update(ticks)  # inject test ticks for the spec names
    for name in ticks:
        runner._state[name].implemented = True
    return runner


async def _until(predicate: Any, limit_s: float = 2.0) -> None:
    async with asyncio.timeout(limit_s):
        while not predicate():  # noqa: ASYNC110 (polling test state, bounded by the timeout)
            await asyncio.sleep(0.01)


async def test_a_notify_wakes_only_the_loops_on_that_channel() -> None:
    counts = {"on_outbox": 0, "quiet": 0}

    def counter(name: str) -> Any:
        async def tick(ctx: Any) -> None:
            counts[name] += 1

        return tick

    specs = [
        LoopSpec("on_outbox", "T", HOUR, "x:y", "sibyl_outbox"),
        LoopSpec("quiet", "T", HOUR, "x:z"),
    ]
    runner = _runner(specs, {n: counter(n) for n in counts})
    assert runner.channels() == {"sibyl_outbox"}
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    await _until(lambda: counts == {"on_outbox": 1, "quiet": 1})
    runner.wake("sibyl_policy")  # nobody listens there
    runner.wake("sibyl_outbox")
    await _until(lambda: counts["on_outbox"] == 2)
    await asyncio.sleep(0.05)
    assert counts == {"on_outbox": 2, "quiet": 1}
    stop.set()
    await task


async def test_a_failing_loop_ignores_wakeups() -> None:
    calls = 0

    async def broken(ctx: Any) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("boom")

    runner = _runner([LoopSpec("broken", "T", HOUR, "x:y", "sibyl_outbox")], {"broken": broken})
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    await _until(lambda: calls == 1)
    runner.wake("sibyl_outbox")
    await asyncio.sleep(0.05)
    assert calls == 1
    stop.set()
    await task


class FakeConn:
    def __init__(self) -> None:
        self.listeners: dict[str, Any] = {}
        self.closed = False

    async def add_listener(self, channel: str, callback: Any) -> None:
        self.listeners[channel] = callback

    async def remove_listener(self, channel: str, callback: Any) -> None:
        self.listeners.pop(channel, None)

    def is_closed(self) -> bool:
        return self.closed

    def notify(self, channel: str) -> None:
        self.listeners[channel](self, 1, channel, "tenant")


class FakeDb:
    def __init__(self) -> None:
        self.conns: list[FakeConn] = []

    @asynccontextmanager
    async def listen_connection(self) -> Any:
        conn = FakeConn()
        self.conns.append(conn)
        yield conn


async def test_listener_wakes_loops_and_reconnects() -> None:
    runner = _runner([LoopSpec("jobs", "T", HOUR, "x:y", "sibyl_outbox")], {"jobs": _noop})
    db, stop = FakeDb(), asyncio.Event()

    async def fast_sleep(_s: float) -> None:
        await asyncio.sleep(0)

    task = asyncio.create_task(
        listen_for_wakeups(db, runner, stop, sleep=fast_sleep, liveness_s=0.01)
    )
    await _until(lambda: len(db.conns) == 1 and "sibyl_outbox" in db.conns[0].listeners)
    wake = runner._wakes["jobs"]
    assert wake.is_set()  # catch-up wake after connecting
    wake.clear()
    db.conns[0].notify("sibyl_outbox")
    assert wake.is_set()
    wake.clear()
    db.conns[0].closed = True  # connection lost: reconnect and wake again
    await _until(lambda: len(db.conns) == 2 and wake.is_set())
    stop.set()
    await task


async def test_listener_is_a_no_op_without_channels_or_support() -> None:
    runner = _runner([LoopSpec("quiet", "T", HOUR, "x:y")], {"quiet": _noop})
    await asyncio.wait_for(listen_for_wakeups(FakeDb(), runner, asyncio.Event()), 1)
    runner2 = _runner([LoopSpec("jobs", "T", HOUR, "x:y", "sibyl_outbox")], {"jobs": _noop})
    await asyncio.wait_for(listen_for_wakeups(object(), runner2, asyncio.Event()), 1)
    assert worker_main.LISTEN_RETRY_MIN_S <= worker_main.LISTEN_RETRY_MAX_S


async def _noop(ctx: Any) -> None:
    return None
