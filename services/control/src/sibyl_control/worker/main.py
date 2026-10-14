"""Worker process: runs the loop table and serves ``/healthz`` (W0-INF runtime contract).

Each loop runs in its own task with jittered intervals and a per-tick deadline; a failing or
hung tick is logged and backs off (doubling, capped at ``max(5 min, interval)`` so an hourly loop
is never retried faster than hourly) without affecting other loops. NOTIFY-driven wake-ups on
``sibyl_policy`` / ``sibyl_outbox`` are added by the owning lanes through ``LoopSpec.channel``.

Startup connects with bounded retry/back-off and fails fast (logged, non-zero exit) when the
database never comes. The worker's pool has its own long ``command_timeout`` (default 900 s) for
long phases such as ``audit_verify`` and bulk erasure. ``/healthz`` is 503 when there is no
database, when the loop runner has stopped, or when every implemented loop is failing; a crashed
runner also stops the server so the process exits (code review M7, L2). Loops whose lane has not
written them yet are idle no-ops: they never fail, never end the runner, and ``/healthz`` lists
them under ``stub_loops``. ``main()`` refuses to start without the worker's secrets.

NOTIFY wake-ups (INT-1, lane U CR): a loop whose ``LoopSpec.channel`` is set (``saga``, ``jobs``,
``anchors`` on ``sibyl_outbox``) runs its next tick as soon as a NOTIFY arrives on that channel
instead of waiting out its interval, so e.g. a break-glass ``audit.anchor_now`` lands within
seconds. One dedicated connection LISTENs; it reconnects with back-off and wakes every loop after
reconnecting (anything committed while it was down). A failing loop ignores wake-ups and keeps
its back-off, so a NOTIFY storm cannot hot-loop it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .loops import LOOPS, LoopContext, LoopSpec, resolve_tick

log = logging.getLogger("sibyl.worker")
MAX_BACKOFF_S = 300.0
DEFAULT_TICK_TIMEOUT_S = 60.0
FAILING_AFTER = 3  # consecutive failures before a loop counts as failing for /healthz
MAX_CONNECT_BACKOFF_S = 30.0
JITTER = 0.1


def backoff_delay(interval_s: float, consecutive_failures: int) -> float:
    """Delay after ``consecutive_failures`` (>= 1) failed ticks: never below the interval."""
    cap = max(MAX_BACKOFF_S, interval_s)
    return float(min(interval_s * 2**consecutive_failures, cap))


def tick_timeout(spec: LoopSpec) -> float:
    if spec.timeout_s is not None:
        return spec.timeout_s
    return max(DEFAULT_TICK_TIMEOUT_S, spec.interval_s)


@dataclass
class _LoopState:
    implemented: bool
    runs: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    last_ok: datetime | None = None
    last_error: str | None = None


@dataclass
class LoopRunner:
    specs: Sequence[LoopSpec]
    context: Callable[[LoopSpec], LoopContext]
    _state: dict[str, _LoopState] = field(default_factory=dict)
    started: bool = False
    finished: bool = False

    def __post_init__(self) -> None:
        self._ticks = {spec.name: resolve_tick(spec) for spec in self.specs}
        self._state = {
            name: _LoopState(implemented=tick is not None) for name, tick in self._ticks.items()
        }
        self._wakes = {spec.name: asyncio.Event() for spec in self.specs}

    def channels(self) -> frozenset[str]:
        """NOTIFY channels some implemented loop wants to be woken by."""
        return frozenset(
            spec.channel
            for spec in self.specs
            if spec.channel is not None and self._ticks[spec.name] is not None
        )

    def wake(self, channel: str | None = None) -> None:
        """Wake every loop listening on ``channel`` (all channel loops when ``None``)."""
        for spec in self.specs:
            if spec.channel is not None and channel in (None, spec.channel):
                self._wakes[spec.name].set()

    def status(self) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "implemented": s.implemented,
                "runs": s.runs,
                "failures": s.failures,
                "consecutive_failures": s.consecutive_failures,
                "last_ok": s.last_ok.isoformat() if s.last_ok else None,
                "last_error": s.last_error,
            }
            for name, s in self._state.items()
        }

    def stub_loops(self) -> list[str]:
        return sorted(name for name, s in self._state.items() if not s.implemented)

    def all_failing(self) -> bool:
        """True when every IMPLEMENTED loop is failing; stubs are ignored, and a runner with
        only stubs is never failing."""
        implemented = [s for s in self._state.values() if s.implemented]
        return bool(implemented) and all(
            s.consecutive_failures >= FAILING_AFTER for s in implemented
        )

    async def _loop(self, spec: LoopSpec, stop: asyncio.Event) -> None:
        tick = self._ticks[spec.name]
        state = self._state[spec.name]
        if tick is None:
            # A stub is an idle no-op: it neither fails nor ends the runner (a TaskGroup whose
            # tasks all return would look like a crashed runner and restart-loop the worker).
            log.info("loop %s (lane %s) not implemented yet; idle", spec.name, spec.owner)
            await stop.wait()
            return
        ctx = self.context(spec)
        timeout = tick_timeout(spec)
        wake = self._wakes[spec.name]
        while not stop.is_set():
            delay = spec.interval_s
            wake.clear()  # a NOTIFY during this tick still wakes the next sleep (set below)
            try:
                await asyncio.wait_for(tick(ctx), timeout=timeout)
                state.runs += 1
                state.consecutive_failures = 0
                state.last_ok = datetime.now(UTC)
                wakeable = True
            except Exception as exc:
                state.failures += 1
                state.consecutive_failures += 1
                state.last_error = type(exc).__name__
                log.exception("loop %s tick failed", spec.name)
                delay = backoff_delay(spec.interval_s, state.consecutive_failures)
                wakeable = False
            delay *= 1 + random.uniform(-JITTER, JITTER)  # noqa: S311  (scheduling jitter)
            await _sleep(delay, stop, wake if wakeable else None)

    async def run(self, stop: asyncio.Event) -> None:
        self.started = True
        try:
            async with asyncio.TaskGroup() as group:
                for spec in self.specs:
                    group.create_task(self._loop(spec, stop))
        finally:
            self.finished = True

    def health(self, *, has_db: bool) -> list[str]:
        """Reasons the worker is unhealthy (empty = healthy)."""
        reasons = []
        if not has_db:
            reasons.append("database")
        if self.finished:
            reasons.append("runner_stopped")
        if self.all_failing():
            reasons.append("all_loops_failing")
        return reasons


async def _sleep(delay: float, stop: asyncio.Event, wake: asyncio.Event | None) -> None:
    """Sleep ``delay`` seconds, cut short by ``stop`` or (when given) ``wake``."""
    events = [stop] if wake is None else [stop, wake]
    waiters = [asyncio.ensure_future(event.wait()) for event in events]
    try:
        await asyncio.wait(waiters, timeout=delay, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for waiter in waiters:
            waiter.cancel()


LISTEN_RETRY_MIN_S = 1.0
LISTEN_RETRY_MAX_S = 30.0
LISTEN_LIVENESS_S = 5.0


async def listen_for_wakeups(
    db: Any,
    runner: LoopRunner,
    stop: asyncio.Event,
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    liveness_s: float = LISTEN_LIVENESS_S,
) -> None:
    """LISTEN on the runner's channels and wake the matching loops until ``stop``."""
    channels = sorted(runner.channels())
    connect = getattr(db, "listen_connection", None)
    if not channels or connect is None:
        return
    delay = LISTEN_RETRY_MIN_S

    def on_notify(_conn: Any, _pid: int, channel: str, _payload: str) -> None:
        runner.wake(channel)

    while not stop.is_set():
        try:
            async with connect() as conn:
                for channel in channels:
                    await conn.add_listener(channel, on_notify)
                try:
                    runner.wake()  # catch up on anything committed while we were not listening
                    delay = LISTEN_RETRY_MIN_S
                    while not stop.is_set() and not conn.is_closed():
                        await _sleep(liveness_s, stop, None)
                finally:
                    if not conn.is_closed():
                        for channel in channels:
                            with contextlib.suppress(Exception):
                                await conn.remove_listener(channel, on_notify)
        except Exception as exc:
            log.warning("worker LISTEN connection lost (%s); retrying", type(exc).__name__)
        if stop.is_set():
            return
        await sleep(delay)
        delay = min(delay * 2, LISTEN_RETRY_MAX_S)


def health_app(runner: LoopRunner, *, has_db: Callable[[], bool]) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        reasons = runner.health(has_db=has_db())
        body = {
            "status": "unhealthy" if reasons else "ok",
            "reasons": reasons,
            "stub_loops": runner.stub_loops(),
            "loops": runner.status(),
        }
        return JSONResponse(body, status_code=503 if reasons else 200)

    return app


class _Closable(Protocol):
    async def close(self) -> None: ...


class _Server(Protocol):
    should_exit: bool

    async def serve(self) -> None: ...


Connect = Callable[..., Awaitable[Any]]
ServerFactory = Callable[[FastAPI, int], _Server]


def _uvicorn_server(app: FastAPI, port: int) -> _Server:
    import uvicorn

    config = uvicorn.Config(
        app,
        host="0.0.0.0",  # noqa: S104  (container entrypoint)
        port=port,
        server_header=False,
        log_level="info",
    )
    return uvicorn.Server(config)


async def connect_with_retry(
    settings: Any, connect: Connect, sleep: Callable[[float], Awaitable[None]]
) -> Any:
    """Open the worker pool, retrying with back-off; raise (logged) when it never comes."""
    attempts = max(1, int(settings.worker_db_connect_attempts))
    for attempt in range(1, attempts + 1):
        try:
            return await connect(
                settings.dsn(),
                min_size=settings.worker_pool_min,
                max_size=settings.worker_pool_max,
                application_name="sibyl-worker",
                command_timeout=settings.worker_command_timeout_s,
            )
        except Exception as exc:
            if attempt == attempts:
                log.error(
                    "worker database unreachable after %d attempts (%s); exiting",
                    attempts,
                    type(exc).__name__,
                )
                raise
            delay = min(
                settings.worker_db_connect_backoff_s * 2 ** (attempt - 1), MAX_CONNECT_BACKOFF_S
            )
            log.warning(
                "worker database connect failed (attempt %d/%d, %s); retrying in %.1fs",
                attempt,
                attempts,
                type(exc).__name__,
                delay,
            )
            await sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover


async def serve(
    port: int,
    specs: Sequence[LoopSpec] = LOOPS,
    *,
    settings: Any = None,
    connect: Connect | None = None,
    server_factory: ServerFactory = _uvicorn_server,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    from ..core.db import Database
    from ..core.settings import Settings

    settings = settings or Settings()
    db: _Closable = await connect_with_retry(settings, connect or Database.connect, sleep)
    try:
        runner = LoopRunner(specs, lambda spec: LoopContext(spec.name, db, settings, log))
        server = server_factory(health_app(runner, has_db=lambda: db is not None), port)
        stop = asyncio.Event()
        loops = asyncio.create_task(runner.run(stop))
        listener = asyncio.create_task(listen_for_wakeups(db, runner, stop))

        def on_loops_done(task: asyncio.Task[None]) -> None:
            if not stop.is_set():
                log.error("worker loop runner stopped unexpectedly; shutting down")
                server.should_exit = True

        loops.add_done_callback(on_loops_done)
        try:
            await server.serve()
        finally:
            stop.set()
            await asyncio.gather(loops, listener, return_exceptions=True)
        if loops.exception() is not None:
            raise loops.exception()  # type: ignore[misc]
    finally:
        await db.close()


def main() -> None:
    from ..core.settings import Settings

    logging.basicConfig(level=logging.INFO)
    settings = Settings()
    settings.require_secrets("worker")
    asyncio.run(serve(settings.port_for("worker"), settings=settings))
