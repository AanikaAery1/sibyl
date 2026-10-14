"""Code review M7 / L2 and the worker pool setting: honest /healthz, DB connect retry or fail
fast, close in its own finally, back-off never faster than the interval, per-tick timeouts."""

from __future__ import annotations

import asyncio
import logging

import pytest
from fastapi.testclient import TestClient
from sibyl_control.core.settings import Settings
from sibyl_control.worker import main as worker
from sibyl_control.worker.loops import LoopContext, LoopSpec
from sibyl_control.worker.main import LoopRunner, backoff_delay, health_app, tick_timeout

from .test_worker import wait_until

ticks: list[str] = []


async def ok_tick(ctx: LoopContext) -> None:
    ticks.append(ctx.name)


async def boom_tick(ctx: LoopContext) -> None:
    raise RuntimeError("tick failed")


async def slow_tick(ctx: LoopContext) -> None:
    await asyncio.sleep(10)


def _runner(*specs: LoopSpec) -> LoopRunner:
    return LoopRunner(specs, lambda s: LoopContext(s.name, None, None, logging.getLogger("t")))


@pytest.mark.parametrize("interval", [1.0, 10.0, 60.0, 3600.0, 86400.0])
@pytest.mark.parametrize("failures", [1, 2, 5, 20])
def test_backoff_is_never_faster_than_the_interval(interval: float, failures: int) -> None:
    delay = backoff_delay(interval, failures)
    assert delay >= interval
    assert delay <= max(worker.MAX_BACKOFF_S, interval)


def test_backoff_doubles_for_fast_loops() -> None:
    assert backoff_delay(1, 1) == 2
    assert backoff_delay(1, 3) == 8
    assert backoff_delay(1, 30) == worker.MAX_BACKOFF_S


def test_tick_timeout_defaults_and_overrides() -> None:
    assert tick_timeout(LoopSpec("a", "H", 1, "x:y")) == worker.DEFAULT_TICK_TIMEOUT_S
    assert tick_timeout(LoopSpec("a", "U", 3600, "x:y")) == 3600
    assert tick_timeout(LoopSpec("a", "U", 1, "x:y", timeout_s=5)) == 5
    with pytest.raises(ValueError):
        LoopSpec("a", "U", 1, "x:y", timeout_s=0)


async def test_a_hung_tick_times_out_and_counts_as_a_failure() -> None:
    runner = _runner(LoopSpec("slow", "W", 0.01, f"{__name__}:slow_tick", timeout_s=0.02))
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    await wait_until(lambda: runner.status()["slow"]["failures"] >= 1)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert runner.status()["slow"]["last_error"] == "TimeoutError"


def _health(runner: LoopRunner, has_db: bool = True):
    return TestClient(health_app(runner, has_db=lambda: has_db)).get("/healthz")


def test_healthz_is_503_without_a_database() -> None:
    resp = _health(_runner(), has_db=False)
    assert resp.status_code == 503
    assert "database" in resp.json()["reasons"]


async def test_healthz_is_503_when_every_implemented_loop_is_failing() -> None:
    runner = _runner(
        LoopSpec("boom", "W", 0.001, f"{__name__}:boom_tick"),
        LoopSpec("missing", "W", 0.001, "sibyl_control.worker.nope:tick"),
    )
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    await wait_until(
        lambda: runner.status()["boom"]["consecutive_failures"] >= worker.FAILING_AFTER
    )
    resp = _health(runner)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert resp.status_code == 503
    assert "all_loops_failing" in resp.json()["reasons"]


async def test_healthz_is_ok_while_some_loop_succeeds() -> None:
    runner = _runner(
        LoopSpec("ok", "W", 0.001, f"{__name__}:ok_tick"),
        LoopSpec("boom", "W", 0.001, f"{__name__}:boom_tick"),
    )
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    await wait_until(
        lambda: (
            runner.status()["boom"]["consecutive_failures"] >= worker.FAILING_AFTER
            and runner.status()["ok"]["runs"] >= 1
        )
    )
    resp = _health(runner)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_healthz_is_503_once_the_runner_has_stopped() -> None:
    runner = _runner(LoopSpec("ok", "W", 0.001, f"{__name__}:ok_tick"))
    stop = asyncio.Event()
    stop.set()
    await runner.run(stop)
    resp = _health(runner)
    assert resp.status_code == 503
    assert "runner_stopped" in resp.json()["reasons"]


# --- serve() ---------------------------------------------------------------------------------


class FakeDb:
    def __init__(self) -> None:
        self.closed = 0

    async def close(self) -> None:
        self.closed += 1


class Connector:
    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls: list[dict] = []
        self.db = FakeDb()

    async def __call__(self, dsn: str, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) <= self.failures:
            raise OSError("connection refused")
        return self.db


class FakeServer:
    def __init__(self, app, port: int, *, fail: bool = False) -> None:
        self.app = app
        self.port = port
        self.fail = fail
        self._exit = asyncio.Event()
        self.served = asyncio.Event()

    @property
    def should_exit(self) -> bool:
        return self._exit.is_set()

    @should_exit.setter
    def should_exit(self, value: bool) -> None:
        if value:
            self._exit.set()

    async def serve(self) -> None:
        self.served.set()
        if self.fail:
            raise RuntimeError("bind failed")
        await self._exit.wait()


def _settings(**kw) -> Settings:
    base = {"worker_db_connect_attempts": 3, "worker_db_connect_backoff_s": 0.0}
    return Settings(**{**base, **kw})


async def _no_sleep(_: float) -> None:
    return None


async def test_serve_retries_the_database_then_runs_and_closes() -> None:
    connector = Connector(failures=2)
    servers: list[FakeServer] = []

    def factory(app, port):
        servers.append(FakeServer(app, port))
        return servers[-1]

    task = asyncio.create_task(
        worker.serve(
            9999,
            (LoopSpec("ok", "W", 0.001, f"{__name__}:ok_tick"),),
            settings=_settings(worker_command_timeout_s=901.0),
            connect=connector,
            server_factory=factory,
            sleep=_no_sleep,
        )
    )
    await wait_until(lambda: bool(servers) and servers[0].served.is_set())
    assert TestClient(servers[0].app).get("/healthz").status_code == 200
    servers[0].should_exit = True
    await asyncio.wait_for(task, 2)
    assert len(connector.calls) == 3
    assert connector.calls[-1]["command_timeout"] == 901.0  # the worker pool, not the api's 30 s
    assert connector.db.closed == 1


async def test_serve_fails_fast_when_the_database_never_comes(caplog) -> None:
    connector = Connector(failures=99)
    with caplog.at_level(logging.ERROR, logger="sibyl.worker"), pytest.raises(OSError):
        await worker.serve(
            9999,
            (),
            settings=_settings(),
            connect=connector,
            server_factory=lambda app, port: FakeServer(app, port),
            sleep=_no_sleep,
        )
    assert len(connector.calls) == 3
    assert any("database" in r.getMessage() for r in caplog.records)


async def test_serve_closes_the_database_when_the_server_fails() -> None:
    connector = Connector(failures=0)
    with pytest.raises(RuntimeError, match="bind failed"):
        await worker.serve(
            9999,
            (),
            settings=_settings(),
            connect=connector,
            server_factory=lambda app, port: FakeServer(app, port, fail=True),
            sleep=_no_sleep,
        )
    assert connector.db.closed == 1


def _crash_context(spec: LoopSpec) -> LoopContext:
    raise RuntimeError("context factory crashed")


async def test_a_crashed_runner_stops_the_server_and_fails_the_process(monkeypatch) -> None:
    connector = Connector(failures=0)
    servers: list[FakeServer] = []

    def factory(app, port):
        servers.append(FakeServer(app, port))
        return servers[-1]

    original = worker.LoopRunner

    def crashing_runner(specs, context):
        return original(specs, _crash_context)

    monkeypatch.setattr(worker, "LoopRunner", crashing_runner)
    with pytest.raises(ExceptionGroup):
        await asyncio.wait_for(
            worker.serve(
                9999,
                (LoopSpec("ok", "W", 0.001, f"{__name__}:ok_tick"),),
                settings=_settings(),
                connect=connector,
                server_factory=factory,
                sleep=_no_sleep,
            ),
            3,
        )
    assert servers[0].should_exit is True
    assert connector.db.closed == 1


# --- stub loops are idle no-ops (compose live run follow-up) ----------------------------------

STUBS = (
    LoopSpec("stub_a", "X", 0.001, "sibyl_control.worker.nope_a:tick"),
    LoopSpec("stub_b", "X", 0.001, "sibyl_control.worker.nope_b:tick"),
)


async def test_a_runner_of_only_stubs_idles_until_stopped() -> None:
    runner = _runner(*STUBS)
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    for _ in range(20):
        await asyncio.sleep(0)
    assert not task.done() and not runner.finished
    status = runner.status()
    assert all(s["failures"] == 0 and not s["implemented"] for s in status.values())
    resp = _health(runner)
    assert resp.status_code == 200
    assert resp.json()["stub_loops"] == ["stub_a", "stub_b"]
    stop.set()
    await asyncio.wait_for(task, 2)


async def test_stubs_do_not_mask_or_cause_all_loops_failing() -> None:
    runner = _runner(*STUBS, LoopSpec("boom", "W", 0.001, f"{__name__}:boom_tick"))
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    await wait_until(
        lambda: runner.status()["boom"]["consecutive_failures"] >= worker.FAILING_AFTER
    )
    resp = _health(runner)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert resp.status_code == 503
    assert resp.json()["reasons"] == ["all_loops_failing"]
    assert resp.json()["stub_loops"] == ["stub_a", "stub_b"]


async def test_serve_with_only_stub_loops_keeps_serving() -> None:
    connector = Connector(failures=0)
    servers: list[FakeServer] = []

    def factory(app, port):
        servers.append(FakeServer(app, port))
        return servers[-1]

    task = asyncio.create_task(
        worker.serve(
            9999,
            STUBS,
            settings=_settings(),
            connect=connector,
            server_factory=factory,
            sleep=_no_sleep,
        )
    )
    await wait_until(lambda: bool(servers) and servers[0].served.is_set())
    for _ in range(50):
        await asyncio.sleep(0)
    assert not servers[0].should_exit  # no "loop runner stopped unexpectedly" restart loop
    resp = TestClient(servers[0].app).get("/healthz")
    assert resp.status_code == 200
    servers[0].should_exit = True
    await asyncio.wait_for(task, 2)
    assert connector.db.closed == 1


def test_the_real_loop_table_is_healthy_while_every_loop_is_a_stub() -> None:
    from sibyl_control.worker.loops import LOOPS

    runner = _runner(*LOOPS)
    resp = _health(runner)
    assert resp.status_code == 200
    stubs = resp.json()["stub_loops"]
    assert stubs == sorted(n for n, s in runner.status().items() if not s["implemented"])


def test_worker_main_requires_the_worker_secrets(monkeypatch) -> None:
    for name in ("SIBYL_KEK", "SIBYL_LEDGER_SIGNING_KEY_FILE", "SIBYL_ANCHOR_SIGNING_KEY"):
        monkeypatch.delenv(name, raising=False)
    called: list[int] = []

    async def fake_serve(port: int, **kwargs) -> None:
        called.append(port)

    monkeypatch.setattr(worker, "serve", fake_serve)
    with pytest.raises(RuntimeError, match="SIBYL_KEK"):
        worker.main()
    assert called == []
