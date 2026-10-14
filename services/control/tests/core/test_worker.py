import asyncio
import logging

import pytest
from fastapi.testclient import TestClient
from sibyl_control.worker.loops import LOOPS, LoopContext, LoopSpec, resolve_tick
from sibyl_control.worker.main import LoopRunner, health_app

calls: list[str] = []


async def wait_until(condition, limit_s: float = 5.0) -> None:
    """Poll a condition instead of sleeping a fixed time (test review F16)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limit_s
    while not condition():
        if loop.time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.005)


async def fake_tick(ctx: LoopContext) -> None:
    calls.append(ctx.name)


async def boom_tick(ctx: LoopContext) -> None:
    raise RuntimeError("tick failed")


def test_loop_table_is_complete_and_unique() -> None:
    names = [spec.name for spec in LOOPS]
    assert len(names) == len(set(names))
    assert {
        "rollup",
        "scoring",
        "status_poller",
        "predict",
        "alerts",
        "saga",
        "approvals",
        "failback",
        "handoff",
        "partitions",
        "retention",
        "anchors",
        "erasure_exec",
        "erasure_ledger",
        "jobs",
        "held_actions",
        "drift",  # D51 (lane DRIFT)
        "sentinel",
        "action_counters",  # AG-LIVE: cumulative-cap window retention
        "webhooks",  # D53 (lane EXTMON): monitor webhooks and external-finding alerts
    } == set(names)
    for spec in LOOPS:
        assert spec.interval_s > 0
        assert spec.target.startswith("sibyl_control.worker.")
        assert spec.channel in (None, "sibyl_policy", "sibyl_outbox")


def test_unimplemented_loops_resolve_to_none() -> None:
    assert resolve_tick(LoopSpec("x", "H", 1, "sibyl_control.worker.nope:tick")) is None
    spec = LoopSpec("fake", "W0", 1, f"{__name__}:fake_tick")
    assert resolve_tick(spec) is fake_tick


async def test_runner_runs_implemented_loops_and_isolates_failures() -> None:
    calls.clear()
    specs = (
        LoopSpec("fake", "W0", 0.01, f"{__name__}:fake_tick"),
        LoopSpec("boom", "W0", 0.01, f"{__name__}:boom_tick"),
        LoopSpec("missing", "W0", 0.01, "sibyl_control.worker.nope:tick"),
    )
    runner = LoopRunner(
        specs, context=lambda spec: LoopContext(spec.name, None, None, logging.getLogger("t"))
    )
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop))
    await wait_until(lambda: calls.count("fake") >= 2 and runner.status()["boom"]["failures"] >= 1)
    stop.set()
    await asyncio.wait_for(task, 2)
    status = runner.status()
    assert calls.count("fake") >= 2
    assert status["fake"]["implemented"] and status["fake"]["runs"] >= 2
    assert status["boom"]["failures"] >= 1
    assert not status["missing"]["implemented"]


def test_worker_health_endpoint_reports_loops() -> None:
    runner = LoopRunner(
        LOOPS, context=lambda spec: LoopContext(spec.name, None, None, logging.getLogger("t"))
    )
    client = TestClient(health_app(runner, has_db=lambda: True))
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert set(body["loops"]) == {spec.name for spec in LOOPS}


@pytest.mark.parametrize("bad", [0, -1])
def test_interval_must_be_positive(bad) -> None:
    with pytest.raises(ValueError):
        LoopSpec("x", "H", bad, "sibyl_control.worker.x:tick")
