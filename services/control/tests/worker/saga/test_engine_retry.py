"""Engine retry path and the failback/handoff/saga tick entry points on PG17."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from sibyl_control.core.settings import Settings
from sibyl_control.worker.loops import LOOPS, LoopContext, resolve_tick
from sibyl_control.worker.saga import engine, runner
from sibyl_control.worker.saga.model import SagaError
from sibyl_lane_s_world import SWorld


def _saga(s: SWorld) -> Any:
    p, p2 = s.provider(), s.provider()
    agent = s.agent(model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent)
    return s.run(runner.detect_tenant(s.worker_db, s.env(), s.a.id))[0]


def test_retryable_step_errors_back_off_then_fail(
    sworld: SWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = sworld
    fid = _saga(s)

    async def flaky(conn: Any, env: Any, tenant: Any, row: Any) -> Any:
        raise SagaError("serialization_failure", "transient", retryable=True)

    monkeypatch.setitem(engine.STEP_FUNCTIONS, "validate", flaky)
    progress = s.run(runner.run_saga(s.worker_db, s.env(), s.a.id, fid))
    assert [p.status for p in progress] == ["retry"]
    row = s.saga(fid)
    assert row["attempt"] == 1 and row["error"] == "serialization_failure"
    assert row["state"] == "running" and row["claim_lock_until"] is None
    for _ in range(5):
        s.admin.execute("UPDATE sibyl.failover SET next_action_at = now() WHERE id = $1", fid)
        s.run(runner.run_saga(s.worker_db, s.env(), s.a.id, fid))
    row = s.saga(fid)
    assert row["state"] == "failed" and row["attempt"] == row["max_attempts"]
    assert s.results(fid)["error"]["code"] == "serialization_failure"


def test_backoff_doubles_and_caps() -> None:
    assert [engine.backoff(n).total_seconds() for n in (1, 2, 3, 10)] == [2, 4, 8, 60]


def test_advance_and_drive_leave_finished_sagas_alone(sworld: SWorld) -> None:
    s = sworld
    fid = _saga(s)
    s.run(runner.run_saga(s.worker_db, s.env(), s.a.id, fid))

    async def go() -> Any:
        async with s.worker_db.tenant_tx(s.a.id) as conn:
            row = await engine.load(conn, s.a.id, fid)
            assert row is not None
            _, progress = await engine.advance(conn, s.env(), s.a.id, row)
            _, driven = await engine.drive(conn, s.env(), s.a.id, fid)
            return progress.status, driven.status

    assert s.run(go()) == ("done", "done")


@pytest.mark.parametrize("name", ["failback", "handoff"])
def test_other_ticks_run_cleanly(sworld: SWorld, name: str) -> None:
    s = sworld
    tick = resolve_tick(next(x for x in LOOPS if x.name == name))
    assert tick is not None
    s.run(tick(LoopContext(name, s.worker_db, Settings(), logging.getLogger("t"))))
