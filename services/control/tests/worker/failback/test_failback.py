"""Failback on PG17: probe → active in one step (Phase 1), ramp and breach behind the flag."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from sibyl_control.core.settings import Settings
from sibyl_control.worker import failback
from sibyl_control.worker.failback import probe
from sibyl_control.worker.loops import LoopContext
from sibyl_control.worker.saga import runner
from sibyl_lane_s_world import SWorld


def _failed_over(s: SWorld) -> dict[str, Any]:
    p, p2 = s.provider(), s.provider()
    agent = s.agent(tier=2, model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent, snapshot_ago_s=600)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    assert s.routing(agent)["state"] == "failed_over"
    return {"agent": agent, "fid": fid, "p": p}


def _age(s: SWorld, agent: Any, minutes: int = 6) -> None:
    s.admin.execute(
        "UPDATE sibyl.routing_state SET state_since = now() - make_interval(mins => $2)"
        " WHERE agent_id = $1",
        agent,
        minutes,
    )


def _run(s: SWorld, *, ramp: bool = False) -> probe.FailbackRun:
    env = s.env("failback:test", failback_ramp=ramp)
    return s.run(probe.run_tenant(s.worker_db, env, s.a.id))


def test_probe_waits_five_minutes_then_returns_to_primary(sworld: SWorld) -> None:
    s = sworld
    f = _failed_over(s)
    assert _run(s).probed == []  # failed over < 5 min
    _age(s, f["agent"])
    head = s.head(s.a)
    run = _run(s)
    assert len(run.probed) == 1 and run.completed == []
    rs = s.routing(f["agent"])
    assert rs["state"] == "active" and rs["target_kind"] == "primary"
    triggers = [
        r["trigger"]
        for r in s.rows(
            "SELECT trigger FROM sibyl.routing_transition WHERE tenant_id = $1 AND failover_id = $2"
            " ORDER BY routing_version",
            s.a.id,
            run.probed[0],
        )
    ]
    assert triggers == ["failback_probe", "canary"]
    saga = s.saga(run.probed[0])
    assert saga["kind"] == "failback" and saga["state"] == "done"
    assert "failback.completed" in s.audit_actions(s.a, head)
    label = s.one(
        "SELECT value FROM sibyl.label WHERE tenant_id = $1 AND kind = 'failover_outcome'"
        " AND agent_id = $2",
        s.a.id,
        f["agent"],
    )
    assert label is not None


def test_unhealthy_primary_blocks_the_probe(sworld: SWorld) -> None:
    s = sworld
    f = _failed_over(s)
    _age(s, f["agent"])
    s.provider_status(f["p"], "partial_outage", ago_s=60)
    assert _run(s).probed == []
    assert s.routing(f["agent"])["state"] == "failed_over"
    g = _failed_over(s)
    _age(s, g["agent"])
    s.snapshot(g["agent"], "degraded", ago_s=30)
    assert _run(s).probed == []


def test_operator_failing_back_is_completed_by_the_loop(sworld: SWorld) -> None:
    s = sworld
    f = _failed_over(s)
    resp = s.post(
        "owner",
        f"/incidents/{f['fid']}/actions",
        {"action": "fail_back", "reason": "provider recovered, failing back"},
    )
    assert resp.status_code == 200, resp.text
    assert s.routing(f["agent"])["state"] == "failing_back"
    run = _run(s)
    assert len(run.completed) == 1
    assert s.routing(f["agent"])["state"] == "active"


def test_ramp_flag_ramps_and_breach_reverts_with_backoff(sworld: SWorld) -> None:
    s = sworld
    f = _failed_over(s)
    _age(s, f["agent"])
    run = _run(s, ramp=True)
    fb = run.probed[0]
    assert s.routing(f["agent"])["canary_pct"] == 10
    s.admin.execute(
        "UPDATE sibyl.failover SET step_results = jsonb_set(step_results, '{ramp,since}',"
        " to_jsonb((now() - interval '6 minutes')::text)) WHERE id = $1",
        fb,
    )
    _run(s, ramp=True)
    assert s.routing(f["agent"])["canary_pct"] == 25
    s.snapshot(f["agent"], "failed")
    run = _run(s, ramp=True)
    assert run.reverted == [fb]
    assert s.routing(f["agent"])["state"] == "failed_over"
    fbinfo = s.results(f["fid"])["failback"]
    assert fbinfo["reverts"] == 1 and fbinfo["suspended"] is False
    assert s.saga(fb)["error"] == "canary_breach"
    _age(s, f["agent"])
    assert _run(s, ramp=True).probed == []  # backoff: next probe in 10 minutes


@pytest.mark.parametrize("ramp", [False, True])
def test_tick_reads_the_ramp_from_settings(
    sworld: SWorld, monkeypatch: pytest.MonkeyPatch, ramp: bool
) -> None:
    """The loop threads ``ctx.settings.failback_ramp``; ``SIBYL_FAILBACK_RAMP`` is not read."""
    monkeypatch.setenv("SIBYL_FAILBACK_RAMP", "0" if ramp else "1")
    s = sworld
    f = _failed_over(s)
    _age(s, f["agent"])
    ctx = LoopContext("failback", s.worker_db, Settings(failback_ramp=ramp), logging.getLogger())
    s.run(failback.tick(ctx))
    rs = s.routing(f["agent"])
    if ramp:
        assert (rs["state"], rs["canary_pct"]) == ("failing_back", 10)
    else:
        assert rs["state"] == "active"


def test_backoff_doubles_and_caps() -> None:
    assert [probe.probe_backoff(n).total_seconds() / 60 for n in range(5)] == [5, 10, 20, 40, 60]
