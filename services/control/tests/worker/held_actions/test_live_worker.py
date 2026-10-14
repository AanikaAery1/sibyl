"""Lane AG-LIVE worker on PG17 (as ``sibyl_worker``): an expired hold ends its history with an
``expired`` entry, and the ``action_counters`` loop sweeps cumulative windows that ended (with a
grace period), oldest first and bounded, never a live window or another tenant's."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from sibyl_ag_gate import TRANSFER_POLICY, Gate, make_gate
from sibyl_control.worker import loops
from sibyl_control.worker.held_actions import counters, expiry
from sibyl_lane_s_world import SWorld


@pytest.fixture(scope="module")
def gate(sworld: SWorld) -> Gate:
    return make_gate(sworld.w)


def test_an_expired_hold_ends_its_history(gate: Gate, sworld: SWorld) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, TRANSFER_POLICY)
    body = gate.hold_body(agent, "live-exp", {"amount": 6000})
    held = gate.post("/held-actions", body, "keys").json()
    gate.w.admin.execute(
        "UPDATE sibyl.held_action SET expires_at = now() - interval '1 s' WHERE id = $1",
        UUID(held["id"]),
    )
    sworld.run(expiry.run_tenant(sworld.worker_db, sworld.env("held_actions:test"), gate.tenant))
    history = gate.get(f"/held-actions/{held['id']}", "operator").json()["history"]
    assert [e["kind"] for e in history] == ["requested", "expired"]
    assert history[-1]["user_id"] is None and history[-1]["reason"] == "hold timeout; default deny"


def _counter(
    gate: Gate, agent: UUID, key: str, window_s: int, age_s: int, tenant: Any = None
) -> None:
    gate.w.admin.execute(
        "INSERT INTO sibyl.action_counter (tenant_id, agent_id, counter_key, window_s,"
        " window_start, value, max_value, calls) VALUES ($1, $2, $3, $4,"
        " now() - make_interval(secs => $5), 1, 10, 1)",
        tenant or gate.tenant,
        agent,
        key,
        window_s,
        age_s,
    )


def _keys(gate: Gate, agent: UUID) -> list[str]:
    rows = gate.w.admin.fetch(
        "SELECT counter_key FROM sibyl.action_counter WHERE agent_id = $1 ORDER BY counter_key",
        agent,
    )
    return [r["counter_key"] for r in rows]


def test_the_sweep_drops_ended_windows_only(gate: Gate, sworld: SWorld) -> None:
    agent = gate.agent()
    hour, day = 3600, 86400
    _counter(gate, agent, "a-live-hour", hour, 600)  # still open
    _counter(gate, agent, "b-just-ended", hour, hour + 60)  # ended, inside the grace period
    _counter(gate, agent, "c-ended", hour, hour + counters.GRACE_S + 60)
    _counter(gate, agent, "d-live-day", day, hour * 5)
    _counter(gate, agent, "e-old-day", day, day * 3)
    swept = sworld.run(counters.sweep_tenant(sworld.worker_db, gate.tenant))
    assert swept == 2
    assert _keys(gate, agent) == ["a-live-hour", "b-just-ended", "d-live-day"]
    assert sworld.run(counters.sweep_tenant(sworld.worker_db, gate.tenant)) == 0


def test_the_sweep_is_bounded_per_tick(gate: Gate, sworld: SWorld) -> None:
    agent = gate.agent()
    for i in range(5):
        _counter(gate, agent, f"old-{i}", 60, 86400 + i)
    assert sworld.run(counters.sweep_tenant(sworld.worker_db, gate.tenant, limit=3)) == 3
    assert sworld.run(counters.sweep_tenant(sworld.worker_db, gate.tenant, limit=3)) == 2
    assert _keys(gate, agent) == []


def test_the_sweep_stays_in_its_tenant(gate: Gate, sworld: SWorld) -> None:
    other_tenant = gate.w.b.id
    other_agent = gate.w.admin.fetchval(
        "INSERT INTO sibyl.agent (tenant_id, slug, name, kind, tier, fail_mode, lifecycle)"
        " VALUES ($1, 'sweep-b', 'sweep-b', 'autonomous_agent', 3, 'closed', 'deployed')"
        " RETURNING id",
        other_tenant,
    )
    _counter(gate, other_agent, "b-old", 60, 86400, tenant=other_tenant)
    sworld.run(counters.sweep_tenant(sworld.worker_db, gate.tenant))
    assert _keys(gate, other_agent) == ["b-old"]
    sworld.run(counters.sweep_tenant(sworld.worker_db, other_tenant))
    assert _keys(gate, other_agent) == []


def test_the_tick_sweeps_every_tenant(gate: Gate, sworld: SWorld) -> None:
    agent = gate.agent()
    _counter(gate, agent, "tick-old", 60, 86400)
    ctx = loops.LoopContext("action_counters", sworld.worker_db, sworld.w.settings, counters.log)
    sworld.run(counters.tick(ctx))
    assert _keys(gate, agent) == []


def test_the_counter_loop_is_registered() -> None:
    spec = next(s for s in loops.LOOPS if s.name == "action_counters")
    assert loops.resolve_tick(spec) is counters.tick and spec.interval_s == 3600
