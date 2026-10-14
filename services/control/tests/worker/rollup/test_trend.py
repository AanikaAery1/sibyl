"""EWMA/CUSUM trend state: pure math and the once-per-closed-bucket guard."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from sibyl_control.worker.rollup.pipeline import rollup_tenant
from sibyl_control.worker.rollup.trend import TrendState, advance, advance_trend_state
from sibyl_h_testkit import Kit, calls, settle

T0 = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


def step(state: TrendState, x: float, i: int, base: float | None = 0.01) -> TrendState:
    return advance(
        state,
        x,
        T0 + timedelta(minutes=5 * i),
        lam=0.3,
        k=0.5,
        h=5,
        baseline=base,
        alarm_at=T0 + timedelta(minutes=5 * i),
    )


def test_ewma_and_variance() -> None:
    s = step(TrendState(), 0.1, 0)
    assert s.ewma == 0.1 and s.ewma_var == 0 and s.samples == 1
    s2 = step(s, 0.2, 1)
    assert s2.ewma == pytest.approx(0.13)
    assert s2.ewma_var == pytest.approx(0.7 * 0.3 * 0.01)


def test_cusum_alarms_on_a_sustained_step_and_clears() -> None:
    s = TrendState()
    for i in range(6):
        s = step(s, 0.01, i)
    assert s.cusum_alarm_at is None
    i = 6
    while s.cusum_alarm_at is None and i < 20:
        s = step(s, 0.2, i)
        i += 1
    assert s.cusum_pos > 5 and s.cusum_alarm_at is not None and i <= 12
    first_alarm = s.cusum_alarm_at
    s = step(s, 0.2, i)
    assert s.cusum_alarm_at == first_alarm, "alarm time is the first crossing"
    for j in range(i + 1, i + 40):
        s = step(s, 0.01, j)
    assert s.cusum_alarm_at is None, "the alarm clears once both sums fall below h"


def test_without_baseline_the_prior_level_is_used() -> None:
    s = step(TrendState(), 5.0, 0, base=None)
    assert s.cusum_pos == 0 and s.cusum_neg == 0


def _roll(kit: Kit, tenant: UUID, expect: int) -> None:
    async def step(conn: Any) -> Any:
        res = await rollup_tenant(conn, tenant)
        await advance_trend_state(conn, tenant, res.closed_5m)
        return res

    settle(kit, tenant, expect, step)


def test_trend_state_advances_once_per_closed_bucket(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    now = datetime.now(UTC)
    b0 = now.replace(second=0, microsecond=0) - timedelta(minutes=30)
    b0 = b0 - timedelta(minutes=b0.minute % 5)
    for i in range(3):
        kit.events(t, calls(a, b0 + timedelta(minutes=5 * i), 10, errors=i))
    _roll(kit, t, 30)
    rows = {
        r["metric"]: r
        for r in kit.q("SELECT * FROM sibyl.agent_trend_state WHERE tenant_id = $1", t)
    }
    assert rows["error_rate"]["samples"] == 3
    assert rows["error_rate"]["last_bucket"] == b0 + timedelta(minutes=10)
    # a late event reopens the middle bucket: the rollup changes, the trend state does not
    kit.events(t, calls(a, b0 + timedelta(minutes=5), 5, errors=5))
    _roll(kit, t, 5)
    again = kit.q(
        "SELECT samples, ewma FROM sibyl.agent_trend_state WHERE tenant_id = $1 "
        "AND metric = 'error_rate'",
        t,
    )[0]
    assert again["samples"] == 3 and again["ewma"] == rows["error_rate"]["ewma"]
    five = kit.q(
        "SELECT request_count FROM sibyl.agent_metrics_5m WHERE tenant_id = $1 AND "
        "bucket_start = $2",
        t,
        b0 + timedelta(minutes=5),
    )
    assert five[0]["request_count"] == 15
