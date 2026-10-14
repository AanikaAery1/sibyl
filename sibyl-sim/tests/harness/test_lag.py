"""B38: scenario deadlines scale with measured tick lag, never with a product clock override.

At idle the dilation is 1 and every deadline is the catalogue's own; under host load the
product's eval loops stretch (each sleeps a full interval after a longer tick) and actors send
late, so deadlines after the stimulus scale by the measured factor. Past the cap the run cannot
be judged at all: it is inconclusive, never a pass.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sibyl_sim.harness.clock import RunClock
from sibyl_sim.harness.lag import LagMeter
from sibyl_sim.oracle.timing import (
    IDLE_TICK_ALLOWANCE_S,
    MAX_DILATION,
    Timing,
    dilation_from,
    p95,
)


def test_idle_timing_leaves_every_deadline_alone() -> None:
    t = Timing()
    assert t.dilation == 1.0 and t.conclusive
    assert t.deadline(120.0, onset=30.0) == 120.0
    assert t.limit(60.0) == 60.0


def test_deadlines_scale_only_after_the_stimulus() -> None:
    t = Timing(dilation=1.5, actor_late_s=2.0, loop_lag_s=0.5)
    # 30 s of pre-onset traffic are not product reaction time; the 90 s after the onset are
    assert t.deadline(120.0, onset=30.0) == 30.0 + 90.0 * 1.5 + 2.5
    assert t.limit(60.0) == 60.0 * 1.5 + 2.5
    # a deadline at or before the onset (a leading alert's window) is not stretched
    assert t.deadline(25.0, onset=30.0) == 25.0


def test_dilation_is_the_worst_eval_loop_against_its_calibrated_period() -> None:
    nominal = {"rollup": 10.0, "scoring": 10.0}
    # idle: the tick's own work stays inside the allowance
    assert dilation_from({"rollup": 10.4, "scoring": 10.9}, nominal) == 1.0
    loaded = dilation_from({"rollup": 12.0, "scoring": 16.5}, nominal)
    assert loaded == round(16.5 / (10.0 + IDLE_TICK_ALLOWANCE_S), 3)
    # loops without a nominal interval or without a measurement do not count
    assert dilation_from({"saga": 99.0}, nominal) == 1.0
    assert dilation_from({}, {}) == 1.0


def test_past_the_cap_a_run_is_inconclusive() -> None:
    assert Timing(dilation=MAX_DILATION).conclusive
    assert not Timing(dilation=MAX_DILATION + 0.01).conclusive


def test_p95() -> None:
    assert p95([]) == 0.0
    assert p95([0.0] * 95 + [9.0] * 5) == 0.0  # nearest rank: the 95th of 100 is a zero
    assert p95([0.0] * 94 + [9.0] * 6) == 9.0
    assert p95([1.0, 2.0, 3.0]) == 3.0


class FakeStack:
    """`loop_status()` runs advance on a stretched period; `loop_intervals()` the nominal."""

    def __init__(self, period_s: float) -> None:
        self.period_s = period_s
        self.t0 = asyncio.get_running_loop().time()

    def loop_status(self) -> dict[str, Any]:
        runs = int((asyncio.get_running_loop().time() - self.t0) / self.period_s)
        return {"scoring": {"runs": runs}, "rollup": {"runs": runs}}

    def loop_intervals(self) -> dict[str, float]:
        return {"scoring": 0.05, "rollup": 0.05}


async def test_lag_meter_measures_a_stretched_product_loop() -> None:
    stack = FakeStack(period_s=0.15)  # three times its 0.05 s interval
    meter = LagMeter(stack, RunClock(), probe_s=0.01, sample_s=0.05, allowance_s=0.0)
    stop = asyncio.Event()
    task = asyncio.create_task(meter.run(stop))
    await asyncio.sleep(1.0)
    stop.set()
    await task
    timing = meter.result(actor_late=[0.0, 0.2, 0.4])
    assert 2.5 <= timing.dilation <= 3.5, timing
    assert timing.periods["scoring"] == pytest.approx(0.15, rel=0.2)
    assert timing.actor_late_s == 0.4
    assert timing.loop_lag_s >= 0.0


async def test_lag_meter_without_loop_status_measures_only_harness_lag() -> None:
    class Remote:  # a compose stack: no in-process loops to read
        def loop_status(self) -> dict[str, Any]:
            return {}

    meter = LagMeter(Remote(), RunClock(), probe_s=0.01, sample_s=0.05)
    stop = asyncio.Event()
    task = asyncio.create_task(meter.run(stop))
    await asyncio.sleep(0.2)
    stop.set()
    await task
    timing = meter.result(actor_late=[])
    assert timing.dilation == 1.0 and timing.periods == {}
    assert timing.data_lag_s == 0.0


def test_data_lag_is_added_after_the_onset_and_capped() -> None:
    """The rollup reads below the cluster-wide commit horizon (R60): a stalled horizon delays
    every reaction by the same seconds, so its excess is additive, not a dilation."""
    from sibyl_sim.oracle.timing import MAX_DATA_LAG_S

    t = Timing(data_lag_s=12.0)
    assert t.deadline(120.0, onset=30.0) == 132.0 and t.limit(60.0) == 72.0
    assert t.conclusive and not Timing(data_lag_s=MAX_DATA_LAG_S + 1).conclusive


async def test_lag_meter_measures_rollup_data_lag_beyond_its_interval() -> None:
    class Stalled(FakeStack):
        def __init__(self, lag: float) -> None:
            super().__init__(period_s=0.05)
            self.lag = lag

        async def data_lag_s(self) -> float | None:
            return self.lag

    for lag, excess in ((0.04, 0.0), (0.5, 0.45)):  # nominal rollup interval 0.05 s
        meter = LagMeter(Stalled(lag), RunClock(), probe_s=0.01, sample_s=0.02, allowance_s=0.0)
        stop = asyncio.Event()
        task = asyncio.create_task(meter.run(stop))
        await asyncio.sleep(0.2)
        stop.set()
        await task
        assert meter.result(actor_late=[]).data_lag_s == pytest.approx(excess), lag
