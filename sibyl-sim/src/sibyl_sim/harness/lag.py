"""Measure a run's tick lag (B38) for `oracle.timing.Timing`.

Two probes run beside the actors for the whole scenario:

- the harness event loop: sleep ``probe_s`` and record the overshoot;
- the product's eval loops (in-process stacks only): sample ``loop_status()[name]["runs"]``
  every ``sample_s`` and take the mean period between the first and the last sample. The
  nominal intervals come from ``stack.loop_intervals()``; a stack without it (compose, remote)
  contributes no dilation, only the harness-side lateness;
- the product's data (stacks with ``async data_lag_s()``): the age of the oldest committed
  event the rollup has not read yet, sampled every ``sample_s``; its p95 beyond one rollup
  interval (plus the allowance) is the run's data lag.

Actor lateness is passed in by the runner at the end (each actor records how late it sent each
planned arrival). Reading counters and sleeping are the only things this module does: it never
touches a product clock or a product table.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from ..oracle.timing import IDLE_TICK_ALLOWANCE_S, Timing, dilation_from, p95
from .clock import RunClock

EVAL_LOOPS = ("rollup", "scoring")
MIN_RUNS = 3  # fewer observed ticks than this measure nothing


class _Loops(Protocol):
    def loop_status(self) -> dict[str, Any]: ...


class LagMeter:
    def __init__(
        self,
        stack: _Loops,
        clock: RunClock,
        *,
        probe_s: float = 0.5,
        sample_s: float = 5.0,
        allowance_s: float = IDLE_TICK_ALLOWANCE_S,
        loops: Sequence[str] = EVAL_LOOPS,
    ) -> None:
        self.stack, self.clock = stack, clock
        self.probe_s, self.sample_s, self.allowance_s = probe_s, sample_s, allowance_s
        self.loops = tuple(loops)
        intervals = getattr(stack, "loop_intervals", None)
        nominal: Mapping[str, float] = intervals() if callable(intervals) else {}
        self.nominal = {k: float(v) for k, v in nominal.items() if k in self.loops}
        self.overshoot: list[float] = []
        self.data_lag: list[float] = []
        self._first: dict[str, tuple[float, int]] = {}
        self._last: dict[str, tuple[float, int]] = {}

    def _sample(self, now: float) -> None:
        status = self.stack.loop_status() or {}
        for name in self.nominal:
            runs = (status.get(name) or {}).get("runs")
            if isinstance(runs, int):
                self._first.setdefault(name, (now, runs))
                self._last[name] = (now, runs)

    async def _sample_data(self) -> None:
        probe = getattr(self.stack, "data_lag_s", None)
        if not callable(probe):
            return
        try:
            value = await probe()
        except Exception:  # a probe failure measures nothing; it never fails the run
            return
        if value is not None:
            self.data_lag.append(float(value))

    async def run(self, stop: asyncio.Event) -> None:
        loop = asyncio.get_running_loop()
        next_sample = loop.time()
        while not stop.is_set():
            before = loop.time()
            if before >= next_sample:
                self._sample(before)
                await self._sample_data()
                before = loop.time()
                next_sample = before + self.sample_s
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.probe_s)
            if not stop.is_set():
                self.overshoot.append(max(0.0, loop.time() - before - self.probe_s))
        self._sample(loop.time())

    def periods(self) -> dict[str, float]:
        out = {}
        for name, (t0, r0) in self._first.items():
            t1, r1 = self._last[name]
            if r1 - r0 >= MIN_RUNS:
                out[name] = round((t1 - t0) / (r1 - r0), 3)
        return out

    def data_lag_excess(self) -> float:
        """p95 unread-event age beyond one rollup interval plus the allowance."""
        if not self.data_lag:
            return 0.0
        idle = (self.nominal.get("rollup") or 0.0) + self.allowance_s
        return round(max(0.0, p95(self.data_lag) - idle), 3)

    def result(self, actor_late: Sequence[float]) -> Timing:
        periods = self.periods()
        return Timing(
            dilation=dilation_from(periods, self.nominal, self.allowance_s),
            actor_late_s=round(p95(actor_late), 3),
            loop_lag_s=round(p95(self.overshoot), 3),
            data_lag_s=self.data_lag_excess(),
            periods=periods,
            nominal=dict(self.nominal),
        )


__all__ = ["EVAL_LOOPS", "LagMeter"]
