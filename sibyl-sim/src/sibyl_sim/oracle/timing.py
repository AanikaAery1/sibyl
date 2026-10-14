"""Tick-lag scaled deadlines (B38).

The product runs on its own wall clock (R45: no clock override) and its loops sleep a full
interval *after* each tick, so under host CPU load every eval loop stretches by its own tick
time; the harness's actors, sharing the host, also send late. A catalogue deadline such as
"detect by t=120" was calibrated on an idle host. Rather than override any clock, the harness
measures how much slower the run actually was and scales the time *after the stimulus*:

    deadline = onset + (by_t - onset) x dilation + actor_late_s + loop_lag_s + data_lag_s

- ``dilation``: the worst eval loop's observed mean period over its calibrated period
  (nominal interval + ``IDLE_TICK_ALLOWANCE_S`` for the tick's own work), never below 1.
- ``actor_late_s``: p95 of how late actors sent planned arrivals before the first chaos step
  (stimulus-free, so a latency-chaos backlog never stretches its own deadline).
- ``loop_lag_s``: p95 overshoot of the harness event loop (SSE frames are stamped on arrival).
- ``data_lag_s``: p95 age of the oldest committed event the rollup has not read yet, beyond
  one rollup interval. The rollup reads only below the cluster-wide commit horizon (R60), so
  transactions held open by *other* work on a shared Postgres (a concurrent test suite) stall
  the product's data while its loops keep their cadence: every reaction is delayed by the
  same seconds, hence additive.

At idle all four are ~0 and every gate is exactly the catalogue's. Above ``MAX_DILATION`` (or
a data lag above ``MAX_DATA_LAG_S``) the run is *inconclusive* (status ``error``): the host was
too loaded to judge the product, which is reported, never passed. Every factor is written to
the run's summary.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Final

IDLE_TICK_ALLOWANCE_S: Final = 1.0  # an eval tick's own work on an idle host
MAX_DILATION: Final = 2.0  # beyond this the run cannot be judged
MAX_DATA_LAG_S: Final = 60.0  # nor beyond a minute of stalled data


def p95(values: Sequence[float]) -> float:
    """Nearest-rank 95th percentile (0 for no values)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return float(ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)])


def dilation_from(
    periods: Mapping[str, float],
    nominal: Mapping[str, float],
    allowance_s: float = IDLE_TICK_ALLOWANCE_S,
) -> float:
    """Worst observed/calibrated period ratio over the loops that have both, at least 1."""
    ratios = [
        period / (nominal[name] + allowance_s)
        for name, period in periods.items()
        if nominal.get(name, 0) > 0 and period > 0
    ]
    return round(max([1.0, *ratios]), 3)


@dataclass(frozen=True)
class Timing:
    dilation: float = 1.0
    actor_late_s: float = 0.0
    loop_lag_s: float = 0.0
    data_lag_s: float = 0.0
    periods: Mapping[str, float] = field(default_factory=dict)
    nominal: Mapping[str, float] = field(default_factory=dict)

    @property
    def slack_s(self) -> float:
        return round(self.actor_late_s + self.loop_lag_s + self.data_lag_s, 3)

    @property
    def conclusive(self) -> bool:
        return self.dilation <= MAX_DILATION and self.data_lag_s <= MAX_DATA_LAG_S

    @property
    def idle(self) -> bool:
        return self.dilation == 1.0 and self.slack_s == 0.0

    def deadline(self, by_t: float, onset: float = 0.0) -> float:
        """``by_t`` stretched after ``onset``; a deadline at or before the onset is not."""
        if by_t <= onset or self.idle:
            return by_t
        return round(onset + (by_t - onset) * self.dilation + self.slack_s, 3)

    def limit(self, seconds: float) -> float:
        """A duration measured from the onset (a time-to-detect limit), stretched."""
        if self.idle:
            return seconds
        return round(seconds * self.dilation + self.slack_s, 3)

    def describe(self) -> str:
        return (
            f"x{self.dilation:g} tick lag, +{self.slack_s:.1f} s actor/loop/data lateness"
            if not self.idle
            else "idle"
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {
            "conclusive": self.conclusive,
            "max_dilation": MAX_DILATION,
            "max_data_lag_s": MAX_DATA_LAG_S,
        }


__all__ = [
    "IDLE_TICK_ALLOWANCE_S",
    "MAX_DATA_LAG_S",
    "MAX_DILATION",
    "Timing",
    "dilation_from",
    "p95",
]
