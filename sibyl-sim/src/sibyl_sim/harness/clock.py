"""Run clock: sim seconds since scenario start, wall time at speed 1 (R45: no product clock
override; the product always runs on its own wall clock)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class RunClock:
    started_wall: float = field(default_factory=time.time)
    _t0: float = field(default_factory=time.monotonic)

    def now(self) -> float:
        return round(time.monotonic() - self._t0, 3)

    def wall(self, t: float) -> float:
        return self.started_wall + t

    def sim(self, wall: float) -> float:
        return round(wall - self.started_wall, 3)

    async def until(self, t: float) -> None:
        delay = t - self.now()
        if delay > 0:
            await asyncio.sleep(delay)
