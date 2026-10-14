"""Backpressure (API.md §4.2, T5): per-tenant event bucket, per-key batch bucket, and a
process-wide saturation limiter. Every 429 carries ``Retry-After`` and ``X-Sibyl-Backpressure``
so the SDK keeps the batch and retries exactly when told.
"""

from __future__ import annotations

import math
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from ..core.problems import ProblemError
from ..core.ratelimit import RateLimiter, RatePolicy
from .config import BACKPRESSURE_HEADER, IngestConfig


def backpressure(code: str, retry_after_s: int, detail: str) -> ProblemError:
    return ProblemError(
        code,
        detail,
        extensions={"retry_after_s": retry_after_s},
        headers={"Retry-After": str(retry_after_s), BACKPRESSURE_HEADER: code},
    )


class Backpressure:
    def __init__(self, limiter: RateLimiter, cfg: IngestConfig) -> None:
        self._limiter = limiter
        self._cfg = cfg
        self.inflight = 0

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        if self.inflight >= self._cfg.max_inflight:
            raise backpressure("ingest_saturated", 1, "ingest is saturated; retry shortly")
        self.inflight += 1
        try:
            yield
        finally:
            self.inflight -= 1

    async def key(self, key_id: UUID) -> None:
        n = self._cfg.key_batches_per_s
        policy = RatePolicy("ingest_key_batches", n, 1, n)
        decision = await self._limiter.hit(f"key:{key_id}", policy)
        if not decision.allowed:
            raise ProblemError(
                "rate_limited",
                f"at most {n} batches per second per key",
                extensions={"retry_after_s": max(1, decision.retry_after_s)},
                headers={"Retry-After": str(max(1, decision.retry_after_s))},
            )

    async def tenant(self, tenant_id: UUID, events_per_s: float, burst: int, cost: int) -> None:
        if cost <= 0:
            return
        policy = RatePolicy(
            "ingest_tenant_events", max(1, math.ceil(events_per_s)), 1, max(1, burst)
        )
        decision = await self._limiter.hit(
            f"tenant:{tenant_id}", policy, min(cost, policy.capacity)
        )
        if not decision.allowed:
            retry = min(self._cfg.tenant_retry_after_max_s, max(1, decision.retry_after_s))
            raise backpressure("tenant_rate_limit", retry, "tenant ingest rate exceeded")
