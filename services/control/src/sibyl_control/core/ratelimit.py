"""Token-bucket rate limiting (API.md §2.8) with IETF RateLimit / RateLimit-Policy headers.

Counters are per replica in Phase 1 (in-memory). The ``RateLimiter`` protocol is the seam for a
shared store later; callers build the bucket key (principal, key, tenant or IP) themselves.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from sibyl_schemas import values as sv

from .problems import ProblemError


@dataclass(frozen=True)
class RatePolicy:
    """``quota`` requests per ``window_s``; bucket capacity = ``burst`` (default ``quota``)."""

    name: str
    quota: int
    window_s: float
    burst: int | None = None

    @property
    def capacity(self) -> int:
        return self.burst if self.burst is not None else self.quota

    @property
    def refill_per_s(self) -> float:
        return self.quota / self.window_s


# Policy names are referenced by the OpenAPI ``x-sibyl-rate-limit`` extension; the table is
# ``sibyl_schemas.values.RATE_POLICY_SPECS`` (API §2.8, G0 single source).
POLICIES: Mapping[str, RatePolicy] = MappingProxyType(
    {
        name: RatePolicy(spec.name, spec.quota, spec.window_s, spec.burst)
        for name, spec in sv.RATE_POLICY_SPECS.items()
    }
)


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    policy: RatePolicy
    remaining: int
    reset_s: int
    retry_after_s: int

    def headers(self) -> dict[str, str]:
        p = self.policy
        out = {
            "RateLimit-Policy": f'"{p.name}";q={p.quota};w={int(p.window_s)}',
            "RateLimit": f'"{p.name}";r={self.remaining};t={self.reset_s}',
        }
        if not self.allowed:
            out["Retry-After"] = str(self.retry_after_s)
        return out


class RateLimiter(Protocol):
    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision: ...

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        """Would one more hit be allowed? Consumes nothing and creates no bucket."""
        ...


@dataclass
class _Bucket:
    tokens: float
    updated: float
    policy: RatePolicy

    def refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.policy.capacity, self.tokens + elapsed * self.policy.refill_per_s)
        self.updated = now

    def is_full(self, now: float) -> bool:
        elapsed = max(0.0, now - self.updated)
        return self.tokens + elapsed * self.policy.refill_per_s >= self.policy.capacity


_EVICTION_SCAN = 64


def _decision(bucket: _Bucket, allowed: bool, cost: int) -> RateDecision:
    policy = bucket.policy
    deficit = max(0.0, cost - bucket.tokens)
    retry = math.ceil(deficit / policy.refill_per_s) if not allowed else 0
    to_full = (policy.capacity - bucket.tokens) / policy.refill_per_s
    return RateDecision(
        allowed=allowed,
        policy=policy,
        remaining=int(bucket.tokens),
        reset_s=math.ceil(to_full),
        retry_after_s=retry,
    )


class InMemoryRateLimiter:
    """Per-process token buckets with bounded memory.

    When the table is full, only buckets that have refilled completely are evicted (they carry
    no state). If none can go, new keys share one coarse overflow bucket per policy, so spraying
    fresh keys can neither grow memory nor reset a throttled bucket (code review L4).
    """

    def __init__(
        self, clock: Callable[[], float] = time.monotonic, max_keys: int = 100_000
    ) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: OrderedDict[tuple[str, str], _Bucket] = OrderedDict()
        self._overflow: dict[str, _Bucket] = {}

    def __len__(self) -> int:
        return len(self._buckets)

    def _evict_full(self, now: float) -> None:
        for _ in range(min(_EVICTION_SCAN, len(self._buckets))):
            if len(self._buckets) < self._max_keys:
                return
            slot, bucket = next(iter(self._buckets.items()))
            if bucket.is_full(now):
                del self._buckets[slot]
            else:
                self._buckets.move_to_end(slot)

    def _bucket(self, key: str, policy: RatePolicy, now: float) -> _Bucket:
        slot = (policy.name, key)
        bucket = self._buckets.get(slot)
        if bucket is not None:
            self._buckets.move_to_end(slot)
            return bucket
        if len(self._buckets) >= self._max_keys:
            self._evict_full(now)
        if len(self._buckets) >= self._max_keys:
            overflow = self._overflow.get(policy.name)
            if overflow is None:
                overflow = self._overflow[policy.name] = _Bucket(
                    float(policy.capacity), now, policy
                )
            return overflow
        bucket = self._buckets[slot] = _Bucket(float(policy.capacity), now, policy)
        return bucket

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        if cost < 1:
            raise ValueError("cost must be >= 1")
        if cost > policy.capacity:
            raise ValueError(
                f"cost {cost} exceeds the bucket capacity {policy.capacity} of {policy.name!r}:"
                " the request could never be allowed"
            )
        now = self._clock()
        bucket = self._bucket(key, policy, now)
        bucket.refill(now)
        allowed = bucket.tokens >= cost
        if allowed:
            bucket.tokens -= cost
        return _decision(bucket, allowed, cost)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        now = self._clock()
        bucket = self._buckets.get((policy.name, key))
        if bucket is None:
            return _decision(_Bucket(float(policy.capacity), now, policy), True, 1)
        probe = _Bucket(bucket.tokens, bucket.updated, policy)
        probe.refill(now)
        return _decision(probe, probe.tokens >= 1, 1)


def enforce(decision: RateDecision, code: str = "rate_limited") -> dict[str, str]:
    """Return the headers to attach, or raise 429 with ``Retry-After``."""
    headers = decision.headers()
    if not decision.allowed:
        raise ProblemError(
            code,
            extensions={"retry_after_s": decision.retry_after_s},
            headers=headers,
        )
    return headers
