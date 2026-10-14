"""Data-plane limits (API.md §2.8): per-key and per-agent token buckets, in-flight caps, 401s.

Counters are per replica in Phase 1 (no shared store). Buckets live in bounded LRU maps so a
key or agent churn cannot grow memory without limit.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass

DEFAULT_KEY_RPS = 50.0
DEFAULT_KEY_BURST = 200
UNAUTH_PER_MIN = 60
_MAX_ENTRIES = 50_000


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after_s: int

    def headers(self, name: str) -> list[tuple[str, str]]:
        out = [
            ("RateLimit-Policy", f'"{name}";q={self.limit};w=1'),
            ("RateLimit", f'"{name}";r={self.remaining};t={self.retry_after_s}'),
        ]
        if not self.allowed:
            out.append(("Retry-After", str(self.retry_after_s)))
        return out


class TokenBuckets:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._buckets: OrderedDict[Hashable, _Bucket] = OrderedDict()

    def hit(self, key: Hashable, rate: float, burst: int) -> LimitResult:
        now = self._clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(float(burst), now)
            self._buckets[key] = bucket
            if len(self._buckets) > _MAX_ENTRIES:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(key)
            bucket.tokens = min(float(burst), bucket.tokens + (now - bucket.updated) * rate)
            bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return LimitResult(True, burst, int(bucket.tokens), 0)
        wait = math.ceil((1.0 - bucket.tokens) / rate) if rate > 0 else 60
        return LimitResult(False, burst, 0, max(1, wait))


class Inflight:
    def __init__(self) -> None:
        self._counts: dict[Hashable, int] = {}

    def acquire(self, key: Hashable, limit: int | None) -> bool:
        current = self._counts.get(key, 0)
        if limit is not None and current >= limit:
            return False
        self._counts[key] = current + 1
        return True

    def release(self, key: Hashable) -> None:
        current = self._counts.get(key, 0) - 1
        if current <= 0:
            self._counts.pop(key, None)
        else:
            self._counts[key] = current

    def current(self, key: Hashable) -> int:
        return self._counts.get(key, 0)


class Limits:
    """All data-plane limiters of one replica."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.keys = TokenBuckets(clock)
        self.agents = TokenBuckets(clock)
        self.unauth = TokenBuckets(clock)
        self.inflight = Inflight()

    def key(self, key_id: Hashable) -> LimitResult:
        return self.keys.hit(key_id, DEFAULT_KEY_RPS, DEFAULT_KEY_BURST)

    def agent(self, agent_id: Hashable, rps: int, burst: int | None) -> LimitResult:
        return self.agents.hit(agent_id, float(rps), burst or rps * 2)

    def failed_auth(self, client: str) -> LimitResult:
        return self.unauth.hit(client, UNAUTH_PER_MIN / 60.0, UNAUTH_PER_MIN)
