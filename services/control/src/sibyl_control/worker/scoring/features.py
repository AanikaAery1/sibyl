"""Engine inputs: windowed counters and statics for one agent (ML.md §2).

Everything here is computed from Postgres aggregates by ``store.py``; this module is pure so the
engine can be replayed offline. ``None`` means "not computable", never zero.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime
from types import MappingProxyType
from typing import Any
from uuid import UUID

HIST_BUCKETS = 40
ZERO_HIST: tuple[int, ...] = (0,) * HIST_BUCKETS

COUNTERS: tuple[str, ...] = (
    "request_count",
    "error_count",
    "timeout_count",
    "rate_limit_count",
    "server_error_count",
    "blocked_count",
    "inline_fallback_count",
    "breaker_open_count",
    "tool_call_count",
    "late_count",
    "policy_stale_count",
    "tokens_in",
    "tokens_out",
    "cost_usd",
    "retry_count",
    "finish_length_count",
    "finish_tool_calls_count",
    "refusal_count",
    "empty_output_count",
    "tool_error_count",
    "tool_schema_invalid_count",
    "output_chars_sum",
    "tool_seq_hash_distinct",
)

_SMALL = re.compile(r"mini|haiku|flash|8b", re.IGNORECASE)
_REASONING = re.compile(r"^o[1-9]|reasoning|thinking|(^|[-_])r1($|[-_])", re.IGNORECASE)


def model_class(model: str | None) -> str:
    """Model class for latency thresholds (ML.md §2.5): small, reasoning or large."""
    if not model:
        return "large"
    if _REASONING.search(model):
        return "reasoning"
    if _SMALL.search(model):
        return "small"
    return "large"


def hist_bucket(ms: float | None) -> int:
    """Python twin of ``sibyl.hist_bucket``: 40 log-spaced buckets, e^(i/3) ms."""
    if ms is None or ms < 1:
        return 0
    return min(HIST_BUCKETS - 1, max(0, math.floor(3 * math.log(ms))))


def latency_hist(values: Iterable[float]) -> tuple[int, ...]:
    hist = [0] * HIST_BUCKETS
    for value in values:
        hist[hist_bucket(value)] += 1
    return tuple(hist)


def hist_add(a: Iterable[int], b: Iterable[int]) -> tuple[int, ...]:
    return tuple(x + y for x, y in zip(a, b, strict=True))


def hist_quantile(hist: Iterable[int], q: float) -> float | None:
    """Python twin of ``sibyl.hist_quantile`` (bucket midpoint on the log scale)."""
    counts = list(hist)
    total = sum(counts)
    if total == 0:
        return None
    running = 0
    for i, count in enumerate(counts):
        running += count
        if running >= q * total:
            return float(round(math.exp((i + 0.5) / 3.0)))
    return float(round(math.exp((len(counts) - 0.5) / 3.0)))


@dataclass(frozen=True)
class WindowStats:
    """Sums over every (provider, model) row of one agent in one window."""

    request_count: int = 0
    error_count: int = 0
    timeout_count: int = 0
    rate_limit_count: int = 0
    server_error_count: int = 0
    blocked_count: int = 0
    inline_fallback_count: int = 0
    breaker_open_count: int = 0
    tool_call_count: int = 0
    late_count: int = 0
    policy_stale_count: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    retry_count: int = 0
    finish_length_count: int = 0
    finish_tool_calls_count: int = 0
    refusal_count: int = 0
    empty_output_count: int = 0
    tool_error_count: int = 0
    tool_schema_invalid_count: int = 0
    output_chars_sum: int = 0
    tool_seq_hash_distinct: int = 0
    latency_hist: tuple[int, ...] = ZERO_HIST
    ratelimit_headroom_min: float | None = None

    def ratio(self, numerator: str, denominator: str = "request_count") -> float | None:
        den = getattr(self, denominator)
        if not den:
            return None
        return float(getattr(self, numerator)) / float(den)

    @property
    def p95_ms(self) -> float | None:
        return hist_quantile(self.latency_hist, 0.95)

    def merge(self, other: WindowStats) -> WindowStats:
        values: dict[str, Any] = {c: getattr(self, c) + getattr(other, c) for c in COUNTERS}
        values["latency_hist"] = hist_add(self.latency_hist, other.latency_hist)
        heads = [
            h for h in (self.ratelimit_headroom_min, other.ratelimit_headroom_min) if h is not None
        ]
        values["ratelimit_headroom_min"] = min(heads) if heads else None
        return WindowStats(**values)

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> WindowStats:
        values: dict[str, Any] = {}
        for f in fields(cls):
            if f.name not in row or row[f.name] is None:
                continue
            value = row[f.name]
            if f.name == "latency_hist":
                value = tuple(int(x) for x in value)
            elif f.name in ("cost_usd", "ratelimit_headroom_min"):
                value = float(value)
            else:
                value = int(value)
            values[f.name] = value
        return cls(**values)

    def summary(self) -> dict[str, float | None]:
        """``grains.5m`` feature keys for the FeatureSnapshot summary (≤ 2 KB)."""
        return {
            "request_count": float(self.request_count),
            "error_rate": self.ratio("error_count"),
            "error_rate_5xx": self.ratio("server_error_count"),
            "error_rate_timeout": self.ratio("timeout_count"),
            "error_rate_429": self.ratio("rate_limit_count"),
            "error_rate_blocked": self.ratio("blocked_count"),
            "latency_p95_ms": self.p95_ms,
            "finish_length_ratio": self.ratio("finish_length_count"),
            "finish_content_filter_ratio": self.ratio("refusal_count"),
            "empty_output_ratio": self.ratio("empty_output_count"),
            "schema_validation_fail_ratio": self.ratio(
                "tool_schema_invalid_count", "tool_call_count"
            ),
            "tool_error_rate": self.ratio("tool_error_count", "tool_call_count"),
            "tool_call_count": float(self.tool_call_count),
            "inline_fallback_ratio": self.ratio("inline_fallback_count"),
            "breaker_open_ratio": self.ratio("breaker_open_count"),
            "ratelimit_headroom_min": self.ratelimit_headroom_min,
            "cost_usd": self.cost_usd,
            "late_ratio": self.ratio("late_count"),
        }


_NO_BASELINES: Mapping[str, float] = MappingProxyType({})


@dataclass(frozen=True)
class AgentInputs:
    """What one tick knows about one agent (the in-memory FeatureSnapshot)."""

    agent_id: UUID
    tier: int
    created_at: datetime
    w5: WindowStats
    w1: WindowStats
    provider: str | None = None
    provider_id: UUID | None = None
    model: str | None = None
    model_class: str = "large"
    kind: str = "autonomous_agent"
    consecutive_errors: int = 0
    request_count_1h: int = 0
    error_count_1h: int = 0  # failed calls among ``request_count_1h`` (cold-start proof)
    active_minutes_1h: int = 0
    provider_status: str | None = None
    provider_status_age_s: float | None = None
    provider_error_rate_fleet: float | None = None
    spend_ratio: float | None = None
    has_plan: bool = False
    cadence_s: int | None = None
    last_request_at: datetime | None = None
    routing_state: str = "active"
    policy_version: int = 0
    baselines: Mapping[str, float] = field(default_factory=lambda: _NO_BASELINES)
    baseline_ref: str = "seed/v1"
    coverage: float = 1.0
    rollup_lag_s: float = 0.0
    business_process_id: UUID | None = None
    routing_transitions_10m: int = 0
