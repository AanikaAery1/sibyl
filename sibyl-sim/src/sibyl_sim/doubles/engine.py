"""Deterministic decision engine for one double.

Every request draws exactly `DRAWS` uniforms from the double's seeded `random.Random`, in a
fixed order, whatever the knobs say. Identical seed + identical request sequence therefore
gives identical decisions, and turning one knob never shifts another knob's outcomes.
"""

from __future__ import annotations

import math
import random
import threading
import zlib
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from sibyl_sim.doubles.knobs import Knobs, Latency

Behaviour = Literal["normal", "refusal", "truncation", "schema_failure", "tool_loop"]
DRAWS: Final = 8
LOG_SIZE: Final = 1000
Clock = Callable[[], float]


@dataclass(frozen=True)
class Decision:
    seq: int
    status: int
    error_code: str | None
    latency_ms: float
    behaviour: Behaviour
    headers: dict[str, str]
    knobs: Knobs = field(repr=False)


def latency_ms(latency: Latency, u1: float, u2: float) -> float:
    if latency.dist == "fixed":
        return latency.ms
    if latency.dist == "uniform":
        return latency.min_ms + (latency.max_ms - latency.min_ms) * u1
    z = math.sqrt(-2.0 * math.log(max(u1, 1e-12))) * math.cos(2.0 * math.pi * u2)  # Box-Muller
    if latency.dist == "normal":
        return max(0.0, latency.mean_ms + latency.stddev_ms * z)
    return latency.median_ms * math.exp(latency.sigma * z)


class Double:
    """One provider double: knobs, seeded RNG, ramp clock, outage history, ground truth."""

    def __init__(
        self, name: str, models: tuple[str, ...], *, seed: int, clock: Clock, provider: str
    ) -> None:
        self.name = name
        self.provider = provider
        self.models = models
        self.clock = clock
        self._lock = threading.Lock()
        self.reset(seed)

    def reset(self, seed: int, knobs: Knobs | None = None) -> None:
        with self._lock:
            self.seed = seed
            self._rng = random.Random(seed ^ zlib.crc32(self.name.encode()))  # noqa: S311
            self.knobs = knobs or Knobs()
            self._seq = 0
            self.ramp_started_at: float | None = self.clock() if self.knobs.ramp else None
            self.outage_history: list[tuple[float, bool]] = [(self.clock(), self.knobs.outage)]
            self.stats: Counter[str] = Counter()
            self.tokens_in = 0
            self.tokens_out = 0
            self.cost_usd = 0.0
            self.log: deque[dict[str, Any]] = deque(maxlen=LOG_SIZE)

    def update(self, knobs: Knobs, *, restart_ramp: bool) -> None:
        with self._lock:
            now = self.clock()
            if knobs.outage != self.knobs.outage:
                self.outage_history.append((now, knobs.outage))
            if knobs.ramp is None:
                self.ramp_started_at = None
            elif restart_ramp or self.ramp_started_at is None:
                self.ramp_started_at = now
            self.knobs = knobs

    def outage_at(self, when: float) -> bool:
        state = False
        for at, outage in self.outage_history:
            if at <= when:
                state = outage
        return state

    # ---------------------------------------------------------------- decide

    def headroom(self, now: float) -> float:
        ramp = self.knobs.ramp
        if ramp is None or self.ramp_started_at is None:
            return 1.0
        elapsed = now - self.ramp_started_at
        progress = 1.0 if ramp.ramp_s == 0 else min(1.0, max(0.0, elapsed / ramp.ramp_s))
        return ramp.start_headroom + (ramp.end_headroom - ramp.start_headroom) * progress

    def decide(self, *, model: str, credential: str | None, has_tools: bool) -> Decision:
        with self._lock:
            self._seq += 1
            draws = [self._rng.random() for _ in range(DRAWS)]
            knobs = self.knobs.for_request(credential, model)
            now = self.clock()
            decision = self._decide(self._seq, knobs, draws, model, has_tools, now)
            self.stats[f"status_{decision.status}"] += 1
            self.stats[f"behaviour_{decision.behaviour}"] += 1
            self.stats["requests"] += 1
            self.log.append(
                {
                    "seq": decision.seq,
                    "at": now,
                    "model": model,
                    "status": decision.status,
                    "error_code": decision.error_code,
                    "behaviour": decision.behaviour,
                    "latency_ms": round(decision.latency_ms, 3),
                }
            )
            return decision

    def _ratelimit_headers(self, knobs: Knobs, headroom: float) -> dict[str, str]:
        return {
            "x-ratelimit-limit-requests": str(knobs.limit_requests),
            "x-ratelimit-remaining-requests": str(math.floor(knobs.limit_requests * headroom)),
            "x-ratelimit-reset-requests": "1s",
            "x-ratelimit-limit-tokens": str(knobs.limit_tokens),
            "x-ratelimit-remaining-tokens": str(math.floor(knobs.limit_tokens * headroom)),
            "x-ratelimit-reset-tokens": "1s",
        }

    def _decide(
        self, seq: int, knobs: Knobs, draws: list[float], model: str, has_tools: bool, now: float
    ) -> Decision:
        u_error, u_status, u_lat1, u_lat2, u_refusal, u_trunc, u_schema, u_loop = draws
        latency = latency_ms(knobs.latency, u_lat1, u_lat2)
        headroom = self.headroom(now)
        headers = self._ratelimit_headers(knobs, headroom)

        def fail(status: int, code: str, extra: dict[str, str] | None = None) -> Decision:
            return Decision(
                seq, status, code, latency, "normal", {**headers, **(extra or {})}, knobs
            )

        if knobs.outage:
            return fail(503, "service_unavailable")
        if model in knobs.missing_models:
            return fail(404, "model_not_found")
        ramp = knobs.ramp
        if (
            ramp is not None
            and self.ramp_started_at is not None
            and ramp.then_429
            and (now - self.ramp_started_at >= ramp.ramp_s)
        ):
            return fail(429, "rate_limit_exceeded", {"retry-after": str(ramp.retry_after_s)})
        if u_error < knobs.error_rate:
            statuses = knobs.error_statuses
            status = statuses[min(int(u_status * len(statuses)), len(statuses) - 1)]
            extra = {"retry-after": "1"} if status == 429 else None
            return fail(status, _error_code(status), extra)
        behaviour: Behaviour = "normal"
        if has_tools and u_loop < knobs.tool_loop.rate:
            behaviour = "tool_loop"
        elif has_tools and u_schema < knobs.schema_failure_rate:
            behaviour = "schema_failure"
        elif u_refusal < knobs.refusal_rate:
            behaviour = "refusal"
        elif u_trunc < knobs.truncation_rate:
            behaviour = "truncation"
        return Decision(seq, 200, None, latency, behaviour, headers, knobs)

    def account(self, knobs: Knobs, tokens_in: int, tokens_out: int) -> float:
        cost = (
            tokens_in * knobs.cost_per_input_token_usd
            + tokens_out * knobs.cost_per_output_token_usd
        )
        with self._lock:
            self.tokens_in += tokens_in
            self.tokens_out += tokens_out
            self.cost_usd += cost
        return cost

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "provider": self.provider,
                "models": list(self.models),
                "seed": self.seed,
                "knobs": self.knobs.to_dict(),
                "headroom": round(self.headroom(self.clock()), 6),
                "stats": dict(self.stats),
                "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out,
                "cost_usd": round(self.cost_usd, 8),
            }


def _error_code(status: int) -> str:
    return {
        429: "rate_limit_exceeded",
        500: "internal_error",
        502: "bad_gateway",
        503: "service_unavailable",
        504: "gateway_timeout",
        404: "not_found",
        400: "invalid_request",
        401: "invalid_api_key",
    }.get(status, f"http_{status}")
