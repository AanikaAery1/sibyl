"""Builders for the pure prediction tests: seed config, ``AgentInputs`` and ``AgentFeed``."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any
from uuid import UUID

from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.predict.feed import AgentFeed, TrendView
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.engine import EngineState, Evaluation, evaluate
from sibyl_control.worker.scoring.features import AgentInputs, WindowStats, latency_hist

NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
AGENT = UUID("00000000-0000-7000-8000-000000000001")
PROVIDER = UUID("00000000-0000-7000-8000-0000000000aa")


@lru_cache(maxsize=1)
def seed_config() -> EngineConfig:
    return EngineConfig.from_seed(load())


def config(**automation: Any) -> EngineConfig:
    """The seed config with ``scoring.automation`` keys overridden."""
    base = seed_config()
    scoring = dict(base.scoring)
    scoring["automation"] = {**dict(base.scoring["automation"]), **automation}
    return EngineConfig(scoring, base.rules, base.scoring_config_id)


def window(
    *,
    req: int = 60,
    err: int = 0,
    latency_ms: int = 500,
    rate_limited: int = 0,
    server_errors: int = 0,
    timeouts: int = 0,
    headroom: float | None = None,
) -> WindowStats:
    return WindowStats(
        request_count=req,
        error_count=err,
        rate_limit_count=rate_limited,
        server_error_count=server_errors,
        timeout_count=timeouts,
        latency_hist=latency_hist([latency_ms] * req),
        ratelimit_headroom_min=headroom,
    )


def inputs(*, tier: int = 2, plan: bool = True, **kw: Any) -> AgentInputs:
    extra = {
        k: kw.pop(k)
        for k in list(kw)
        if k
        in (
            "provider_status",
            "provider_status_age_s",
            "provider_error_rate_fleet",
            "spend_ratio",
            "model_class",
            "baselines",
            "baseline_ref",
            "coverage",
        )
    }
    w5 = window(**kw)
    base = AgentInputs(
        agent_id=AGENT,
        tier=tier,
        created_at=NOW - timedelta(days=30),
        provider="provider-one",
        provider_id=PROVIDER,
        model="large-1",
        model_class="large",
        w5=w5,
        w1=w5,
        request_count_1h=max(w5.request_count * 12, 0),
        active_minutes_1h=60,
        has_plan=plan,
    )
    return replace(base, **extra)


def feed(
    *,
    error_series: tuple[float | None, ...] = (),
    p95_series: tuple[float | None, ...] = (),
    error_ewma: float | None = None,
    error_cusum: float = 0.0,
    p95_ewma: float | None = None,
    p95_cusum: float = 0.0,
    closed_requests: int = 60,
    headroom: tuple[tuple[float, float], ...] = (),
    budget: float | None = None,
    mtd: float = 0.0,
    rate_s: float = 0.0,
) -> AgentFeed:
    trends: dict[str, TrendView] = {}
    if error_ewma is not None:
        trends["error_rate"] = TrendView(error_ewma, error_cusum, 10)
    if p95_ewma is not None:
        trends["latency_p95_ms"] = TrendView(p95_ewma, p95_cusum, 10)
    return AgentFeed(
        trends=trends,
        error_series=error_series,
        p95_series=p95_series,
        closed_requests=closed_requests,
        headroom_points=headroom,
        budget_usd=budget,
        mtd_cost_usd=mtd,
        cost_rate_usd_s=rate_s,
        loaded=True,
    )


def headroom_ramp(
    start: float, per_min: float, minutes: int = 6
) -> tuple[tuple[float, float], ...]:
    """Closed-minute headroom points, newest first: ``(seconds before now, headroom)``."""
    return tuple((60.0 * age, max(0.0, start + per_min * age)) for age in range(minutes))


def run_ticks(
    inp: AgentInputs,
    cfg: EngineConfig,
    leading: Any,
    ticks: int,
    prior: EngineState | None = None,
) -> Evaluation:
    """Evaluate ``ticks`` times (10 s apart) so leading hysteresis completes."""
    ev = None
    state = prior
    for i in range(ticks):
        now = NOW + timedelta(seconds=10 * i)
        ev = evaluate(inp, state, cfg, now, leading=leading(inp, cfg, now))
        state = ev.state
    assert ev is not None
    return ev
