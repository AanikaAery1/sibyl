"""EWMA / CUSUM state per (agent, metric), advanced once per closed 5m bucket (ML.md §4.1).

This is the input lane P's leading rules (L1-L7) read; the math lives here so the rollup can
advance it in the same transaction as the 5m rows it reads. ``last_bucket`` never goes
backwards (a DB trigger enforces it), so a 5m bucket reopened by a late event updates the
rollup but never re-advances CUSUM. A ``repair`` rollup job resets the rows and replays.

Baseline for the CUSUM z-score: the agent's own ``agent_baseline`` row for this hour of week
when one exists, else the ``seed_baselines`` from scoring_config (error rate, p95 by model
class), else the EWMA level before this update. ``sigma`` is the EWMA standard deviation floored
at 5 % of the baseline.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from ..scoring.features import WindowStats, model_class

METRICS: dict[str, Callable[[WindowStats], float | None]] = {
    "error_rate": lambda w: w.ratio("error_count"),
    "latency_p95_ms": lambda w: w.p95_ms,
    "finish_content_filter_ratio": lambda w: w.ratio("refusal_count"),
    "tokens_out_mean": lambda w: w.ratio("tokens_out"),
    "output_chars_mean": lambda w: w.ratio("output_chars_sum"),
    "cost_usd": lambda w: float(w.cost_usd) if w.request_count else None,
    "tool_call_count": lambda w: float(w.tool_call_count),
}
SIGMA_FLOOR = 0.05
EPS = 1e-9


@dataclass(frozen=True)
class TrendState:
    last_bucket: datetime | None = None
    ewma: float | None = None
    ewma_var: float | None = None
    cusum_pos: float = 0.0
    cusum_neg: float = 0.0
    cusum_alarm_at: datetime | None = None
    samples: int = 0


def advance(
    state: TrendState,
    x: float,
    bucket: datetime,
    *,
    lam: float,
    k: float,
    h: float,
    baseline: float | None,
    alarm_at: datetime,
) -> TrendState:
    """One closed bucket. Pure, so replay equals production."""
    prev = state.ewma
    ewma = x if prev is None else lam * x + (1 - lam) * prev
    var = 0.0 if prev is None else (1 - lam) * ((state.ewma_var or 0.0) + lam * (x - prev) ** 2)
    base = baseline if baseline is not None else (prev if prev is not None else x)
    sigma = max(math.sqrt(var), SIGMA_FLOOR * abs(base), EPS)
    z = (x - base) / sigma
    pos = max(0.0, state.cusum_pos + z - k)
    neg = max(0.0, state.cusum_neg - z - k)
    alarm = state.cusum_alarm_at
    if pos > h or neg > h:
        alarm = alarm or alarm_at
    else:
        alarm = None
    return TrendState(bucket, ewma, var, pos, neg, alarm, state.samples + 1)


_STATE_SQL = (
    "SELECT agent_id, metric, last_bucket, ewma, ewma_var, cusum_pos, cusum_neg, cusum_alarm_at, "
    "samples FROM sibyl.agent_trend_state WHERE tenant_id = $1 AND agent_id = ANY($2)"
)
_ROWS_SQL = (
    "SELECT agent_id, bucket_start, model, request_count, error_count, refusal_count, tokens_out, "
    "output_chars_sum, cost_usd, tool_call_count, latency_hist FROM sibyl.agent_metrics_5m "
    "WHERE tenant_id = $1 AND agent_id = ANY($2) AND bucket_start >= $3 AND bucket_start <= $4"
)
_CONFIG_SQL = (
    "SELECT id, config FROM sibyl.scoring_config WHERE tenant_id = $1 "
    "AND activated_at IS NOT NULL AND superseded_at IS NULL"
)
_BASELINE_SQL = (
    "SELECT agent_id, metric, hour_of_week, mean FROM sibyl.agent_baseline "
    "WHERE tenant_id = $1 AND agent_id = ANY($2) AND mean IS NOT NULL"
)
_UPSERT_SQL = (
    "INSERT INTO sibyl.agent_trend_state (tenant_id, agent_id, metric, last_bucket, ewma, "
    "ewma_var, cusum_pos, cusum_neg, cusum_alarm_at, samples, scoring_config_id) "
    "SELECT $1, u.a, u.m, u.b, u.e, u.v, u.p, u.n, u.al, u.s, $2 FROM unnest($3::uuid[], "
    "$4::text[], $5::timestamptz[], $6::float8[], $7::float8[], $8::float8[], $9::float8[], "
    "$10::timestamptz[], $11::int[]) AS u(a, m, b, e, v, p, n, al, s) "
    "ON CONFLICT (tenant_id, agent_id, metric) DO UPDATE SET last_bucket = EXCLUDED.last_bucket, "
    "ewma = EXCLUDED.ewma, ewma_var = EXCLUDED.ewma_var, cusum_pos = EXCLUDED.cusum_pos, "
    "cusum_neg = EXCLUDED.cusum_neg, cusum_alarm_at = EXCLUDED.cusum_alarm_at, "
    "samples = EXCLUDED.samples, scoring_config_id = EXCLUDED.scoring_config_id"
)


def _hour_of_week(ts: datetime) -> int:
    return ts.weekday() * 24 + ts.hour


def _seed_baseline(cfg: Mapping[str, Any], metric: str, model: str | None) -> float | None:
    seeds = cfg.get("seed_baselines") or {}
    if metric == "error_rate":
        return float(seeds.get("error_rate", 0.01))
    if metric == "latency_p95_ms":
        table = seeds.get("p95_latency_ms") or {}
        value = table.get(model_class(model))
        return None if value is None else float(value)
    return None


async def advance_trend_state(
    conn: Any, tenant: UUID, closed: Sequence[tuple[UUID, datetime]]
) -> int:
    """Advance every (agent, metric) over its closed 5m buckets newer than ``last_bucket``."""
    if not closed:
        return 0
    config = await conn.fetchrow(_CONFIG_SQL, tenant)
    if config is None:
        return 0
    cfg: Mapping[str, Any] = config["config"]
    trend = cfg.get("trend") or {}
    lam, k, h = (
        float(trend.get("ewma_lambda", 0.3)),
        float(trend.get("cusum_k", 0.5)),
        float(trend.get("cusum_h", 5)),
    )
    agents = sorted({a for a, _ in closed})
    newest = max(b for _, b in closed)
    states: dict[tuple[UUID, str], TrendState] = {
        (r["agent_id"], r["metric"]): TrendState(
            r["last_bucket"],
            r["ewma"],
            r["ewma_var"],
            r["cusum_pos"],
            r["cusum_neg"],
            r["cusum_alarm_at"],
            r["samples"],
        )
        for r in await conn.fetch(_STATE_SQL, tenant, agents)
    }
    oldest = min(b for _, b in closed)
    floor = min([oldest, *(s.last_bucket for s in states.values() if s.last_bucket)])
    buckets: dict[tuple[UUID, datetime], list[Mapping[str, Any]]] = defaultdict(list)
    for r in await conn.fetch(_ROWS_SQL, tenant, agents, floor, newest):
        buckets[(r["agent_id"], r["bucket_start"])].append(r)
    baselines = {
        (r["agent_id"], r["metric"], r["hour_of_week"]): float(r["mean"])
        for r in await conn.fetch(_BASELINE_SQL, tenant, agents)
    }
    changed: dict[tuple[UUID, str], TrendState] = {}
    for (agent, bucket), rows in sorted(buckets.items(), key=lambda kv: (kv[0][1], str(kv[0][0]))):
        stats = WindowStats()
        for r in rows:
            stats = stats.merge(WindowStats.from_row(r))
        model = max(rows, key=lambda r: r["request_count"])["model"] or None
        for metric, fn in METRICS.items():
            key = (agent, metric)
            state = changed.get(key) or states.get(key) or TrendState()
            if state.last_bucket is not None and bucket <= state.last_bucket:
                continue
            x = fn(stats)
            if x is None:
                continue
            base = baselines.get((agent, metric, _hour_of_week(bucket)))
            if base is None:
                base = _seed_baseline(cfg, metric, model)
            changed[key] = advance(
                state, x, bucket, lam=lam, k=k, h=h, baseline=base, alarm_at=bucket
            )
    if changed:
        items = sorted(changed.items(), key=lambda kv: (str(kv[0][0]), kv[0][1]))
        await conn.execute(
            _UPSERT_SQL,
            tenant,
            config["id"],
            [a for (a, _), _ in items],
            [m for (_, m), _ in items],
            [s.last_bucket for _, s in items],
            [s.ewma for _, s in items],
            [s.ewma_var for _, s in items],
            [s.cusum_pos for _, s in items],
            [s.cusum_neg for _, s in items],
            [s.cusum_alarm_at for _, s in items],
            [s.samples for _, s in items],
        )
    return len(changed)
