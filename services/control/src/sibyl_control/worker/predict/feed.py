"""Leading-rule inputs the scoring tick's ``AgentInputs`` does not carry (ML.md §4.1).

``AgentInputs`` holds the open 5-minute window and statics; the leading rules also need the
EWMA/CUSUM state (``agent_trend_state``), the closed 5m series (for "rising for 3 windows"),
the closed-minute rate-limit headroom series (time to exhaustion) and the budget burn. This
module loads them in a bounded number of tenant-wide statements (flat in the number of agents)
and hands them to the pure evaluators through a context variable for the duration of one
scoring tick.

Wiring: ``prepare`` is lane P's ``Extensions.prepare`` hook (registered by
``worker.predict.install``). ``score_tenant`` awaits it once per tenant right after
``load_tenant``, on the tick's connection and with the tick's ``now``, in the same task as the
evaluators, so the context variable it sets is the one they read. A feed loaded for another
tick (``now`` more than ``FEED_MAX_SKEW_S`` away) or another tenant's agents is never used: the
evaluators then fall back to what ``AgentInputs`` alone supports (headroom level and 429 share
for L3, the spend-ratio level for L4) and L1/L2 report "no trend state".
"""

from __future__ import annotations

import contextvars
import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any
from uuid import UUID

from ..rollup.aggregate import sql_agg
from ..scoring.features import hist_quantile

SERIES_BUCKETS = 5  # closed 5m buckets: enough for three consecutive rising windows
HEADROOM_MINUTES = 10
RATE_SHORT_S = 300
RATE_LONG_S = 3600
FEED_MAX_SKEW_S = 30.0
TREND_METRICS = ("error_rate", "latency_p95_ms")


@dataclass(frozen=True)
class TrendView:
    """One ``agent_trend_state`` row as the leading rules read it."""

    ewma: float | None
    cusum_pos: float = 0.0
    samples: int = 0
    last_bucket: datetime | None = None


@dataclass(frozen=True)
class AgentFeed:
    """Closed-bucket inputs for one agent (all optional: ``None`` means not computable)."""

    trends: Mapping[str, TrendView] = field(default_factory=lambda: MappingProxyType({}))
    error_series: tuple[float | None, ...] = ()  # oldest -> newest closed 5m buckets
    p95_series: tuple[float | None, ...] = ()
    closed_requests: int = 0  # requests in the newest closed 5m bucket
    headroom_points: tuple[tuple[float, float], ...] = ()  # (seconds before now, headroom 0..1)
    budget_usd: float | None = None
    mtd_cost_usd: float = 0.0
    cost_rate_usd_s: float = 0.0
    loaded: bool = False


EMPTY_FEED = AgentFeed()


@dataclass(frozen=True)
class Feed:
    tenant_id: UUID
    now: datetime
    agents: Mapping[UUID, AgentFeed]


_CURRENT: contextvars.ContextVar[Feed | None] = contextvars.ContextVar(
    "sibyl_predict_feed", default=None
)


def install(feed: Feed | None) -> contextvars.Token[Feed | None]:
    return _CURRENT.set(feed)


def reset(token: contextvars.Token[Feed | None]) -> None:
    _CURRENT.reset(token)


def current(agent_id: UUID, now: datetime) -> AgentFeed:
    """The installed feed for ``agent_id`` when it was loaded for this tick, else empty."""
    feed = _CURRENT.get()
    if feed is None or abs((feed.now - now).total_seconds()) > FEED_MAX_SKEW_S:
        return EMPTY_FEED
    return feed.agents.get(agent_id, EMPTY_FEED)


# ------------------------------------------------------------------------------ loading

_TREND_SQL = (
    "SELECT agent_id, metric, ewma, cusum_pos, samples, last_bucket FROM sibyl.agent_trend_state"
    " WHERE tenant_id = $1 AND metric = ANY($2::text[])"
)
_SERIES_SQL = (
    "SELECT agent_id, bucket_start, sum(request_count)::int AS req, sum(error_count)::int AS err, "  # noqa: S608 (constant SQL)
    f"{sql_agg('latency_hist')} AS latency_hist FROM sibyl.agent_metrics_5m t"
    " WHERE t.tenant_id = $1 AND t.bucket_start >= $2"
    " AND t.bucket_start + interval '5 minutes' <= $3"
    " GROUP BY agent_id, bucket_start"
)
_MINUTE_SQL = (
    "SELECT agent_id, sum(cost_usd) FILTER (WHERE bucket_start >= $3) AS cost_short,"
    " sum(cost_usd) AS cost_long FROM sibyl.agent_metrics_1m WHERE tenant_id = $1"
    " AND bucket_start >= $2 AND bucket_start + interval '1 minute' <= $4 GROUP BY agent_id"
)
_HEADROOM_SQL = (
    "SELECT agent_id, bucket_start, min(ratelimit_remaining_min) AS head FROM"
    " sibyl.agent_metrics_1m"
    " WHERE tenant_id = $1 AND bucket_start >= $2 AND bucket_start + interval '1 minute' <= $3"
    " AND ratelimit_remaining_min IS NOT NULL GROUP BY agent_id, bucket_start"
)
_BUDGET_SQL = (
    "SELECT cp.agent_id, cp.budget_usd_month, coalesce(("
    " SELECT sum(m.cost_usd) FROM sibyl.agent_metrics_1h m WHERE m.tenant_id = cp.tenant_id"
    " AND m.agent_id = cp.agent_id AND m.bucket_start >= date_trunc('month', $2::timestamptz)"
    " AND m.bucket_start <= $2), 0) AS mtd FROM sibyl.continuity_plan cp"
    " WHERE cp.tenant_id = $1 AND cp.budget_usd_month IS NOT NULL AND cp.budget_usd_month > 0"
)


def floor_minute(ts: datetime) -> datetime:
    return ts.replace(second=0, microsecond=0)


async def load_feed(conn: Any, tenant: UUID, now: datetime) -> Feed:
    """Every agent's ``AgentFeed`` for one tick, in five statements on the tenant tx."""
    trends: dict[UUID, dict[str, TrendView]] = defaultdict(dict)
    for r in await conn.fetch(_TREND_SQL, tenant, list(TREND_METRICS)):
        trends[r["agent_id"]][r["metric"]] = TrendView(
            r["ewma"], float(r["cusum_pos"] or 0.0), int(r["samples"] or 0), r["last_bucket"]
        )

    series: dict[UUID, list[tuple[datetime, int, int, Sequence[int]]]] = defaultdict(list)
    start5 = now - timedelta(minutes=5 * (SERIES_BUCKETS + 1))
    for r in await conn.fetch(_SERIES_SQL, tenant, start5, now):
        series[r["agent_id"]].append(
            (r["bucket_start"], r["req"] or 0, r["err"] or 0, r["latency_hist"] or ())
        )

    minute = floor_minute(now)
    costs = {
        r["agent_id"]: (float(r["cost_short"] or 0), float(r["cost_long"] or 0))
        for r in await conn.fetch(
            _MINUTE_SQL,
            tenant,
            minute - timedelta(seconds=RATE_LONG_S),
            minute - timedelta(seconds=RATE_SHORT_S),
            now,
        )
    }
    heads: dict[UUID, list[tuple[float, float]]] = defaultdict(list)
    for r in await conn.fetch(
        _HEADROOM_SQL, tenant, minute - timedelta(minutes=HEADROOM_MINUTES), now
    ):
        end = r["bucket_start"] + timedelta(minutes=1)
        heads[r["agent_id"]].append(((now - end).total_seconds(), r["head"] / 1000.0))
    budgets = {
        r["agent_id"]: (float(r["budget_usd_month"]), float(r["mtd"] or 0))
        for r in await conn.fetch(_BUDGET_SQL, tenant, now)
    }

    agents: dict[UUID, AgentFeed] = {}
    for agent in {*trends, *series, *costs, *heads, *budgets}:
        agents[agent] = _agent_feed(
            trends.get(agent, {}),
            sorted(series.get(agent, [])),
            costs.get(agent),
            sorted(heads.get(agent, []), reverse=True),
            budgets.get(agent),
        )
    return Feed(tenant, now, MappingProxyType(agents))


def _agent_feed(
    trends: Mapping[str, TrendView],
    rows: Sequence[tuple[datetime, int, int, Sequence[int]]],
    cost: tuple[float, float] | None,
    heads: Sequence[tuple[float, float]],
    budget: tuple[float, float] | None,
) -> AgentFeed:
    rows = list(rows)[-SERIES_BUCKETS:]
    errors = tuple((err / req) if req else None for _, req, err, _ in rows)
    p95 = tuple(hist_quantile(hist, 0.95) if req else None for _, req, _, hist in rows)
    short, long_ = cost or (0.0, 0.0)
    rate = max(short / RATE_SHORT_S, long_ / RATE_LONG_S)
    return AgentFeed(
        trends=MappingProxyType(dict(trends)),
        error_series=errors,
        p95_series=p95,
        closed_requests=rows[-1][1] if rows else 0,
        headroom_points=tuple(heads),
        budget_usd=budget[0] if budget else None,
        mtd_cost_usd=budget[1] if budget else 0.0,
        cost_rate_usd_s=rate if math.isfinite(rate) else 0.0,
        loaded=True,
    )


async def prepare(conn: Any, tenant: UUID, now: datetime) -> Feed:
    """The ``Extensions.prepare`` hook: load and install this tenant tick's feed."""
    feed = await load_feed(conn, tenant, now)
    install(feed)
    return feed
