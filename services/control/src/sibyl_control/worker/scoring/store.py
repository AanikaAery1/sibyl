"""Read everything one scoring tick needs for one tenant, in a bounded number of queries.

All reads run on the caller's ``tenant_tx`` connection (RLS scoped). Per-agent loops never
issue queries: each input is one statement over the tenant, keyed back to agents in memory, so
the cost is flat in the number of agents (ML.md §7.4/§7.5).
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from ..rollup.aggregate import bucket_start, sql_agg
from .config import EngineConfig
from .engine import EngineState
from .features import AgentInputs, WindowStats, model_class

WINDOW = timedelta(minutes=5)
SERVING_PRIMARY = frozenset({"active", "degraded"})
TAIL = 10

_SEED_DEFAULTS: list[Mapping[str, Any]] | None = None

_CONFIG_SQL = (
    "SELECT id, config FROM sibyl.scoring_config WHERE tenant_id = $1 "
    "AND activated_at IS NOT NULL AND superseded_at IS NULL"
)
_RULES_SQL = (
    "SELECT id, code, short_code, kind, scope, severity, enabled, min_samples, window_s, "
    "collapses_to_provider, escalate_after_fires, escalate_window_s, what_to_do_template, "
    "thresholds FROM sibyl.alert_rule WHERE tenant_id = $1"
)
_AGENTS_SQL = """
SELECT a.id, a.tier, a.kind, a.created_at, a.business_process_id,
       coalesce(rs.state, 'active') AS routing_state, coalesce(rs.routing_version, 0) AS rv,
       cp.id IS NOT NULL AS has_plan, cp.budget_usd_month, cp.expected_cadence_s,
       (SELECT p.slug FROM sibyl.agent_version v
          JOIN sibyl.model m ON m.tenant_id = v.tenant_id AND m.id = v.primary_model_id
          JOIN sibyl.provider p ON p.tenant_id = m.tenant_id AND p.id = m.provider_id
         WHERE v.tenant_id = a.tenant_id AND v.id = a.current_version_id) AS primary_provider
  FROM sibyl.agent a
  LEFT JOIN sibyl.routing_state rs ON rs.tenant_id = a.tenant_id AND rs.agent_id = a.id
  LEFT JOIN sibyl.continuity_plan cp ON cp.tenant_id = a.tenant_id AND cp.agent_id = a.id
 WHERE a.tenant_id = $1 AND a.lifecycle <> 'retired'
"""
_WINDOW_COLUMNS: tuple[str, ...] = (
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
    "latency_hist",
    "ratelimit_remaining_min",
)
_M1_SQL = (
    "SELECT t.agent_id, t.provider, t.model, t.bucket_start >= $4 AS last_minute, "  # noqa: S608
    + ", ".join(f"{sql_agg(c)} AS {c}" for c in _WINDOW_COLUMNS)
    + " FROM sibyl.agent_metrics_1m t WHERE t.tenant_id = $1 AND t.bucket_start > $2 "
    "AND t.bucket_start <= $3 GROUP BY 1, 2, 3, 4"
)
_HOUR_SQL = (
    "SELECT agent_id, sum(request_count)::int AS req, sum(error_count)::int AS err, "
    "count(DISTINCT bucket_start) FILTER (WHERE request_count > 0)::int * 5 AS active "
    "FROM sibyl.agent_metrics_5m WHERE tenant_id = $1 AND bucket_start > $2 AND bucket_start <= $3 "
    "GROUP BY agent_id"
)
_PROVIDERS_SQL = "SELECT id, slug, provider_kind FROM sibyl.provider WHERE tenant_id = $1"
_STATUS_SQL = (
    "SELECT DISTINCT ON (provider_id) provider_id, id, status, observed_at "
    "FROM sibyl.provider_status WHERE tenant_id = $1 AND observed_at <= $2 "
    "ORDER BY provider_id, observed_at DESC, created_at DESC"
)
_TAIL_SQL = """
SELECT a.id AS agent_id, t.statuses
  FROM unnest($2::uuid[]) AS a(id)
 CROSS JOIN LATERAL (
   SELECT array_agg(x.status ORDER BY x.ts DESC) AS statuses FROM (
     SELECT status, ts FROM sibyl.events
      WHERE tenant_id = $1 AND agent_id = a.id AND event_type = 'gen_ai.request'
        AND ts <= $3 AND ts > $3::timestamptz - interval '10 minutes'
      ORDER BY ts DESC LIMIT $4) x) t
"""
_SPEND_SQL = (
    "SELECT agent_id, sum(cost_usd) AS cost FROM sibyl.agent_metrics_1h WHERE tenant_id = $1 "
    "AND agent_id = ANY($2) AND bucket_start >= date_trunc('month', $3::timestamptz) "
    "GROUP BY agent_id"
)
_LAST_SEEN_SQL = (
    "SELECT agent_id, max(bucket_start) + interval '1 minute' AS last FROM sibyl.agent_metrics_1m "
    "WHERE tenant_id = $1 AND agent_id = ANY($2) AND request_count > 0 "
    "AND bucket_start > $3::timestamptz - interval '1 day' AND bucket_start <= $3 GROUP BY agent_id"
)
_BASELINE_SQL = (
    "SELECT agent_id, metric, mean, baseline_ref FROM sibyl.agent_baseline WHERE tenant_id = $1 "
    "AND hour_of_week = $2 AND peer_group IS NULL AND mean IS NOT NULL "
    "AND metric IN ('latency_p95_ms', 'finish_length_ratio')"
)
_PRIOR_SQL = """
SELECT a.id AS agent_id, s.evaluated_at, s.score, s.band, s.factors
  FROM sibyl.agent a
 CROSS JOIN LATERAL (
   SELECT evaluated_at, score, band, factors FROM sibyl.health_snapshot h
    WHERE h.tenant_id = a.tenant_id AND h.agent_id = a.id AND h.evaluated_at <= $2
    ORDER BY h.evaluated_at DESC LIMIT 1) s
 WHERE a.tenant_id = $1 AND a.lifecycle <> 'retired'
"""
# The agent's latest frozen feature snapshot: every health snapshot references one (B-04,
# sibyl-health/1 ``feature_snapshot_ref``); ix_feature_snapshot_agent serves the lookup.
_LATEST_FS_SQL = """
SELECT a.id AS agent_id, f.id, f.as_of
  FROM sibyl.agent a
 CROSS JOIN LATERAL (
   SELECT id, as_of FROM sibyl.feature_snapshot f
    WHERE f.tenant_id = a.tenant_id AND f.agent_id = a.id AND f.as_of <= $2
    ORDER BY f.as_of DESC LIMIT 1) f
 WHERE a.tenant_id = $1 AND a.lifecycle <> 'retired'
"""
_LAG_SQL = (
    "SELECT last_created_at FROM sibyl.consumer_offsets WHERE consumer_group = 'rollup' "
    "AND tenant_id = $1 AND topic = 'events'"
)
_ROUTING_SQL = (
    "SELECT agent_id, count(*)::int AS n FROM sibyl.routing_transition WHERE tenant_id = $1 "
    "AND created_at > $2::timestamptz - interval '10 minutes' AND actor_kind IN ('rule', 'policy') "
    "GROUP BY agent_id"
)


async def _seed_defaults(conn: Any) -> list[Mapping[str, Any]]:
    global _SEED_DEFAULTS
    if _SEED_DEFAULTS is None:
        raw = await conn.fetchval("SELECT rules FROM sibyl.rules_seed()")
        _SEED_DEFAULTS = list(raw if not isinstance(raw, str) else json.loads(raw))
    return _SEED_DEFAULTS


def reset_caches() -> None:
    global _SEED_DEFAULTS
    _SEED_DEFAULTS = None


async def load_config(conn: Any, tenant: UUID) -> EngineConfig | None:
    row = await conn.fetchrow(_CONFIG_SQL, tenant)
    if row is None:
        return None
    rules = [dict(r) for r in await conn.fetch(_RULES_SQL, tenant)]
    return EngineConfig.from_rows(
        row["config"], rules, scoring_config_id=row["id"], defaults=await _seed_defaults(conn)
    )


@dataclass(frozen=True)
class AgentRow:
    agent_id: UUID
    tier: int
    kind: str
    created_at: datetime
    business_process_id: UUID | None
    routing_state: str
    policy_version: int
    has_plan: bool
    budget: Decimal | None
    cadence_s: int | None
    primary_provider: str | None = None

    @property
    def serving_primary(self) -> bool:
        return self.routing_state in SERVING_PRIMARY


@dataclass
class TenantData:
    tenant_id: UUID
    now: datetime
    config: EngineConfig
    agents: list[AgentRow]
    inputs: dict[UUID, AgentInputs]
    priors: dict[UUID, EngineState]
    provider_ids: dict[str, UUID]
    provider_status: dict[UUID, Mapping[str, Any]]
    rollup_lag_s: float
    provider_slugs: dict[UUID, str] = field(default_factory=dict)
    summaries: dict[UUID, dict[str, float | None]] = field(default_factory=dict)
    latest_fs: dict[UUID, tuple[UUID, datetime]] = field(default_factory=dict)


def _dominant(groups: Mapping[tuple[str, str], int]) -> tuple[str | None, str | None]:
    attributed = {k: v for k, v in groups.items() if k[0]}
    if not attributed:
        return None, None
    (provider, model), _ = max(attributed.items(), key=lambda kv: (kv[1], kv[0]))
    return provider, model or None


def _attribute(
    own: Mapping[tuple[str, str], int], served: Mapping[tuple[str, str], int], a: AgentRow
) -> tuple[str | None, str | None]:
    """The agent's provider for R4, collapse and fleet corroboration, and its model class.

    A call the gateway rescued on the inline fallback step is stored under the fallback
    provider, but it is a failed call on the route the agent is on. So the provider is the
    dominant one by calls *not* rescued (``own``); when every call in the window was rescued and
    the agent is meant to be serving its primary, it is the primary's provider (a primary
    outage the fallback hides still reaches the agent through R4). The model (latency class)
    follows what actually served the calls.
    """
    provider, model = _dominant({k: v for k, v in own.items() if v > 0})
    if provider is not None:
        return provider, model
    provider, model = _dominant(served)
    if a.primary_provider and a.serving_primary:
        return a.primary_provider, model
    return provider, model


def _run_length(statuses: Sequence[str] | None) -> int:
    n = 0
    for status in statuses or ():
        if status != "error":
            break
        n += 1
    return n


def _prior(row: Mapping[str, Any]) -> EngineState:
    doc = next((f for f in row["factors"] or () if f.get("rule") == "_hysteresis"), None)
    return EngineState.from_bookkeeping(
        doc, written_at=row["evaluated_at"], score=row["score"], band=row["band"]
    )


async def load_tenant(conn: Any, tenant: UUID, now: datetime) -> TenantData | None:
    cfg = await load_config(conn, tenant)
    if cfg is None:
        return None
    agents = [
        AgentRow(
            r["id"],
            r["tier"],
            r["kind"],
            r["created_at"],
            r["business_process_id"],
            r["routing_state"],
            int(r["rv"]),
            r["has_plan"],
            r["budget_usd_month"],
            r["expected_cadence_s"],
            r["primary_provider"],
        )
        for r in await conn.fetch(_AGENTS_SQL, tenant)
    ]
    ids = [a.agent_id for a in agents]

    w5: dict[UUID, WindowStats] = defaultdict(WindowStats)
    w1: dict[UUID, WindowStats] = defaultdict(WindowStats)
    volume: dict[UUID, dict[tuple[str, str], int]] = defaultdict(lambda: defaultdict(int))
    own: dict[UUID, dict[tuple[str, str], int]] = defaultdict(lambda: defaultdict(int))
    fleet: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    # every 1m bucket overlapping [now - 60 s, now]: the open minute and the one before it
    last_minute = bucket_start(now - timedelta(minutes=1), 60)
    for r in await conn.fetch(_M1_SQL, tenant, now - WINDOW, now, last_minute):
        stats = WindowStats.from_row(r)
        if r["ratelimit_remaining_min"] is not None:
            stats = replace(stats, ratelimit_headroom_min=r["ratelimit_remaining_min"] / 1000)
        agent = r["agent_id"]
        w5[agent] = w5[agent].merge(stats)
        if r["last_minute"]:
            w1[agent] = w1[agent].merge(stats)
        volume[agent][(r["provider"], r["model"])] += stats.request_count
        own[agent][(r["provider"], r["model"])] += stats.request_count - stats.inline_fallback_count
        if r["provider"]:
            fleet[r["provider"]][0] += stats.error_count
            fleet[r["provider"]][1] += stats.request_count

    hour = {
        r["agent_id"]: (r["req"], r["active"], r["err"] or 0)
        for r in await conn.fetch(_HOUR_SQL, tenant, now - timedelta(hours=1), now)
    }
    providers = await conn.fetch(_PROVIDERS_SQL, tenant)
    provider_ids: dict[str, UUID] = {p["slug"]: p["id"] for p in providers}
    kinds: dict[str, list[UUID]] = defaultdict(list)
    for p in providers:
        kinds[p["provider_kind"]].append(p["id"])
    for kind, pids in kinds.items():
        if len(pids) == 1:
            provider_ids.setdefault(kind, pids[0])
    status: dict[UUID, Mapping[str, Any]] = {
        r["provider_id"]: dict(r) for r in await conn.fetch(_STATUS_SQL, tenant, now)
    }

    erroring = [a for a in ids if w1[a].error_count > 0]
    tails = {
        r["agent_id"]: _run_length(r["statuses"])
        for r in (await conn.fetch(_TAIL_SQL, tenant, erroring, now, TAIL) if erroring else [])
    }
    budgeted = [a.agent_id for a in agents if a.budget]
    spend = {
        r["agent_id"]: r["cost"]
        for r in (await conn.fetch(_SPEND_SQL, tenant, budgeted, now) if budgeted else [])
    }
    cadenced = [a.agent_id for a in agents if a.cadence_s]
    last_seen = {
        r["agent_id"]: r["last"]
        for r in (await conn.fetch(_LAST_SEEN_SQL, tenant, cadenced, now) if cadenced else [])
    }
    how = now.weekday() * 24 + now.hour
    baselines: dict[UUID, dict[str, float]] = defaultdict(dict)
    base_ref: dict[UUID, str] = {}
    for r in await conn.fetch(_BASELINE_SQL, tenant, how):
        baselines[r["agent_id"]][r["metric"]] = float(r["mean"])
        base_ref[r["agent_id"]] = r["baseline_ref"]
    priors = {r["agent_id"]: _prior(r) for r in await conn.fetch(_PRIOR_SQL, tenant, now)}
    latest_fs = {
        r["agent_id"]: (r["id"], r["as_of"]) for r in await conn.fetch(_LATEST_FS_SQL, tenant, now)
    }
    lag_at = await conn.fetchval(_LAG_SQL, tenant)
    lag = max(0.0, (now - lag_at).total_seconds()) if lag_at else 0.0
    routes = {r["agent_id"]: r["n"] for r in await conn.fetch(_ROUTING_SQL, tenant, now)}

    inputs: dict[UUID, AgentInputs] = {}
    for a in agents:
        provider, model = _attribute(own.get(a.agent_id, {}), volume.get(a.agent_id, {}), a)
        pid = provider_ids.get(provider) if provider else None
        pstat = status.get(pid) if pid else None
        f_err, f_req = fleet.get(provider or "", [0, 0])
        req_1h, active, err_1h = hour.get(a.agent_id, (0, 0, 0))
        spent = spend.get(a.agent_id)
        inputs[a.agent_id] = AgentInputs(
            agent_id=a.agent_id,
            tier=a.tier,
            created_at=a.created_at,
            w5=w5[a.agent_id],
            w1=w1[a.agent_id],
            provider=provider,
            provider_id=pid,
            model=model,
            model_class=model_class(model),
            kind=a.kind,
            consecutive_errors=tails.get(a.agent_id, 0),
            request_count_1h=req_1h,
            error_count_1h=err_1h,
            active_minutes_1h=active,
            provider_status=pstat["status"] if pstat else None,
            provider_status_age_s=(now - pstat["observed_at"]).total_seconds() if pstat else None,
            provider_error_rate_fleet=(f_err / f_req) if f_req else None,
            spend_ratio=float(spent / a.budget)
            if a.budget and spent is not None
            else (0.0 if a.budget else None),
            has_plan=a.has_plan,
            cadence_s=a.cadence_s,
            last_request_at=last_seen.get(a.agent_id),
            routing_state=a.routing_state,
            policy_version=a.policy_version,
            baselines=baselines.get(a.agent_id, {}),
            baseline_ref=base_ref.get(a.agent_id, "seed/v1"),
            rollup_lag_s=lag,
            business_process_id=a.business_process_id,
            routing_transitions_10m=routes.get(a.agent_id, 0),
        )
    return TenantData(
        tenant,
        now,
        cfg,
        agents,
        inputs,
        priors,
        provider_ids,
        status,
        lag,
        {p["id"]: p["slug"] for p in providers},
        {a: inputs[a].w5.summary() for a in inputs},
        latest_fs,
    )
