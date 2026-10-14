"""Per-agent reads (API.md §5.7, §5.10): routing state + transitions, health document and history,
risk, metric buckets, checkpoints. Read models only; no audit rows."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response

from ...core.authz import PrincipalKind
from ...core.etag import etag_for_version, if_none_match_hit
from ...core.problems import ProblemError
from ..auth.common import Paging, iso, json_response, page_response, parse_uuid, tenant_tx
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from .common import agent_in_scope, approval_view, public_factors, s, transition_view, window

router = APIRouter()
TRANSITIONS = Paging(
    "GET /api/v1/agents/{agent_id}/routing/transitions", "created_at desc,id desc", "tu"
)
HISTORY = Paging("GET /api/v1/agents/{agent_id}/health/history", "evaluated_at,id", "tu")
METRICS = Paging("GET /api/v1/agents/{agent_id}/metrics", "bucket_start,provider,model", "tss")
CHECKPOINTS = Paging("GET /api/v1/agents/{agent_id}/checkpoints", "created_at,id", "tu")
HISTORY_WINDOW = timedelta(days=3)
GRAINS: dict[str, tuple[str, timedelta, timedelta]] = {
    # grain -> (source table, default window, maximum window)
    "1m": ("agent_metrics_1m", timedelta(hours=1), timedelta(days=1)),
    "5m": ("agent_metrics_5m", timedelta(hours=6), timedelta(days=7)),
    "15m": ("agent_metrics_5m", timedelta(hours=24), timedelta(days=14)),
    "1h": ("agent_metrics_1h", timedelta(days=7), timedelta(days=90)),
}
STEP_RE = re.compile(r"^(\d+)(s|m|h)$")
_TRANSITION_SQL = (
    "SELECT t.*, (SELECT u.id FROM sibyl.routing_transition u WHERE u.tenant_id = t.tenant_id"
    " AND u.inverse_of = t.id) AS undone_by FROM sibyl.routing_transition t"
)


@router.get(API_PREFIX + "/agents/{agent_id}/routing")
async def get_routing_state(
    request: Request,
    agent_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getRoutingState"))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    aid = parse_uuid(agent_id)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        await agent_in_scope(conn, ctx, aid)
        rs = await conn.fetchrow(
            "SELECT * FROM sibyl.routing_state WHERE tenant_id = $1 AND agent_id = $2",
            ctx.tenant_id,
            aid,
        )
        if rs is None:
            raise ProblemError("not_found", "the agent has no routing state yet")
        last = None
        if rs["last_transition_id"] is not None:
            last = await conn.fetchrow(
                _TRANSITION_SQL + " WHERE t.tenant_id = $1 AND t.id = $2",
                ctx.tenant_id,
                rs["last_transition_id"],
            )
        pending = None
        if rs["approval_id"] is not None:
            pending = await conn.fetchrow(
                "SELECT * FROM sibyl.approval WHERE tenant_id = $1 AND id = $2 AND state ="
                " 'pending'",
                ctx.tenant_id,
                rs["approval_id"],
            )
    etag = etag_for_version(rs["routing_version"])
    if if_none_match_hit(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    is_key = ctx.principal is not None and ctx.principal.kind is PrincipalKind.API_KEY
    body = {
        "agent_id": str(aid),
        "state": rs["state"],
        "target_kind": rs["target_kind"],
        "target_provider_id": s(rs["target_provider_id"]),
        "target_model_id": s(rs["target_model_id"]),
        "target_agent_id": s(rs["target_agent_id"]),
        "current_step_id": s(rs["current_step_id"]),
        "canary_pct": rs["canary_pct"],
        "routing_version": rs["routing_version"],
        "operator_hold_until": iso(rs["operator_hold_until"]),
        "state_since": iso(rs["state_since"]),
        # Keys (SDK resolve_route) get the routing facts only, not the decision record.
        "last_transition": transition_view(last) if last is not None and not is_key else None,
        "pending_approval": approval_view(pending) if pending is not None and not is_key else None,
    }
    return json_response(body, headers={"ETag": etag})


@router.get(API_PREFIX + "/agents/{agent_id}/routing/transitions")
async def list_routing_transitions(
    request: Request,
    agent_id: str,
    ctx: Annotated[AuthContext, Depends(guard("listRoutingTransitions"))],
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    aid = parse_uuid(agent_id)
    filters = {"agent_id": aid}
    size, after = TRANSITIONS.params(limit, cursor, filters)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        await agent_in_scope(conn, ctx, aid)
        rows = await conn.fetch(
            _TRANSITION_SQL + " WHERE t.tenant_id = $1 AND t.agent_id = $2"
            " AND ($3::timestamptz IS NULL OR (t.created_at, t.id) < ($3, $4::uuid))"
            " ORDER BY t.created_at DESC, t.id DESC LIMIT $5",
            ctx.tenant_id,
            aid,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    return page_response(
        request,
        TRANSITIONS,
        list(rows),
        size,
        lambda r: (r["created_at"], r["id"]),
        filters,
        transition_view,
    )


# ---- health and risk ---------------------------------------------------------------------------

_LATEST_SNAPSHOT = (
    "SELECT h.*, coalesce((c.config #>> '{provisional,min_requests_1h}')::int,"
    " (c.config #>> '{defaults,provisional,min_requests_1h}')::int, 50) AS events_needed"
    " FROM sibyl.health_snapshot h LEFT JOIN sibyl.scoring_config c"
    " ON c.tenant_id = h.tenant_id AND c.id = h.scoring_config_id"
    " WHERE h.tenant_id = $1 AND h.agent_id = $2 ORDER BY h.evaluated_at DESC, h.id DESC LIMIT 1"
)


def health_document(tenant: UUID, row: Any) -> dict[str, Any]:
    """``sibyl-health/1`` (``sibyl_schemas.models.health.HealthDocument``)."""
    coverage = float(row["observation_coverage"])
    return {
        "schema": "sibyl-health/1",
        "health_snapshot_id": str(row["id"]),
        "tenant_id": str(tenant),
        "agent_id": str(row["agent_id"]),
        "computed_at": iso(row["evaluated_at"]),
        "window": {
            "start": iso(row["window_start"]),
            "end": iso(row["window_end"]),
            "grain_s": row["grain_s"],
        },
        "score": row["score"],
        "status": row["band"],
        "provisional": {
            "flag": row["provisional"],
            "events_seen": row["events_seen"],
            "events_needed": row["events_needed"],
            "observation_coverage": coverage,
        },
        "factors": public_factors(row["factors"]),
        "horizons": row["horizons"] or {},
        "predicted_failure_mode": row["predicted_failure_mode"],
        "recommended_action": row["recommended_action"],
        "feature_snapshot_ref": f"fs_{row['feature_snapshot_id']}"
        if row["feature_snapshot_id"]
        else None,
        "policy_version": row["policy_version"],
        "routing_state": row["routing_state_at"],
    }


# Zero-penalty factors (``?verbose=1``, ML.md §3.6): the engine stores only penalising
# factors, so the other rules of the snapshot's scoring config that apply to the agent's tier
# (cap > 0) are listed at read time with penalty 0 and their tier threshold.
_ZERO_FACTOR_SQL = """
SELECT r.code, r.kind, r.comparator, r.thresholds -> 'tiers' -> a.tier::text AS tier_cfg,
       coalesce((c.config -> 'caps' -> r.code ->> a.tier::text)::double precision,
                (r.thresholds -> 'tiers' -> a.tier::text ->> 'cap')::double precision, 0) AS cap
  FROM sibyl.alert_rule r
  JOIN sibyl.agent a ON a.tenant_id = r.tenant_id AND a.id = $2
  LEFT JOIN sibyl.scoring_config c ON c.tenant_id = r.tenant_id AND c.id = $3
 WHERE r.tenant_id = $1 AND r.enabled AND r.scope = 'agent'
 ORDER BY r.code
"""


def _zero_factor(row: Any, agent: UUID) -> dict[str, Any]:
    tier_cfg = row["tier_cfg"] or {}
    threshold = tier_cfg.get("threshold") if isinstance(tier_cfg, dict) else None
    return {
        "rule": row["code"],
        "weight": round(float(row["cap"]) / 100, 4),
        "penalty": 0,
        "value": 0.0,
        "threshold": threshold if isinstance(threshold, int | float | str) else 0.0,
        "direction": "below" if row["comparator"] == "below" else "above",
        "kind": row["kind"],
        "explanation": f"{row['code']}: no penalty at this snapshot",
        "evidence": f"{API_PREFIX}/agents/{agent}/metrics",
    }


async def zero_penalty_factors(
    conn: Any, tenant: UUID, agent: UUID, scoring_config_id: UUID | None, present: set[str]
) -> list[dict[str, Any]]:
    rows = await conn.fetch(_ZERO_FACTOR_SQL, tenant, agent, scoring_config_id)
    return [
        _zero_factor(r, agent) for r in rows if r["code"] not in present and float(r["cap"]) > 0
    ]


@router.get(API_PREFIX + "/agents/{agent_id}/health")
async def get_agent_health(
    request: Request,
    agent_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getAgentHealth"))],
    if_none_match: Annotated[str | None, Header()] = None,
    verbose: Annotated[bool, Query()] = False,
) -> Response:
    aid = parse_uuid(agent_id)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        await agent_in_scope(conn, ctx, aid)
        row = await conn.fetchrow(_LATEST_SNAPSHOT, ctx.tenant_id, aid)
        if row is None:
            raise ProblemError("no_snapshot_yet")
        document = health_document(ctx.tenant_id, row)
        if verbose:
            present = {f.get("rule") for f in document["factors"] if isinstance(f, dict)}
            document["factors"] = list(document["factors"]) + await zero_penalty_factors(
                conn, ctx.tenant_id, aid, row["scoring_config_id"], {str(p) for p in present}
            )
    etag = f'"{row["id"]}{"-v" if verbose else ""}"'
    if if_none_match_hit(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    return json_response(document, headers={"ETag": etag})


def _step(value: str | None) -> timedelta | None:
    if value is None:
        return None
    match = STEP_RE.fullmatch(value)
    if match is None:
        raise ProblemError("validation_failed", "step looks like 30s, 5m or 1h")
    amount, unit = int(match.group(1)), match.group(2)
    step = timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours"}[unit]: amount})
    if not timedelta(seconds=10) <= step <= timedelta(hours=24):
        raise ProblemError("validation_failed", "step must be between 10s and 24h")
    return step


@router.get(API_PREFIX + "/agents/{agent_id}/health/history")
async def get_agent_health_history(
    request: Request,
    agent_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getAgentHealthHistory"))],
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    step: Annotated[str | None, Query(max_length=8)] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    aid = parse_uuid(agent_id)
    lo, hi = window(start, end, now=ctx.now, default=HISTORY_WINDOW, maximum=HISTORY_WINDOW)
    bucket = _step(step)
    filters = {"agent_id": aid, "from": start, "to": end, "step": step}
    size, after = HISTORY.params(limit, cursor, filters)
    # With a step, the last snapshot of each bucket stands for it (change-based writes).
    sql = (
        "SELECT DISTINCT ON (date_bin($5::interval, evaluated_at, timestamptz '2000-01-01'))"
        " evaluated_at, id, score, band, provisional FROM sibyl.health_snapshot"
        " WHERE tenant_id = $1 AND agent_id = $2 AND evaluated_at >= $3 AND evaluated_at < $4"
        " ORDER BY date_bin($5::interval, evaluated_at, timestamptz '2000-01-01'),"
        " evaluated_at DESC, id DESC"
        if bucket
        else "SELECT evaluated_at, id, score, band, provisional FROM sibyl.health_snapshot"
        " WHERE tenant_id = $1 AND agent_id = $2 AND evaluated_at >= $3 AND evaluated_at < $4"
        " AND $5::interval IS NULL"
    )
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        await agent_in_scope(conn, ctx, aid)
        rows = await conn.fetch(
            f"SELECT * FROM ({sql}) p"  # noqa: S608 (constant SQL)
            " WHERE ($6::timestamptz IS NULL OR (p.evaluated_at, p.id) > ($6, $7::uuid))"
            " ORDER BY p.evaluated_at, p.id LIMIT $8",
            ctx.tenant_id,
            aid,
            lo,
            hi,
            bucket,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    return page_response(
        request,
        HISTORY,
        list(rows),
        size,
        lambda r: (r["evaluated_at"], r["id"]),
        filters,
        lambda r: {
            "evaluated_at": iso(r["evaluated_at"]),
            "score": r["score"],
            "band": r["band"],
            "provisional": r["provisional"],
        },
    )


_ABSTAIN = {
    "probability_band": "0.05",
    "confidence": "low",
    "contributing_rules": [],
    "abstained": True,
}
_HORIZONS = {"15m": 900, "1h": 3600, "24h": 86400}
# The frozen ``RiskHorizon`` (core.risk): the stored sibyl-health/1 horizons also carry
# ``source`` / ``predicted_failure_mode``, which the risk read must not copy (lane P CR).
RISK_HORIZON_KEYS = (
    "horizon_s",
    "probability_band",
    "probability",
    "confidence",
    "contributing_rules",
    "abstained",
)


def risk_horizon(seconds: int, stored: Any) -> dict[str, Any]:
    merged = {"horizon_s": seconds, "probability": None, **_ABSTAIN}
    if isinstance(stored, dict):
        merged.update({k: v for k, v in stored.items() if k in RISK_HORIZON_KEYS})
    merged["horizon_s"] = seconds
    return {k: merged[k] for k in RISK_HORIZON_KEYS}


@router.get(API_PREFIX + "/agents/{agent_id}/risk")
async def get_agent_risk(
    request: Request, agent_id: str, ctx: Annotated[AuthContext, Depends(guard("getAgentRisk"))]
) -> Response:
    aid = parse_uuid(agent_id)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        await agent_in_scope(conn, ctx, aid)
        row = await conn.fetchrow(_LATEST_SNAPSHOT, ctx.tenant_id, aid)
    if row is None:
        raise ProblemError("no_snapshot_yet")
    stored = row["horizons"] or {}
    horizons = {
        name: risk_horizon(seconds, stored.get(name)) for name, seconds in _HORIZONS.items()
    }
    leading = sorted({r for h in horizons.values() for r in h.get("contributing_rules") or []})
    return json_response(
        {
            "agent_id": str(aid),
            "evaluated_at": iso(row["evaluated_at"]),
            "horizons": horizons,
            "predicted_failure_mode": row["predicted_failure_mode"],
            "recommended_action": row["recommended_action"] or "none",
            "leading_rules_firing": leading,
            "rules_source": row["rules_source"],
        }
    )


# ---- metrics -----------------------------------------------------------------------------------


def _metric_sql(grain: str) -> str:
    table = GRAINS[grain][0]
    bucket = (
        "date_bin('15 minutes', bucket_start, timestamptz '2000-01-01')"
        if grain == "15m"
        else "bucket_start"
    )
    return (
        f"SELECT {bucket} AS bucket_start, provider, model,"  # noqa: S608 (whitelisted grain)
        " sum(request_count)::bigint AS requests, sum(error_count)::bigint AS errors,"
        " sum(tokens_in)::bigint AS tokens_in, sum(tokens_out)::bigint AS tokens_out,"
        " round(sum(cost_usd), 4) AS cost_usd, sibyl.hist_sum(latency_hist) AS hist"
        f" FROM sibyl.{table} WHERE tenant_id = $1 AND agent_id = $2"
        " AND bucket_start >= $3 AND bucket_start < $4"
        " AND ($5::text IS NULL OR provider = $5) AND ($6::text IS NULL OR model = $6)"
        f" GROUP BY 1, 2, 3"
    )


@router.get(API_PREFIX + "/agents/{agent_id}/metrics")
async def get_agent_metrics(
    request: Request,
    agent_id: str,
    grain: Annotated[Literal["1m", "5m", "15m", "1h"], Query()],
    ctx: Annotated[AuthContext, Depends(guard("getAgentMetrics"))],
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    provider: Annotated[str | None, Query(max_length=60)] = None,
    model: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    aid = parse_uuid(agent_id)
    _, default, maximum = GRAINS[grain]
    lo, hi = window(start, end, now=ctx.now, default=default, maximum=maximum, code="grain_range")
    filters = {
        "agent_id": aid,
        "grain": grain,
        "from": start,
        "to": end,
        "provider": provider,
        "model": model,
    }
    size, after = METRICS.params(limit, cursor, filters)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        await agent_in_scope(conn, ctx, aid)
        rows = await conn.fetch(
            f"SELECT m.*, sibyl.hist_quantile(m.hist, 0.5) AS p50,"  # noqa: S608 (constant SQL)
            " sibyl.hist_quantile(m.hist, 0.95) AS p95, sibyl.hist_quantile(m.hist, 0.99) AS p99"
            f" FROM ({_metric_sql(grain)}) m"
            " WHERE ($7::timestamptz IS NULL OR (m.bucket_start, m.provider, m.model) > ($7,"
            " $8::text, $9::text))"
            " ORDER BY m.bucket_start, m.provider, m.model LIMIT $10",
            ctx.tenant_id,
            aid,
            lo,
            hi,
            provider,
            model,
            after[0] if after else None,
            after[1] if after else None,
            after[2] if after else None,
            size + 1,
        )

    def view(r: Any) -> dict[str, Any]:
        has_latency = r["requests"] > 0
        return {
            "bucket_start": iso(r["bucket_start"]),
            "grain": grain,
            "provider": r["provider"],
            "model": r["model"],
            "requests": r["requests"],
            "errors": r["errors"],
            "tokens_in": r["tokens_in"],
            "tokens_out": r["tokens_out"],
            "cost_usd": f"{r['cost_usd']:.4f}",
            "p50_ms": r["p50"] if has_latency else None,
            "p95_ms": r["p95"] if has_latency else None,
            "p99_ms": r["p99"] if has_latency else None,
        }

    return page_response(
        request,
        METRICS,
        list(rows),
        size,
        lambda r: (r["bucket_start"], r["provider"], r["model"]),
        filters,
        view,
    )


# ---- checkpoints -------------------------------------------------------------------------------


@router.get(API_PREFIX + "/agents/{agent_id}/checkpoints")
async def list_agent_checkpoints(
    request: Request,
    agent_id: str,
    ctx: Annotated[AuthContext, Depends(guard("listAgentCheckpoints"))],
    task_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    """Inline ``state`` is content: it is returned only to a caller who could read the
    checkpoint payload unaudited (``packets:read``, not an auditor's A grant); everyone else gets
    the metadata and ``state_sha256``, and reads the state through ``/payloads`` (audited)."""
    aid = parse_uuid(agent_id)
    filters = {"agent_id": aid, "task_id": task_id}
    size, after = CHECKPOINTS.params(limit, cursor, filters)
    principal = ctx.principal
    packets = principal.grants.get("packets:read") if principal is not None else None
    payloads = principal.grants.get("payloads:read") if principal is not None else None
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        agent = await agent_in_scope(conn, ctx, aid)
        inline = (
            packets is not None
            and not packets.audited
            and payloads is not None
            and not payloads.audited
            and (packets.group_ids is None or agent["agent_group_id"] in packets.group_ids)
        )
        rows = await conn.fetch(
            "SELECT id, agent_id, task_id, seq, step_index, step_name, state, state_ref_id,"
            " state_sha256, capture_mode, created_at FROM sibyl.checkpoint"
            " WHERE tenant_id = $1 AND agent_id = $2 AND ($3::uuid IS NULL OR task_id = $3)"
            " AND ($4::timestamptz IS NULL OR (created_at, id) > ($4, $5::uuid))"
            " ORDER BY created_at, id LIMIT $6",
            ctx.tenant_id,
            aid,
            task_id,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )

    def view(r: Any) -> dict[str, Any]:
        return {
            "id": str(r["id"]),
            "agent_id": str(r["agent_id"]),
            "task_id": str(r["task_id"]),
            "seq": r["seq"],
            "step_index": r["step_index"],
            "step_name": r["step_name"],
            "state": r["state"] if inline else None,
            "state_ref_id": s(r["state_ref_id"]),
            "state_sha256": bytes(r["state_sha256"]).hex() if r["state_sha256"] else None,
            "capture_mode": r["capture_mode"],
            "created_at": iso(r["created_at"]),
        }

    return page_response(
        request, CHECKPOINTS, list(rows), size, lambda r: (r["created_at"], r["id"]), filters, view
    )
