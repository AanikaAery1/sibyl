"""Drift reads and writes on the tick's tenant connection (sibyl_worker, RLS-scoped).

Samples come from ``sibyl.events`` through the ``(tenant_id, agent_id, ts)`` index, one
bounded statement per baseline (``max_samples`` calls, ``max_tool_samples`` tool calls). The
flags are derived exactly as the rollup derives its counters (``worker.rollup.pipeline``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from .config import TenantThresholds
from .features import SCHEMA_ERROR_TYPES, CallSample, ToolSample, Window

_THRESHOLDS_SQL = "SELECT * FROM sibyl.drift_thresholds WHERE tenant_id = $1"

_DISCOVER_SQL = """
SELECT e.agent_id, coalesce(e.provider, '') AS provider, e.model, min(e.ts) AS first_ts,
       count(*)::int AS n
  FROM sibyl.events e
  JOIN sibyl.agent a ON a.tenant_id = e.tenant_id AND a.id = e.agent_id AND a.lifecycle <> 'retired'
 WHERE e.tenant_id = $1 AND e.event_type = 'gen_ai.request' AND e.ts >= $2 AND e.ts <= $3
   AND e.model IS NOT NULL AND char_length(e.model) BETWEEN 1 AND 256
   AND char_length(coalesce(e.provider, '')) <= 64
 GROUP BY 1, 2, 3
 ORDER BY 1, 2, 3
 LIMIT $4
"""
_CURRENT_SQL = """
SELECT * FROM sibyl.drift_baseline
 WHERE tenant_id = $1 AND state <> 'superseded'
 ORDER BY coalesce(last_evaluated_at, '-infinity'::timestamptz), created_at
"""
_CREATE_SQL = """
INSERT INTO sibyl.drift_baseline (tenant_id, agent_id, provider, model, window_start)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, agent_id, provider, model) WHERE state <> 'superseded' DO NOTHING
RETURNING id
"""
_COUNT_SQL = """
SELECT count(*)::int FROM sibyl.events
 WHERE tenant_id = $1 AND agent_id = $2 AND coalesce(provider, '') = $3 AND model = $4
   AND event_type = 'gen_ai.request' AND ts >= $5 AND ts < $6
"""
_CALL_COLUMNS = """
SELECT tokens_out, tokens_in, latency_ms, status, error_class,
       (status = 'ok'
        AND (coalesce(attrs->'finish_reasons' ?| ARRAY['content_filter', 'refusal', 'safety'],
                      false)
             OR lower(coalesce(attrs->'quality'->>'refusal', '')) IN ('true', 't', '1')))
         AS refusal,
       coalesce(attrs->'finish_reasons' ?| ARRAY['length', 'max_tokens'], false) AS truncated,
       coalesce(attrs->'finish_reasons' ? 'tool_calls', false) AS tool_call,
       left(coalesce(response_model, attrs->>'response_model'), 128) AS response_model,
       left(attrs->>'system_fingerprint', 128) AS fingerprint, ts
  FROM sibyl.events
 WHERE tenant_id = $1 AND agent_id = $2 AND coalesce(provider, '') = $3 AND model = $4
   AND event_type = 'gen_ai.request' AND ts >= $5 AND ts < $6
"""
_CALLS_OLDEST_SQL = _CALL_COLUMNS + " ORDER BY ts LIMIT $7"
_CALLS_NEWEST_SQL = _CALL_COLUMNS + " ORDER BY ts DESC LIMIT $7"
_TOOLS_SQL = """
SELECT task_id::text AS task_id, left(attrs->>'tool_name', 128) AS tool, ts,
       (lower(coalesce(attrs->>'schema_valid', '')) IN ('false', 'f', '0')
        OR coalesce(error_type = ANY($6::text[]), false)) AS schema_fail
  FROM sibyl.events
 WHERE tenant_id = $1 AND agent_id = $2 AND event_type = 'tool.call' AND ts >= $3 AND ts < $4
 ORDER BY ts DESC
 LIMIT $5
"""
_FREEZE_SQL = """
UPDATE sibyl.drift_baseline
   SET state = 'frozen', window_end = $3, sample_count = $4, tool_sample_count = $5,
       features = $6::jsonb, served_models = $7::text[], fingerprints = $8::text[], frozen_at = $9
 WHERE tenant_id = $1 AND id = $2 AND state = 'collecting'
"""
_SLIDE_SQL = (
    "UPDATE sibyl.drift_baseline SET window_start = $3 WHERE tenant_id = $1 AND id = $2"
    " AND state = 'collecting' AND window_start < $3"
)
_REPORT_SQL = """
INSERT INTO sibyl.drift_report (tenant_id, baseline_id, agent_id, provider, model, evaluated_at,
  window_start, window_end, sample_count, tool_sample_count, verdict, behaviour_evaluated,
  identity_changed, max_ratio, features, identity, config)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16::jsonb,
        $17::jsonb)
RETURNING id
"""
_STREAKS_SQL = """
UPDATE sibyl.drift_baseline SET drift_streak = $3, clear_streak = $4, identity_clear_streak = $5,
  last_evaluated_at = $6
 WHERE tenant_id = $1 AND id = $2
"""
_RETENTION_SQL = """
DELETE FROM sibyl.drift_report
 WHERE tenant_id = $1 AND id IN (SELECT id FROM sibyl.drift_report
                                  WHERE tenant_id = $1 AND evaluated_at < $2
                                  ORDER BY evaluated_at LIMIT $3)
"""
# B24: superseded baselines go 30 days after supersession; their remaining reports first (FK).
_OLD_BASELINES_SQL = """
SELECT id FROM sibyl.drift_baseline
 WHERE tenant_id = $1 AND state = 'superseded' AND superseded_at < $2
 ORDER BY superseded_at LIMIT $3
"""
_BASELINE_REPORTS_SQL = (
    "DELETE FROM sibyl.drift_report WHERE tenant_id = $1 AND baseline_id = ANY($2::uuid[])"
)
_BASELINES_SQL = "DELETE FROM sibyl.drift_baseline WHERE tenant_id = $1 AND id = ANY($2::uuid[])"


@dataclass(frozen=True)
class Key:
    agent_id: UUID
    provider: str
    model: str


async def discover(
    conn: Any, tenant: UUID, since: datetime, now: datetime, limit: int
) -> list[tuple[Key, datetime]]:
    rows = await conn.fetch(_DISCOVER_SQL, tenant, since, now, limit)
    return [(Key(r["agent_id"], r["provider"], r["model"]), r["first_ts"]) for r in rows]


async def tenant_thresholds(conn: Any, tenant: UUID) -> TenantThresholds:
    """The tenant's drift threshold overrides (all ``None`` without a row)."""
    return TenantThresholds.from_row(await conn.fetchrow(_THRESHOLDS_SQL, tenant))


async def current_baselines(conn: Any, tenant: UUID) -> list[dict[str, Any]]:
    return [dict(r) for r in await conn.fetch(_CURRENT_SQL, tenant)]


async def create_baseline(conn: Any, tenant: UUID, key: Key, window_start: datetime) -> UUID | None:
    value = await conn.fetchval(
        _CREATE_SQL, tenant, key.agent_id, key.provider, key.model, window_start
    )
    return None if value is None else UUID(str(value))


async def count_calls(conn: Any, tenant: UUID, key: Key, start: datetime, end: datetime) -> int:
    return int(
        await conn.fetchval(_COUNT_SQL, tenant, key.agent_id, key.provider, key.model, start, end)
    )


def _call(r: Mapping[str, Any]) -> CallSample:
    return CallSample(
        tokens_out=r["tokens_out"],
        tokens_in=r["tokens_in"],
        latency_ms=None if r["latency_ms"] is None else float(r["latency_ms"]),
        status=r["status"],
        error_class=r["error_class"],
        refusal=bool(r["refusal"]),
        truncated=bool(r["truncated"]),
        tool_call=bool(r["tool_call"]),
        response_model=r["response_model"],
        fingerprint=r["fingerprint"],
    )


async def load_window(
    conn: Any,
    tenant: UUID,
    key: Key,
    start: datetime,
    end: datetime,
    *,
    oldest_first: bool,
    max_calls: int,
    max_tools: int,
) -> tuple[Window, datetime | None]:
    """Calls of ``key`` and tool calls of its agent in ``[start, end)``; returns the window and
    the timestamp of the last call taken (``None`` without calls)."""
    sql = _CALLS_OLDEST_SQL if oldest_first else _CALLS_NEWEST_SQL
    rows = await conn.fetch(
        sql, tenant, key.agent_id, key.provider, key.model, start, end, max_calls
    )
    last = max((r["ts"] for r in rows), default=None)
    if oldest_first and last is not None:
        end = min(end, last)
    tool_rows = await conn.fetch(
        _TOOLS_SQL, tenant, key.agent_id, start, end, max_tools, sorted(SCHEMA_ERROR_TYPES)
    )
    tools = tuple(
        ToolSample(r["task_id"], r["tool"], bool(r["schema_fail"]))
        for r in sorted(tool_rows, key=lambda r: r["ts"])
    )
    return Window(tuple(_call(r) for r in rows), tools), last


async def freeze(
    conn: Any,
    tenant: UUID,
    baseline_id: UUID,
    *,
    window_end: datetime,
    window: Window,
    features: Mapping[str, Any],
    served: Sequence[str],
    fingerprints: Sequence[str],
    now: datetime,
) -> bool:
    status = await conn.execute(
        _FREEZE_SQL,
        tenant,
        baseline_id,
        window_end,
        len(window.calls),
        len(window.tools),
        dict(features),
        list(served),
        list(fingerprints),
        now,
    )
    return str(status).endswith(" 1")


async def slide(conn: Any, tenant: UUID, baseline_id: UUID, start: datetime) -> None:
    await conn.execute(_SLIDE_SQL, tenant, baseline_id, start)


async def write_report(conn: Any, tenant: UUID, row: Mapping[str, Any]) -> UUID:
    value = await conn.fetchval(
        _REPORT_SQL,
        tenant,
        row["baseline_id"],
        row["agent_id"],
        row["provider"],
        row["model"],
        row["evaluated_at"],
        row["window_start"],
        row["window_end"],
        row["sample_count"],
        row["tool_sample_count"],
        row["verdict"],
        row["behaviour_evaluated"],
        row["identity_changed"],
        row["max_ratio"],
        list(row["features"]),
        list(row["identity"]),
        dict(row["config"]),
    )
    return UUID(str(value))


async def save_streaks(
    conn: Any,
    tenant: UUID,
    baseline_id: UUID,
    drift: int,
    clear: int,
    identity_clear: int,
    now: datetime,
) -> None:
    cap = 32000  # smallint headroom: a run this long changes nothing anyway
    await conn.execute(
        _STREAKS_SQL,
        tenant,
        baseline_id,
        min(drift, cap),
        min(clear, cap),
        min(identity_clear, cap),
        now,
    )


async def purge_reports(conn: Any, tenant: UUID, before: datetime, batch: int) -> int:
    status = await conn.execute(_RETENTION_SQL, tenant, before, batch)
    return int(str(status).rsplit(" ", 1)[-1])


async def purge_baselines(conn: Any, tenant: UUID, before: datetime, batch: int) -> int:
    """Delete superseded baselines (and any report left on them) superseded before ``before``."""
    ids = [r["id"] for r in await conn.fetch(_OLD_BASELINES_SQL, tenant, before, batch)]
    if not ids:
        return 0
    await conn.execute(_BASELINE_REPORTS_SQL, tenant, ids)
    status = await conn.execute(_BASELINES_SQL, tenant, ids)
    return int(str(status).rsplit(" ", 1)[-1])
