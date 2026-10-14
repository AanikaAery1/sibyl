# ruff: noqa: S608 -- SQL is built once at import from fixed column constants
"""events -> agent_metrics_1m -> 5m -> 1h, plus provider_metrics_5m (ML.md §7.2; db §2).

One call is one tenant's tick, inside the caller's ``tenant_tx`` (so the cursor and every
rollup row commit together or not at all):

1. Read new events through the commit-ordered cursor (R60): rows strictly after
   ``(last_xid, last_id)`` in ``consumer_offsets('rollup', tenant, 'events')`` and strictly below
   ``sibyl.commit_horizon()``, so a transaction that commits late is never skipped.
2. Their ``(agent, minute)`` pairs are the dirty set. Late events dirty their true ``ts`` bucket.
3. Each dirty 1m bucket is recomputed from scratch from ``events`` and replaced (delete +
   insert), so crashes, replays and late events are harmless. Buckets older than the 1m
   retention (14 d) skip the 1m grain and recompute their 5m bucket directly (``children_1m=0``).
4. Dirty 5m parents are recomputed from their 1m children, dirty 1h parents from 5m, and the
   provider 5m rows from every agent's 5m row in the dirty buckets.
5. The cursor advances to the last event read; ``last_created_at`` records freshness for the
   rollup-lag SLI (now when caught up, else the last consumed ``received_at``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from .aggregate import (
    AGENT_COLUMNS,
    BIGINT_COLUMNS,
    DECIMAL_COLUMNS,
    HIST_COLUMNS,
    PROVIDER_COLUMNS,
    ROLLED_EVENT_TYPES,
    aggregate_events,
    bucket_start,
    sql_agg,
)

CONSUMER_GROUP = "rollup"
CURSOR_TOPIC = "events"
BATCH_EVENTS = 20_000
RETENTION_1M = timedelta(days=14)
M1, M5, H1 = 60, 300, 3600
ALL_MODELS = "*"

_CURSOR_SQL = (
    "SELECT last_xid, last_id FROM sibyl.consumer_offsets "
    "WHERE consumer_group = $1 AND tenant_id = $2 AND topic = $3"
)
_HORIZON_SQL = "SELECT sibyl.commit_horizon()"
_NEW_EVENTS_SQL = (
    "SELECT xid, event_id, agent_id, ts, received_at FROM sibyl.events "
    "WHERE tenant_id = $1 AND (xid, event_id) > ($2::xid8, $3::uuid) AND xid < $4::xid8 "
    "ORDER BY xid, event_id LIMIT $5"
)
_SAVE_CURSOR_SQL = (
    "INSERT INTO sibyl.consumer_offsets (consumer_group, tenant_id, topic, last_xid, last_id, "
    "last_created_at) VALUES ($1, $2, $3, $4::xid8, $5, $6) "
    "ON CONFLICT (consumer_group, tenant_id, topic) DO UPDATE SET last_xid = EXCLUDED.last_xid, "
    "last_id = EXCLUDED.last_id, last_created_at = EXCLUDED.last_created_at"
)
_EVENT_COLUMNS = """
  e.agent_id, coalesce(e.provider, '') AS p, coalesce(e.model, '') AS m, e.ts, e.event_type,
  e.status, e.error_class, e.http_status, e.latency_ms, e.ttfb_ms, e.tokens_in, e.tokens_out,
  e.cost_usd, e.route_decision, e.policy_state, e.is_late, e.error_type,
  e.attrs->'retry'->>'attempt' AS retry_attempt,
  e.attrs->'retry'->>'inline_fallback_used' AS inline_fb,
  e.attrs->'retry'->>'breaker_state' AS breaker_state,
  e.attrs->>'action' AS action,
  e.attrs->'ratelimit'->>'headroom' AS rl_headroom,
  e.attrs->'ratelimit'->>'remaining_requests' AS rl_rem,
  e.attrs->'ratelimit'->>'limit_requests' AS rl_lim,
  e.attrs->'context'->>'utilisation' AS ctx,
  coalesce(e.attrs->'finish_reasons' ?| ARRAY['length', 'max_tokens'], false) AS fin_length,
  coalesce(e.attrs->'finish_reasons' ?| ARRAY['content_filter', 'refusal', 'safety'], false)
    AS fin_filter,
  coalesce(e.attrs->'finish_reasons' ? 'tool_calls', false) AS fin_tools,
  e.attrs->'quality'->>'refusal' AS refusal,
  e.attrs->>'output_chars' AS output_chars,
  e.attrs->>'tool_name' AS tool_name, e.task_id,
  e.attrs->>'schema_valid' AS schema_valid,
  e.attrs->>'outcome' AS outcome,
  e.attrs->>'score' AS fb_score
"""
_BUCKET_EVENTS_SQL = f"""
SELECT {_EVENT_COLUMNS}
  FROM unnest($2::uuid[], $3::timestamptz[]) AS d(agent_id, b)
  JOIN sibyl.events e ON e.tenant_id = $1 AND e.agent_id = d.agent_id
                     AND e.ts >= d.b AND e.ts < d.b + $4::interval
 WHERE e.event_type = ANY($5::text[])
"""


@dataclass(frozen=True)
class RollupResult:
    events: int
    buckets_1m: int
    buckets_5m: int
    buckets_1h: int
    provider_rows: int
    carryover: bool
    lag_s: float
    closed_5m: tuple[tuple[UUID, datetime], ...] = ()


def _sql_type(col: str) -> str:
    if col in HIST_COLUMNS:
        return "int[]"
    if col in DECIMAL_COLUMNS:
        return "numeric[]"
    if col in BIGINT_COLUMNS:
        return "int8[]"
    return "int[]"


def _insert_sql(
    table: str,
    key_cols: Sequence[str],
    key_types: Sequence[str],
    columns: Sequence[str],
    extra: Sequence[str] = (),
) -> str:
    """``INSERT … SELECT FROM unnest(...) ON CONFLICT DO UPDATE``: one statement per grain.

    Replace, never add: every column takes the recomputed value. An upsert (not delete +
    insert) keeps the current bucket's rows HOT-updatable instead of bloating them every tick.
    Histograms travel flattened (``int[]`` of ``40 x rows``) and are sliced back per ordinal.
    """
    sel = ["$1"]
    names = ["tenant_id"]
    unnest_args: list[str] = []
    aliases: list[str] = []
    n = 2
    for col, typ in zip(key_cols, key_types, strict=True):
        unnest_args.append(f"${n}::{typ}[]")
        aliases.append(col)
        names.append(col)
        sel.append(f"u.{col}")
        n += 1
    hist_params: dict[str, int] = {}
    for col in (*columns, *extra):
        if col in HIST_COLUMNS:
            hist_params[col] = n
        else:
            unnest_args.append(f"${n}::{_sql_type(col)}")
            aliases.append(col)
        names.append(col)
        n += 1
    for col in (*columns, *extra):
        if col in HIST_COLUMNS:
            p = hist_params[col]
            sel.append(f"(${p}::int[])[(u.o - 1) * 40 + 1 : u.o * 40]")
        else:
            sel.append(f"u.{col}")
    updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in (*columns, *extra, "computed_at"))
    return (
        f"INSERT INTO sibyl.{table} ({', '.join(names)}, computed_at) "
        f"SELECT {', '.join(sel)}, clock_timestamp() "
        f"FROM unnest({', '.join(unnest_args)}) WITH ORDINALITY AS u({', '.join(aliases)}, o) "
        f"ON CONFLICT (tenant_id, {', '.join(key_cols)}) DO UPDATE SET {updates}"
    )


def _insert_args(
    rows: Sequence[tuple[tuple[Any, ...], Mapping[str, Any]]], key_len: int, columns: Sequence[str]
) -> list[Any]:
    args: list[Any] = [[k[i] for k, _ in rows] for i in range(key_len)]
    for col in columns:
        if col in HIST_COLUMNS:
            flat: list[int] = []
            for _, r in rows:
                flat.extend(int(x) for x in r[col])
            args.append(flat)
        else:
            args.append([r[col] for _, r in rows])
    return args


AGENT_KEY = ("agent_id", "provider", "model", "bucket_start")
AGENT_KEY_TYPES = ("uuid", "text", "text", "timestamptz")
_INSERT_1M = _insert_sql("agent_metrics_1m", AGENT_KEY, AGENT_KEY_TYPES, AGENT_COLUMNS)
_INSERT_5M = _insert_sql(
    "agent_metrics_5m", AGENT_KEY, AGENT_KEY_TYPES, AGENT_COLUMNS, ("children_1m",)
)


def _parent_sql(child: str, parent: str, width: str, *, children: bool) -> str:
    """Recompute parent buckets from their children in one statement (no client round trip)."""
    cols = list(AGENT_COLUMNS) + (["children_1m"] if children else [])
    aggs = [sql_agg(c) for c in AGENT_COLUMNS] + (["count(*)::smallint"] if children else [])
    updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in (*cols, "computed_at"))
    return (
        f"INSERT INTO sibyl.{parent} (tenant_id, agent_id, provider, model, bucket_start, "
        f"{', '.join(cols)}, computed_at) "
        f"SELECT $1, t.agent_id, t.provider, t.model, d.b, {', '.join(aggs)}, clock_timestamp() "
        f"FROM unnest($2::uuid[], $3::timestamptz[]) AS d(a, b) "
        f"JOIN sibyl.{child} t ON t.tenant_id = $1 AND t.agent_id = d.a "
        f"AND t.bucket_start >= d.b AND t.bucket_start < d.b + interval '{width}' "
        "GROUP BY t.agent_id, t.provider, t.model, d.b "
        f"ON CONFLICT (tenant_id, agent_id, provider, model, bucket_start) DO UPDATE SET {updates}"
    )


def _provider_sql() -> str:
    cols = [*PROVIDER_COLUMNS, "agent_count"]
    aggs = [sql_agg(c) for c in PROVIDER_COLUMNS] + ["count(DISTINCT t.agent_id)::smallint"]
    updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in (*cols, "computed_at"))
    return (
        "INSERT INTO sibyl.provider_metrics_5m (tenant_id, provider, model, bucket_start, "
        f"{', '.join(cols)}, computed_at) "
        f"SELECT $1, t.provider, CASE WHEN GROUPING(t.model) = 1 THEN '{ALL_MODELS}' "
        f"ELSE t.model END, t.bucket_start, {', '.join(aggs)}, clock_timestamp() "
        "FROM sibyl.agent_metrics_5m t "
        "WHERE t.tenant_id = $1 AND t.bucket_start = ANY($2::timestamptz[]) AND t.provider <> '' "
        "GROUP BY GROUPING SETS ((t.provider, t.model, t.bucket_start), "
        "(t.provider, t.bucket_start)) "
        f"ON CONFLICT (tenant_id, provider, model, bucket_start) DO UPDATE SET {updates}"
    )


_PARENT_5M = _parent_sql("agent_metrics_1m", "agent_metrics_5m", "5 minutes", children=True)
_PARENT_1H = _parent_sql("agent_metrics_5m", "agent_metrics_1h", "1 hour", children=False)
_PROVIDER_5M = _provider_sql()


async def _ensure_partitions(
    conn: Any, table: str, buckets: Iterable[datetime], width: timedelta
) -> None:
    starts = sorted(set(buckets))
    if starts:
        await conn.fetchval(
            "SELECT sibyl.partition_ensure($1, $2, $3)", table, starts[0], starts[-1] + width
        )


async def _replace(
    conn: Any,
    tenant: UUID,
    insert_sql: str,
    rows: Sequence[tuple[tuple[Any, ...], Mapping[str, Any]]],
    columns: Sequence[str],
) -> None:
    if rows:
        await conn.execute(insert_sql, tenant, *_insert_args(rows, 4, columns))


async def _events_for(
    conn: Any, tenant: UUID, keys: Sequence[tuple[UUID, datetime]], width_s: int
) -> list[Mapping[str, Any]]:
    if not keys:
        return []
    return list(
        await conn.fetch(
            _BUCKET_EVENTS_SQL,
            tenant,
            [a for a, _ in keys],
            [b for _, b in keys],
            timedelta(seconds=width_s),
            list(ROLLED_EVENT_TYPES),
        )
    )


async def _parents(
    conn: Any, tenant: UUID, sql: str, parents: Sequence[tuple[UUID, datetime]]
) -> int:
    if not parents:
        return 0
    status = await conn.execute(sql, tenant, [a for a, _ in parents], [b for _, b in parents])
    return int(str(status).rsplit(" ", 1)[-1])


async def _provider_rows(conn: Any, tenant: UUID, buckets: Sequence[datetime]) -> int:
    if not buckets:
        return 0
    status = await conn.execute(_PROVIDER_5M, tenant, list(buckets))
    return int(str(status).rsplit(" ", 1)[-1])


async def rollup_tenant(
    conn: Any,
    tenant: UUID,
    *,
    now: datetime | None = None,
    batch: int = BATCH_EVENTS,
) -> RollupResult:
    """One rollup unit for one tenant on a connection already inside its ``tenant_tx``."""
    now = now or await conn.fetchval("SELECT now()")
    cur = await conn.fetchrow(_CURSOR_SQL, CONSUMER_GROUP, tenant, CURSOR_TOPIC)
    last_xid, last_id = (cur["last_xid"], cur["last_id"]) if cur else (0, UUID(int=0))
    horizon = await conn.fetchval(_HORIZON_SQL)
    new = await conn.fetch(_NEW_EVENTS_SQL, tenant, last_xid, last_id, horizon, batch)
    carryover = len(new) >= batch
    if new:
        last_xid, last_id = new[-1]["xid"], new[-1]["event_id"]
    lag_s = (now - new[-1]["received_at"]).total_seconds() if carryover else 0.0
    await conn.execute(
        _SAVE_CURSOR_SQL,
        CONSUMER_GROUP,
        tenant,
        CURSOR_TOPIC,
        last_xid,
        last_id,
        new[-1]["received_at"] if carryover else now,
    )
    dirty_min = {(r["agent_id"], bucket_start(r["ts"], M1)) for r in new if r["agent_id"]}
    if not dirty_min:
        return RollupResult(len(new), 0, 0, 0, 0, carryover, lag_s)

    floor_1m = now - RETENTION_1M
    recent = sorted(k for k in dirty_min if k[1] >= floor_1m)
    old5 = sorted({(a, bucket_start(b, M5)) for a, b in dirty_min if b < floor_1m})

    # 1m from events (recent buckets only)
    await _ensure_partitions(conn, "agent_metrics_1m", (b for _, b in recent), timedelta(minutes=1))
    rows_1m = aggregate_events(await _events_for(conn, tenant, recent, M1), M1)
    await _replace(conn, tenant, _INSERT_1M, sorted(rows_1m.items()), AGENT_COLUMNS)

    # 5m from 1m children, or from events beyond the 1m retention
    dirty5 = sorted({(a, bucket_start(b, M5)) for a, b in recent})
    all5 = sorted({*dirty5, *old5})
    await _ensure_partitions(conn, "agent_metrics_5m", (b for _, b in all5), timedelta(minutes=5))
    await _parents(conn, tenant, _PARENT_5M, dirty5)
    if old5:
        direct = aggregate_events(await _events_for(conn, tenant, old5, M5), M5)
        rows_5m = [(k, {**r, "children_1m": 0}) for k, r in sorted(direct.items())]
        await _replace(conn, tenant, _INSERT_5M, rows_5m, (*AGENT_COLUMNS, "children_1m"))

    # 1h from 5m
    dirty1h = sorted({(a, bucket_start(b, H1)) for a, b in all5})
    await _ensure_partitions(conn, "agent_metrics_1h", (b for _, b in dirty1h), timedelta(hours=1))
    await _parents(conn, tenant, _PARENT_1H, dirty1h)

    # provider 5m across every agent in the dirty buckets
    buckets5 = sorted({b for _, b in all5})
    await _ensure_partitions(conn, "provider_metrics_5m", buckets5, timedelta(minutes=5))
    provider_rows = await _provider_rows(conn, tenant, buckets5)

    closed = tuple(k for k in all5 if k[1] + timedelta(minutes=5) <= now)
    return RollupResult(
        len(new), len(recent), len(all5), len(dirty1h), provider_rows, carryover, lag_s, closed
    )
