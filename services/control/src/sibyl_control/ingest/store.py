"""SQL for the ingest write path (DATAMODEL §6.1 as amended by R61/T5).

Every function runs on a connection already inside ``tenant_tx`` (RLS on, first statement
``set_tenant``). Multi-row writes use ``unnest`` arrays: one statement per table per batch, all
``ON CONFLICT DO NOTHING`` except the ``call_merge`` upsert. The ``sibyl_ingest`` role holds
exactly the grants these statements need.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sibyl_schemas.values import ActorType

from .normalise.derive import Price
from .normalise.envelope import EVENT_COLUMNS
from .payloads import SealedPayload

Conn = Any


@dataclass(frozen=True)
class TenantInfo:
    status: str
    raw_retention_days: int
    events_per_s: float
    burst: int
    unknown_agent_fail_mode: str | None


@dataclass(frozen=True)
class Policy:
    scope_kind: str
    agent_id: UUID | None
    capture_mode: str
    profile_name: str
    detector_ids: tuple[str, ...]
    profile_hash: bytes
    retention_days: int
    max_payload_bytes: int


@dataclass(frozen=True)
class AgentRow:
    id: UUID
    slug: str
    current_version_id: UUID | None
    fail_mode: str


async def load_tenant(conn: Conn, tenant_id: UUID) -> TenantInfo | None:
    row = await conn.fetchrow(
        "SELECT status, raw_retention_days, ingest_rate_limit, unknown_agent_fail_mode"
        " FROM sibyl.tenant WHERE id = $1",
        tenant_id,
    )
    if row is None:
        return None
    rate = row["ingest_rate_limit"]
    rate = json.loads(rate) if isinstance(rate, str) else rate
    return TenantInfo(
        row["status"],
        row["raw_retention_days"],
        float(rate.get("events_per_s", 500)),
        int(rate.get("burst", 5000)),
        row["unknown_agent_fail_mode"],
    )


async def load_policies(conn: Conn) -> list[Policy]:
    rows = await conn.fetch(
        "SELECT cp.scope_kind, cp.agent_id, cp.capture_mode, cp.payload_retention_days,"
        " cp.max_payload_bytes, rp.name, rp.content_hash,"
        " ARRAY(SELECT d->>'id' FROM jsonb_array_elements(rp.detectors) d) AS detector_ids"
        " FROM sibyl.capture_policy cp JOIN sibyl.redaction_profile rp"
        "   ON rp.tenant_id = cp.tenant_id AND rp.id = cp.redaction_profile_id"
        " WHERE cp.superseded_by IS NULL"
    )
    return [
        Policy(
            r["scope_kind"],
            r["agent_id"],
            r["capture_mode"],
            r["name"],
            tuple(r["detector_ids"]),
            bytes(r["content_hash"]),
            r["payload_retention_days"],
            r["max_payload_bytes"],
        )
        for r in rows
    ]


async def baseline_profile_hash(conn: Conn) -> bytes | None:
    """The tenant's ``secrets_only`` system profile hash (the floor every event records)."""
    value = await conn.fetchval(
        "SELECT content_hash FROM sibyl.redaction_profile WHERE name = 'secrets_only'"
        " AND origin = 'system' ORDER BY version_no DESC LIMIT 1"
    )
    return bytes(value) if value is not None else None


async def find_agents(conn: Conn, ids: Sequence[UUID], slugs: Sequence[str]) -> list[AgentRow]:
    if not ids and not slugs:
        return []
    rows = await conn.fetch(
        "SELECT id, slug, current_version_id, fail_mode FROM sibyl.agent"
        " WHERE id = ANY($1::uuid[]) OR slug = ANY($2::text[])",
        list(ids),
        list(slugs),
    )
    return [AgentRow(r["id"], r["slug"], r["current_version_id"], r["fail_mode"]) for r in rows]


async def find_replay(conn: Conn, batch_id: str, hours: int) -> dict[str, Any] | None:
    row = await conn.fetchrow(
        "SELECT response_body FROM sibyl.ingest_batch_seen WHERE tenant_id = sibyl.current_tenant()"
        " AND batch_id = $1 AND received_at > clock_timestamp() - make_interval(hours => $2)"
        " ORDER BY received_at DESC LIMIT 1",
        batch_id,
        hours,
    )
    if row is None:
        return None
    body = row["response_body"]
    result: dict[str, Any] = json.loads(body) if isinstance(body, str) else body
    return result


async def partition_ranges(conn: Conn, table: str) -> list[tuple[datetime, datetime]]:
    rows = await conn.fetch(
        "SELECT range_from, range_to FROM sibyl.partition_registry"
        " WHERE table_name = $1 AND state = 'attached' ORDER BY range_from",
        table,
    )
    return [(r["range_from"], r["range_to"]) for r in rows]


async def load_prices(conn: Conn, models: Iterable[str]) -> dict[tuple[str, str], Price]:
    names = sorted(set(models))
    if not names:
        return {}
    out: dict[tuple[str, str], Price] = {}
    for r in await conn.fetch(
        "SELECT provider_kind, model_name, input_usd_per_1m, output_usd_per_1m,"
        " cached_input_usd_per_1m, context_window, source_version"
        " FROM sibyl.model_catalog WHERE model_name = ANY($1::text[])",
        names,
    ):
        out[(r["provider_kind"], r["model_name"])] = Price(
            r["input_usd_per_1m"],
            r["output_usd_per_1m"],
            r["cached_input_usd_per_1m"],
            f"catalog/{r['source_version']}",
            r["context_window"],
        )
    for r in await conn.fetch(
        "SELECT p.slug, p.provider_kind, m.model_name, m.input_usd_per_1m, m.output_usd_per_1m,"
        " mc.cached_input_usd_per_1m, mc.context_window"
        " FROM sibyl.model m JOIN sibyl.provider p ON p.tenant_id = m.tenant_id AND p.id ="
        " m.provider_id"
        " LEFT JOIN sibyl.model_catalog mc ON mc.id = m.catalog_id"
        " WHERE m.model_name = ANY($1::text[]) AND m.input_usd_per_1m IS NOT NULL"
        "   AND m.output_usd_per_1m IS NOT NULL",
        names,
    ):
        price = Price(
            r["input_usd_per_1m"],
            r["output_usd_per_1m"],
            r["cached_input_usd_per_1m"],
            f"tenant/model/{r['model_name']}",
            r["context_window"],
        )
        out[(r["slug"], r["model_name"])] = price
        out[(r["provider_kind"], r["model_name"])] = price
    return out


async def register_agent(
    conn: Conn,
    tenant_id: UUID,
    slug: str,
    name: str,
    api_key_id: UUID,
    request_id: UUID | None,
    agent_id: UUID | None = None,
    discovered_via: str = "span_attr",
    first_trace_id: UUID | None = None,
) -> tuple[AgentRow, bool]:
    """Auto-register in the caller's own short transaction (R61, T5b): audit lock first,
    then the provisional agent row (lifecycle ``discovered``: never routed or gated until an
    admin confirms it), then ``routing_apply(register)`` which audits ``agent.discovered``
    (D50). Returns (agent, inserted)."""
    await conn.execute("SELECT sibyl.audit_lock($1)", tenant_id)
    row = await conn.fetchrow(
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, is_provisional, lifecycle,"
        " discovered_via, first_trace_id)"
        " VALUES ($1, coalesce($4, sibyl.uuidv7()), $2, $3, 'autonomous_agent', true, 'discovered',"
        " $5, $6)"
        " ON CONFLICT DO NOTHING"
        " RETURNING id, slug, current_version_id, fail_mode",
        tenant_id,
        slug,
        name,
        agent_id,
        discovered_via,
        first_trace_id,
    )
    if row is None:
        existing = await conn.fetchrow(
            "SELECT id, slug, current_version_id, fail_mode FROM sibyl.agent"
            " WHERE slug = $1 OR id = $2 ORDER BY (id = $2) DESC NULLS LAST LIMIT 1",
            slug,
            agent_id,
        )
        return AgentRow(
            existing["id"], existing["slug"], existing["current_version_id"], existing["fail_mode"]
        ), False
    agent = AgentRow(row["id"], row["slug"], row["current_version_id"], row["fail_mode"])
    detail = {
        "slug": slug,
        "api_key_id": str(api_key_id),
        "default_fail_mode": agent.fail_mode,
        "discovered_via": discovered_via,
    }
    # G0-6/G0-11: ingest principals are always API keys, so the discovering key is the actor
    # (``api_key`` + its key id, as ``core.audit.audit_actor`` maps it); never ``system``.
    await conn.fetchrow(
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register',"
        " $6,"
        " NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3, 'agent.discovered',"
        " $4::text::jsonb, NULL, NULL, $5, $7)",
        tenant_id,
        agent.id,
        f"register:{agent.id}",
        json.dumps(detail),
        request_id,
        ActorType.API_KEY.value,
        api_key_id,
    )
    return agent, True


async def insert_payload_refs(conn: Conn, tenant_id: UUID, sealed: Sequence[SealedPayload]) -> None:
    if not sealed:
        return
    await conn.execute(
        "INSERT INTO sibyl.payload_refs (tenant_id, id, created_at, kind, uri, content_type, parts,"
        " sha256, size_bytes, stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
        " redaction_profile_hash, api_key_id, agent_id, source_kind, source_id, expires_at)"
        " SELECT $1, u.id, u.created_at, u.kind, u.uri, u.content_type,"
        "  ARRAY(SELECT jsonb_array_elements_text(u.parts::jsonb)), u.sha256, u.size_bytes,"
        "  u.stored_bytes, u.tenant_key_id, u.key_version, u.nonce, u.capture_mode,"
        "  u.redaction_profile_hash, u.api_key_id, u.agent_id, u.source_kind, u.source_id,"
        " u.expires_at"
        " FROM unnest($2::uuid[], $3::timestamptz[], $4::text[], $5::text[], $6::text[],"
        " $7::text[],"
        "  $8::bytea[], $9::int8[], $10::int8[], $11::uuid[], $12::int4[], $13::bytea[],"
        " $14::text[],"
        "  $15::bytea[], $16::uuid[], $17::uuid[], $18::text[], $19::uuid[], $20::timestamptz[])"
        " AS u(id, created_at, kind, uri, content_type, parts, sha256, size_bytes, stored_bytes,"
        "  tenant_key_id, key_version, nonce, capture_mode, redaction_profile_hash, api_key_id,"
        "  agent_id, source_kind, source_id, expires_at)"
        " ON CONFLICT DO NOTHING",
        tenant_id,
        [s.id for s in sealed],
        [s.created_at for s in sealed],
        [s.kind for s in sealed],
        [s.key for s in sealed],
        [s.content_type for s in sealed],
        [json.dumps(list(s.parts)) for s in sealed],
        [s.sha256 for s in sealed],
        [s.size_bytes for s in sealed],
        [s.stored_bytes for s in sealed],
        [s.tenant_key_id for s in sealed],
        [s.key_version for s in sealed],
        [s.nonce for s in sealed],
        [s.capture_mode for s in sealed],
        [s.redaction_profile_hash for s in sealed],
        [s.api_key_id for s in sealed],
        [s.agent_id for s in sealed],
        [s.source_kind for s in sealed],
        [s.source_id for s in sealed],
        [s.expires_at for s in sealed],
    )


_COLS = ", ".join(name for name, _ in EVENT_COLUMNS)
_ARGS = ", ".join(f"${i + 1}::{kind}[]" for i, (_, kind) in enumerate(EVENT_COLUMNS))
_JSONB_COLUMNS = ("ingest", "attrs")
_TEXT_ARRAY_COLUMNS = ("scrub_rules_fired",)  # unnest cannot carry text[] per row: JSON text


def _select_expr(name: str) -> str:
    if name in _JSONB_COLUMNS:
        return f"u.{name}::jsonb"
    if name in _TEXT_ARRAY_COLUMNS:
        return f"ARRAY(SELECT jsonb_array_elements_text(u.{name}::jsonb))"
    return f"u.{name}"


_SELECT = ", ".join(_select_expr(name) for name, _ in EVENT_COLUMNS)
# Column names and casts come from the constant EVENT_COLUMNS, never from input.
_INSERT_EVENTS = (
    f"INSERT INTO sibyl.events ({_COLS}) SELECT {_SELECT}"  # noqa: S608
    f" FROM unnest({_ARGS}) AS u({_COLS}) ON CONFLICT DO NOTHING"
)


async def insert_events(conn: Conn, rows: Sequence[tuple[Any, ...]]) -> None:
    if not rows:
        return
    columns = list(zip(*rows, strict=True))
    await conn.execute(_INSERT_EVENTS, *[list(c) for c in columns])


async def stage_calls(
    conn: Conn, contributions: dict[UUID, dict[str, str]], flush_after_s: float
) -> set[UUID]:
    """Upsert ``call_merge``; returns the call ids accepted (the rest arrived after a flush)."""
    if not contributions:
        return set()
    ids = list(contributions)
    rows = await conn.fetch(
        "INSERT INTO sibyl.call_merge AS cm (tenant_id, call_id, sdk_contribution,"
        " gateway_contribution, state, flush_due_at)"
        " SELECT sibyl.current_tenant(), u.call_id, u.sdk::jsonb, u.gw::jsonb,"
        "  CASE WHEN u.sdk IS NOT NULL AND u.gw IS NOT NULL THEN 'complete' ELSE 'partial' END,"
        "  clock_timestamp() + make_interval(secs => $4)"
        " FROM unnest($1::uuid[], $2::text[], $3::text[]) AS u(call_id, sdk, gw)"
        " ON CONFLICT (tenant_id, call_id) DO UPDATE SET"
        "  sdk_contribution = coalesce(EXCLUDED.sdk_contribution, cm.sdk_contribution),"
        "  gateway_contribution = coalesce(EXCLUDED.gateway_contribution, cm.gateway_contribution),"
        "  state = CASE WHEN coalesce(EXCLUDED.sdk_contribution, cm.sdk_contribution) IS NOT NULL"
        "   AND coalesce(EXCLUDED.gateway_contribution, cm.gateway_contribution) IS NOT NULL"
        "   THEN 'complete' ELSE 'partial' END"
        " WHERE cm.state <> 'flushed'"
        " RETURNING call_id",
        ids,
        [contributions[i].get("sdk") for i in ids],
        [contributions[i].get("gateway") for i in ids],
        flush_after_s,
    )
    return {r["call_id"] for r in rows}


@dataclass(frozen=True)
class CheckpointRow:
    id: UUID
    created_at: datetime
    agent_id: UUID
    task_id: UUID
    seq: int
    step_index: int
    step_name: str | None
    state_bytes: int
    state: str | None
    state_ref_id: UUID | None
    state_sha256: bytes | None
    state_schema: str
    doc: str
    capture_mode: str
    redaction_profile_hash: bytes
    api_key_id: UUID


async def insert_checkpoints(conn: Conn, tenant_id: UUID, rows: Sequence[CheckpointRow]) -> None:
    if not rows:
        return
    await conn.executemany(
        "INSERT INTO sibyl.checkpoint (tenant_id, id, created_at, agent_id, task_id, seq,"
        " step_index,"
        " step_name, state_bytes, state, state_ref_id, state_sha256, state_schema, doc,"
        " capture_mode,"
        " redaction_profile_hash, api_key_id)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::jsonb, $11, $12, $13,"
        " $14::text::jsonb, $15, $16, $17)"
        " ON CONFLICT DO NOTHING",
        [
            (
                tenant_id,
                r.id,
                r.created_at,
                r.agent_id,
                r.task_id,
                r.seq,
                r.step_index,
                r.step_name,
                r.state_bytes,
                r.state,
                r.state_ref_id,
                r.state_sha256,
                r.state_schema,
                r.doc,
                r.capture_mode,
                r.redaction_profile_hash,
                r.api_key_id,
            )
            for r in rows
        ],
    )


async def insert_rejections(
    conn: Conn, raw_ref_id: UUID | None, rejections: Sequence[tuple[str, dict[str, Any]]]
) -> None:
    if not rejections:
        return
    await conn.execute(
        "INSERT INTO sibyl.events_rejected (tenant_id, reason, raw_ref_id, head)"
        " SELECT sibyl.current_tenant(), u.reason, $1, u.head::jsonb"
        " FROM unnest($2::text[], $3::text[]) AS u(reason, head)",
        raw_ref_id,
        [reason for reason, _ in rejections],
        [json.dumps(head, ensure_ascii=False) for _, head in rejections],
    )


async def discover_models(conn: Conn, pairs: Iterable[tuple[str, str]]) -> None:
    pairs = sorted(set(pairs))
    if not pairs:
        return
    await conn.execute(
        "INSERT INTO sibyl.model (tenant_id, provider_id, model_name, is_discovered)"
        " SELECT p.tenant_id, p.id, u.model, true"
        " FROM unnest($1::text[], $2::text[]) AS u(provider, model)"
        " JOIN sibyl.provider p ON p.slug = u.provider"
        " ON CONFLICT DO NOTHING",
        [p for p, _ in pairs],
        [m for _, m in pairs],
    )


async def remember_batch(
    conn: Conn, batch_id: str, api_key_id: UUID, body: dict[str, Any], digest: bytes
) -> None:
    await conn.execute(
        "INSERT INTO sibyl.ingest_batch_seen (tenant_id, batch_id, api_key_id, response_sha256,"
        " response_body)"
        " VALUES (sibyl.current_tenant(), $1, $2, $3, $4::text::jsonb) ON CONFLICT DO NOTHING",
        batch_id,
        api_key_id,
        digest,
        json.dumps(body, ensure_ascii=False),
    )


async def touch_key(conn: Conn, api_key_id: UUID) -> None:
    await conn.execute(
        "UPDATE sibyl.api_key SET last_used_at = now() WHERE tenant_id = sibyl.current_tenant()"
        " AND id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
        api_key_id,
    )
