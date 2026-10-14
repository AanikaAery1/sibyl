"""``call_merge`` flusher (DATAMODEL §6.1, ingest every 1 s, per tenant).

Merges the SDK and gateway contributions of one call by the authority table: the SDK owns
identity and conversation (agent, task, trace/span, conversation, prompt version), the gateway
owns latency, usage, rate-limit, routing, retry and HTTP outcome. The payload comes from the
side that carried one (the stricter ``capture_mode`` wins when both did). Rows are claimed with
``FOR UPDATE SKIP LOCKED``; merged events go to ``events`` (``ON CONFLICT DO NOTHING``) and the
staging rows become ``flushed`` in the same transaction.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from ..core.db import Database
from . import store
from .config import IngestConfig
from .normalise import derive
from .normalise.envelope import RowContext, event_row, fit_attrs, validate_canonical
from .normalise.scrubbing import rule_ids, strictest

log = logging.getLogger("sibyl.ingest.flusher")

GATEWAY_OWNS = (
    "status",
    "error_type",
    "http_status",
    "latency_ms",
    "ttfb_ms",
    "streamed",
    "usage",
    "ratelimit",
    "retry",
    "route",
    "server",
    "response_model",
    "response_id",
    "finish_reasons",
    "cost_usd",
    "cost_source",
)
SDK_ENVELOPE = ("agent_id", "task_id", "trace_id", "span_id", "parent_span_id")


def _load(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    doc: dict[str, Any] = json.loads(value) if isinstance(value, str) else value
    return doc


def _merge_redaction(sdk: dict[str, Any], gateway: dict[str, Any]) -> dict[str, Any]:
    """Union of both sides' rules (re-capped for the DB) and the sum of ingest's late hits."""
    rules = rule_ids([*sdk.get("rules_fired", []), *gateway.get("rules_fired", [])])
    merged = {**gateway, "rules_fired": rules}
    late = int(sdk.get("late_hits") or 0) + int(gateway.get("late_hits") or 0)
    if late:
        merged["late_hits"] = late
    return merged


def merge(
    sdk: dict[str, Any] | None, gateway: dict[str, Any] | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (merged canonical event, row extras) from the staged contributions."""
    if sdk is None or gateway is None:
        only = sdk or gateway
        assert only is not None
        return only["event"], only["row"]
    s_event, g_event = sdk["event"], gateway["event"]
    attrs = dict(s_event["attrs"])
    for key in GATEWAY_OWNS:
        if key in g_event["attrs"]:
            attrs[key] = g_event["attrs"][key]
        elif key in ("cost_usd", "cost_source"):
            attrs.pop(key, None)
    mode = strictest(s_event["capture_mode"], g_event["capture_mode"])
    payload_side = None
    for side, event in (("sdk", s_event), ("gateway", g_event)):
        if "payload" in event["attrs"] and (payload_side is None or event["capture_mode"] == mode):
            payload_side = side
    attrs.pop("payload", None)
    if payload_side is not None:
        attrs["payload"] = (s_event if payload_side == "sdk" else g_event)["attrs"]["payload"]
    attrs["contributions"] = sorted(
        set(s_event["attrs"]["contributions"]) | set(g_event["attrs"]["contributions"])
    )
    attrs["merge_state"] = "complete"
    event = dict(g_event)
    for key in SDK_ENVELOPE:
        if s_event.get(key) is not None:
            event[key] = s_event[key]
        elif key in event and s_event.get(key) is None and key == "parent_span_id":
            event.pop(key)
    event["redaction_profile"] = _merge_redaction(
        s_event["redaction_profile"], g_event["redaction_profile"]
    )
    event["capture_mode"] = mode
    event["attrs"] = attrs
    row = dict(gateway["row"])
    payload_row = (sdk if payload_side == "sdk" else gateway)["row"]
    for key in ("payload_ref_id", "payload_sha256", "payload_bytes"):
        row[key] = payload_row.get(key) if payload_side else None
    return event, row


def _row(
    event: dict[str, Any], extras: dict[str, Any], tenant_id: UUID, cfg: IngestConfig
) -> tuple[Any, ...]:
    def hexed(key: str) -> bytes | None:
        value = extras.get(key)
        return bytes.fromhex(value) if value else None

    def uid(key: str) -> UUID | None:
        value = extras.get(key)
        return UUID(value) if value else None

    payload = None
    if extras.get("payload_ref_id"):
        payload = (
            UUID(extras["payload_ref_id"]),
            hexed("payload_sha256") or b"",
            int(extras["payload_bytes"] or 0),
        )
    ctx = RowContext(
        tenant_id,
        uid("api_key_id") or UUID(int=0),
        datetime.fromisoformat(extras["observed_at"]),
        uid("raw_ref_id"),
        hexed("redaction_profile_hash") or b"\x00" * 32,
        cfg,
    )
    cost = Decimal(extras["cost_usd"]) if extras.get("cost_usd") is not None else None
    return event_row(
        event,
        ctx,
        agent_version_id=uid("agent_version_id"),
        error_class=derive.error_class(event["attrs"], event["type"]),
        cost=cost,
        payload=payload,
    )


async def flush_tenant(
    db: Database, tenant_id: UUID, cfg: IngestConfig, *, now: datetime | None = None
) -> int:
    """Flush due or complete calls for one tenant; returns the number of calls flushed."""
    cutoff = now or datetime.now(UTC)
    async with db.tenant_tx(tenant_id, statement_timeout_ms=cfg.statement_timeout_ms) as conn:
        rows = await conn.fetch(
            "SELECT call_id, sdk_contribution, gateway_contribution FROM sibyl.call_merge"
            " WHERE state <> 'flushed' AND (state = 'complete' OR flush_due_at <= $1)"
            " ORDER BY flush_due_at LIMIT $2 FOR UPDATE SKIP LOCKED",
            cutoff,
            cfg.flush_batch_rows,
        )
        if not rows:
            return 0
        events = []
        for r in rows:
            event, extras = merge(_load(r["sdk_contribution"]), _load(r["gateway_contribution"]))
            try:
                event["attrs"], _notes = fit_attrs(
                    event["type"], event["attrs"], cfg.attrs_budget_bytes
                )
            except ValueError:
                log.warning("merged call %s over the attrs budget; skipped", r["call_id"])
                continue
            if validate_canonical(event) is not None:
                log.warning("merged call %s failed sibyl-event/1 validation; skipped", r["call_id"])
                continue
            events.append(_row(event, extras, tenant_id, cfg))
        await store.insert_events(conn, events)
        await conn.execute(
            "UPDATE sibyl.call_merge SET state = 'flushed', flushed_at = clock_timestamp()"
            " WHERE call_id = ANY($1::uuid[])",
            [r["call_id"] for r in rows],
        )
    return len(rows)


async def active_tenants(db: Database) -> list[UUID]:
    async with db.pre_tenant() as conn:
        rows = await conn.fetch("SELECT id FROM sibyl.tenant WHERE status = 'active'")
    return [r["id"] for r in rows]


async def run_flusher(db: Database, cfg: IngestConfig, stop: asyncio.Event) -> None:
    """Background loop owned by the ingest app's lifespan."""
    while not stop.is_set():
        try:
            for tenant_id in await active_tenants(db):
                await flush_tenant(db, tenant_id, cfg)
        except Exception:
            log.exception("call_merge flush pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg.flush_interval_s)
        except TimeoutError:
            pass
