"""Turn outbox rows and failed runs into webhook deliveries (D53).

* **Outbox** (``alert``, ``incident``, ``action`` topics): read strictly after the tenant's
  commit-ordered cursor ``consumer_offsets('webhooks', tenant, 'outbox')`` and below the commit
  horizon (R60), so no row is skipped or delivered twice per webhook. ``alert.fired`` /
  ``alert.updated`` of a drift rule are also delivered as ``drift.detected``.
* **Runs**: ``agent.invoke`` end events with a non-ok status, by ``received_at`` with a 60 s
  re-scan overlap (``consumer_offsets('webhooks', tenant, 'runs').last_created_at``); the
  delivery's unique ``event_key`` (``run:<run_id>``) absorbs the overlap.

A delivery is created only for an enabled webhook of an **active** monitor that subscribed to the
event type, existed when the event happened, and watches the agent the event is about (an event
about no agent goes to all-groups monitors only). A tenant's first scan starts at the current
horizon: a new webhook never receives the backlog. Payloads are references and states only.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final
from uuid import NAMESPACE_URL, UUID, uuid5

from sibyl_schemas.values import DRIFT_ALERT_RULES, OUTBOX_WEBHOOK_EVENTS, WebhookEventType

from ...core.monitor_keys import descendants
from .deliver import envelope

CONSUMER: Final = "webhooks"
OUTBOX_TOPIC_KEY: Final = "outbox"
RUNS_TOPIC_KEY: Final = "runs"
OUTBOX_TOPICS: Final = ["alert", "incident", "action"]
BATCH: Final = 500
RUN_OVERLAP: Final = timedelta(seconds=60)
RUN_SETTLE: Final = timedelta(seconds=5)
RUN_MAX_LOOKBACK: Final = timedelta(days=1)
_EVENT_NS: Final = uuid5(NAMESPACE_URL, "https://sibyl.dev/webhooks/events")
PAYLOAD_BUDGET: Final = 7168
"""Bytes of ``payload::text`` a delivery may use: below the 8192-byte
``ck_webhook_delivery_payload`` CHECK, with room for jsonb's own number rendering."""
_KEPT_SCALARS: Final = frozenset({"rule", "severity", "scope", "state", "step", "decision", "tool"})

_TARGETS_SQL = """
SELECT w.id, w.monitor_id, w.event_types, w.created_at, m.all_groups, m.group_ids
  FROM sibyl.monitor_webhook w
  JOIN sibyl.monitor m ON m.tenant_id = w.tenant_id AND m.id = w.monitor_id
 WHERE w.tenant_id = $1 AND w.state = 'enabled' AND m.state = 'active'
"""
_GROUPS_SQL = "SELECT id, parent_group_id FROM sibyl.agent_group WHERE tenant_id = $1"
_AGENT_GROUPS_SQL = (
    "SELECT id, agent_group_id FROM sibyl.agent WHERE tenant_id = $1 AND id = ANY($2::uuid[])"
)
_CURSOR_SQL = (
    "SELECT last_xid, last_id, last_created_at FROM sibyl.consumer_offsets"
    " WHERE consumer_group = $1 AND tenant_id = $2 AND topic = $3 FOR UPDATE"
)
_CURSOR_INIT_SQL = """
INSERT INTO sibyl.consumer_offsets (consumer_group, tenant_id, topic, last_xid, last_id,
  last_created_at)
VALUES ($1, $2, $3, sibyl.commit_horizon(), sibyl.nil_uuid(), now())
ON CONFLICT (consumer_group, tenant_id, topic) DO NOTHING
"""
_CURSOR_MOVE_SQL = """
UPDATE sibyl.consumer_offsets SET last_xid = $4, last_id = $5, last_created_at = $6
 WHERE consumer_group = $1 AND tenant_id = $2 AND topic = $3
"""
_OUTBOX_SQL = "SELECT * FROM sibyl.outbox_read($1, $2, $3, $4::text[])"
_RUNS_SQL = """
SELECT e.task_id, e.agent_id, e.received_at, e.ts, e.status, e.error_type, e.trace_id,
       e.attrs->>'status' AS run_status, e.attrs->>'error_type' AS run_error_type
  FROM sibyl.events e
 WHERE e.tenant_id = $1 AND e.event_type = 'agent.invoke' AND e.task_id IS NOT NULL
   AND e.attrs->>'phase' = 'end'
   AND coalesce(e.attrs->>'status', e.status, 'ok') NOT IN ('ok', 'handed_off')
   AND e.ts >= $2 AND e.received_at > $3 AND e.received_at <= $4
 ORDER BY e.received_at, e.event_id
 LIMIT $5
"""
_INSERT_SQL = """
INSERT INTO sibyl.webhook_delivery (tenant_id, webhook_id, monitor_id, event_type, event_key,
  agent_id, payload)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
ON CONFLICT (tenant_id, webhook_id, event_key) DO NOTHING
"""


@dataclass(frozen=True)
class Target:
    """An enabled webhook of an active monitor, with the agent groups it may hear about."""

    webhook_id: UUID
    monitor_id: UUID
    events: frozenset[str]
    created_at: datetime
    groups: frozenset[UUID] | None  # None = all groups

    def wants(self, event: str, at: datetime, agent_groups: Sequence[UUID | None]) -> bool:
        if event not in self.events or at < self.created_at:
            return False
        if self.groups is None:
            return True  # all groups: agent events and tenant-level events alike
        # A group-limited monitor hears only about agents in its groups (never tenant-level).
        return any(g is not None and g in self.groups for g in agent_groups)


@dataclass(frozen=True)
class Event:
    key: str
    event_id: UUID
    event_type: str
    created_at: datetime
    agents: tuple[UUID, ...]
    data: Mapping[str, Any]


async def load_targets(conn: Any, tenant: UUID) -> list[Target]:
    rows = await conn.fetch(_TARGETS_SQL, tenant)
    if not rows:
        return []
    edges = None
    out: list[Target] = []
    for row in rows:
        groups: frozenset[UUID] | None = None
        if not row["all_groups"]:
            if edges is None:
                edges = {
                    r["id"]: r["parent_group_id"] for r in await conn.fetch(_GROUPS_SQL, tenant)
                }
            groups = descendants(row["group_ids"] or (), edges)
        out.append(
            Target(
                row["id"],
                row["monitor_id"],
                frozenset(row["event_types"]),
                row["created_at"],
                groups,
            )
        )
    return out


def agent_refs(row: Mapping[str, Any]) -> tuple[UUID, ...]:
    """The agents an outbox row is about (mirrors the SSE visibility rule)."""
    payload = _payload(row)
    refs: list[UUID] = []
    if row["aggregate_kind"] == "agent":
        refs.append(row["aggregate_id"])
    candidates: list[Any] = [payload.get("agent_id")]
    candidates += list(payload.get("affected_agent_ids") or [])
    if payload.get("scope_kind") == "agent":
        candidates.append(payload.get("scope_id"))
    for value in candidates:
        with contextlib.suppress(TypeError, ValueError, AttributeError):
            if value:
                refs.append(UUID(str(value)))
    return tuple(dict.fromkeys(refs))


def _payload(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return dict(payload or {})


def outbox_events(row: Mapping[str, Any]) -> list[Event]:
    """The webhook events one outbox row becomes (none, one, or two for a drift alert)."""
    mapped = OUTBOX_WEBHOOK_EVENTS.get(row["event_type"])
    if mapped is None:
        return []
    payload = _payload(row)
    agents = agent_refs(row)
    base = Event(
        key=str(row["id"]),
        event_id=row["id"],
        event_type=mapped.value,
        created_at=row["created_at"],
        agents=agents,
        data=payload,
    )
    out = [base]
    is_drift = payload.get("rule") in DRIFT_ALERT_RULES
    if is_drift and mapped in (WebhookEventType.ALERT_FIRED, WebhookEventType.ALERT_UPDATED):
        out.append(
            Event(
                key=f"drift:{row['id']}",
                event_id=uuid5(_EVENT_NS, f"drift:{row['id']}"),
                event_type=WebhookEventType.DRIFT_DETECTED.value,
                created_at=row["created_at"],
                agents=agents,
                data=payload,
            )
        )
    return out


def run_event(row: Mapping[str, Any]) -> Event:
    run_id = row["task_id"]
    trace = row["trace_id"]
    data = {
        "run_id": str(run_id),
        "agent_id": str(row["agent_id"]) if row["agent_id"] else None,
        "status": row["run_status"] or row["status"],
        "error_type": row["run_error_type"] or row["error_type"],
        "ended_at": row["ts"].isoformat().replace("+00:00", "Z"),
        "trace_id": trace.hex if isinstance(trace, UUID) else None,
    }
    return Event(
        key=f"run:{run_id}",
        event_id=uuid5(_EVENT_NS, f"run.failed:{run_id}"),
        event_type=WebhookEventType.RUN_FAILED.value,
        created_at=row["received_at"],
        agents=(row["agent_id"],) if row["agent_id"] else (),
        data=data,
    )


def _jsonb_text_bytes(doc: Mapping[str, Any]) -> int:
    """Approximate ``octet_length(payload::text)`` (jsonb prints ``", "`` and ``": "``)."""
    return len(json.dumps(doc, ensure_ascii=False, default=str).encode("utf-8"))


def fit_payload(doc: dict[str, Any]) -> dict[str, Any]:
    """The envelope as stored, or, when it would not fit the delivery CHECK, the same envelope
    whose ``data`` keeps only short references (``*_id``) and states, marked ``truncated``.

    An oversized row would otherwise abort the tenant's whole webhooks transaction on every
    tick (no deliveries, no external-finding alerts, the cursor never moves)."""
    if _jsonb_text_bytes(doc) <= PAYLOAD_BUDGET:
        return doc
    kept: dict[str, Any] = {"truncated": True}
    for key, value in dict(doc.get("data") or {}).items():
        short = isinstance(value, str) and len(value) <= 64
        if short and (key.endswith("_id") or key in _KEPT_SCALARS):
            kept[key] = value
    out = doc | {"data": kept}
    if _jsonb_text_bytes(out) > PAYLOAD_BUDGET:  # pragma: no cover - ids only cannot get here
        out = doc | {"data": {"truncated": True}}
    return out


async def _agent_groups(
    conn: Any, tenant: UUID, events: Iterable[Event]
) -> dict[UUID, UUID | None]:
    ids = sorted({a for e in events for a in e.agents}, key=str)
    if not ids:
        return {}
    rows = await conn.fetch(_AGENT_GROUPS_SQL, tenant, ids)
    return {r["id"]: r["agent_group_id"] for r in rows}


async def fan_out(
    conn: Any, tenant: UUID, targets: Sequence[Target], events: Sequence[Event]
) -> int:
    """Insert one delivery per (target, event) that the target may hear about."""
    if not events or not targets:
        return 0
    groups = await _agent_groups(conn, tenant, events)
    known = set(groups)
    created = 0
    for event in events:
        existing = tuple(a for a in event.agents if a in known)
        if event.agents and not existing:
            continue  # the agent was erased since: nothing to deliver
        agent_groups = [groups[a] for a in existing]
        for target in targets:
            if not target.wants(event.event_type, event.created_at, agent_groups):
                continue
            doc = fit_payload(
                envelope(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    created_at=event.created_at,
                    tenant_id=tenant,
                    monitor_id=target.monitor_id,
                    data=event.data,
                )
            )
            status = await conn.execute(
                _INSERT_SQL,
                tenant,
                target.webhook_id,
                target.monitor_id,
                event.event_type,
                event.key,
                existing[0] if existing else None,
                doc,
            )
            created += int(status.rsplit(" ", 1)[-1] or 0)
    return created


async def _cursor(conn: Any, tenant: UUID, topic: str) -> Any:
    row = await conn.fetchrow(_CURSOR_SQL, CONSUMER, tenant, topic)
    if row is None:
        await conn.execute(_CURSOR_INIT_SQL, CONSUMER, tenant, topic)
        return None
    return row


async def scan_outbox(conn: Any, tenant: UUID, targets: Sequence[Target]) -> int:
    cursor = await _cursor(conn, tenant, OUTBOX_TOPIC_KEY)
    if cursor is None:
        return 0
    rows = await conn.fetch(
        _OUTBOX_SQL, cursor["last_xid"], cursor["last_id"], BATCH, OUTBOX_TOPICS
    )
    if not rows:
        return 0
    events = [e for row in rows for e in outbox_events(row)]
    created = await fan_out(conn, tenant, targets, events)
    last = rows[-1]
    await conn.execute(
        _CURSOR_MOVE_SQL,
        CONSUMER,
        tenant,
        OUTBOX_TOPIC_KEY,
        last["xid"],
        last["id"],
        cursor["last_created_at"],
    )
    return created


async def scan_runs(conn: Any, tenant: UUID, targets: Sequence[Target], now: datetime) -> int:
    if not any(WebhookEventType.RUN_FAILED.value in t.events for t in targets):
        return 0
    cursor = await _cursor(conn, tenant, RUNS_TOPIC_KEY)
    if cursor is None:
        return 0
    since = cursor["last_created_at"] or now
    upper = now - RUN_SETTLE
    if upper <= since - RUN_OVERLAP:
        return 0
    rows = await conn.fetch(
        _RUNS_SQL, tenant, since - RUN_MAX_LOOKBACK, since - RUN_OVERLAP, upper, BATCH
    )
    created = await fan_out(conn, tenant, targets, [run_event(r) for r in rows])
    moved = rows[-1]["received_at"] if len(rows) >= BATCH else upper
    await conn.execute(
        _CURSOR_MOVE_SQL,
        CONSUMER,
        tenant,
        RUNS_TOPIC_KEY,
        cursor["last_xid"],
        cursor["last_id"],
        max(moved, since),
    )
    return created
