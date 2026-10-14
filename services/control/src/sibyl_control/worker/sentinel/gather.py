"""What Sentinel looks at: read-only queries that pick the subjects of each task and build the
data document the model sees.

Capture mode decides content: an agent whose effective capture mode (agent policy, else tenant
policy, else ``metadata``) is ``metadata`` contributes metadata only (tool names, statuses,
latencies, counts); ``redacted`` / ``full`` agents may also contribute their already-scrubbed
captured payloads (held-action arguments, tool-call arguments), opened through a
``ContentReader`` and only when the event itself was captured with content. Every query here is
a SELECT.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final
from uuid import UUID

ContentReader = Callable[[Any, UUID, UUID], Awaitable[Any]]
"""``(conn, tenant, payload_ref_id) -> decoded payload or None`` (never raises)."""

CONTENT_MODES: Final = frozenset({"full", "redacted"})
INCIDENT_LOOKBACK: Final = "24 hours"
DRIFT_LOOKBACK: Final = "6 hours"
DRIFT_WINDOW_H: Final = 6
MAX_TRACES: Final = 3
MAX_STEPS: Final = 30
MAX_CONTENT_CHARS: Final = 600

_CAPTURE_SQL = """
SELECT coalesce(
  (SELECT capture_mode FROM sibyl.capture_policy WHERE tenant_id = $1 AND scope_kind = 'agent'
      AND agent_id = $2 AND superseded_by IS NULL),
  (SELECT capture_mode FROM sibyl.capture_policy WHERE tenant_id = $1 AND scope_kind = 'tenant'
      AND superseded_by IS NULL),
  'metadata')
"""
_AGENT_SQL = """
SELECT a.id, a.slug, a.name, a.description, a.kind, a.framework, a.tier, a.risk_class,
       a.lifecycle, a.tags, v.declared_tool_ids,
       coalesce((SELECT array_agg(t.slug ORDER BY t.slug) FROM sibyl.tool t
                  WHERE t.tenant_id = a.tenant_id AND t.id = ANY (v.declared_tool_ids)), '{}')
         AS declared_tools
  FROM sibyl.agent a
  LEFT JOIN sibyl.agent_version v ON v.tenant_id = a.tenant_id AND v.id = a.current_version_id
 WHERE a.tenant_id = $1 AND a.id = $2
"""
_NEW_INCIDENTS_SQL = f"""
SELECT f.id, f.agent_id FROM sibyl.failover f
 WHERE f.tenant_id = $1 AND f.created_at > now() - interval '{INCIDENT_LOOKBACK}'
   AND NOT EXISTS (SELECT 1 FROM sibyl.sentinel_finding s
                    WHERE s.tenant_id = f.tenant_id AND s.dedupe_key = 'incident:' || f.id)
 ORDER BY f.created_at LIMIT $2
"""  # noqa: S608 (constant interval)
_INCIDENT_SQL = """
SELECT f.id, f.agent_id, f.kind, f.state, f.step, f.attempt, f.priority, f.rule_codes,
       f.actor_kind, f.from_state, f.to_state, f.error, f.step_results, f.cancel_requested,
       f.created_at, f.finished_at,
       al.summary AS alert_summary, al.what_to_do AS alert_what_to_do,
       al.severity AS alert_severity,
       (SELECT r.code FROM sibyl.alert_rule r
         WHERE r.tenant_id = al.tenant_id AND r.id = al.rule_id) AS alert_rule
  FROM sibyl.failover f
  LEFT JOIN sibyl.alert al ON al.tenant_id = f.tenant_id AND al.id = f.trigger_alert_id
 WHERE f.tenant_id = $1 AND f.id = $2
"""
_HEALTH_SQL = """
SELECT score, band, provisional, evaluated_at, predicted_failure_mode, recommended_action
  FROM sibyl.health_snapshot WHERE tenant_id = $1 AND agent_id = $2
 ORDER BY evaluated_at DESC LIMIT 1
"""
_PENDING_HOLDS_SQL = """
SELECT h.id, h.agent_id FROM sibyl.held_action h
 WHERE h.tenant_id = $1 AND h.state = 'pending' AND h.expires_at > now()
   AND NOT EXISTS (SELECT 1 FROM sibyl.sentinel_finding s
                    WHERE s.tenant_id = h.tenant_id AND s.dedupe_key = 'held_action:' || h.id)
 ORDER BY h.created_at LIMIT $2
"""
_HOLD_SQL = """
SELECT h.id, h.agent_id, h.tool, h.source, h.reason, h.rule_id, h.policy_version, h.server_effect,
       h.sensitive, h.approvals_required, h.args_bytes, h.args_payload_ref, h.state,
       h.created_at, h.expires_at, p.name AS policy_name,
       (SELECT r.reason FROM sibyl.action_rule r WHERE r.tenant_id = h.tenant_id
          AND r.policy_id = h.policy_id AND r.rule_id = h.rule_id) AS rule_reason,
       (SELECT count(*) FROM sibyl.held_action o WHERE o.tenant_id = h.tenant_id
          AND o.agent_id = h.agent_id AND o.tool = h.tool AND o.id <> h.id
          AND o.created_at > now() - interval '7 days') AS same_tool_holds_7d,
       (SELECT count(*) FROM sibyl.held_action o WHERE o.tenant_id = h.tenant_id
          AND o.agent_id = h.agent_id AND o.tool = h.tool AND o.state = 'denied'
          AND o.created_at > now() - interval '7 days') AS same_tool_denied_7d
  FROM sibyl.held_action h
  LEFT JOIN sibyl.action_policy p ON p.tenant_id = h.tenant_id AND p.id = h.policy_id
 WHERE h.tenant_id = $1 AND h.id = $2
"""
_DRIFT_CANDIDATES_SQL = f"""
SELECT e.agent_id FROM sibyl.events e
 WHERE e.tenant_id = $1 AND e.event_type = 'tool.call' AND e.agent_id IS NOT NULL
   AND e.ts > now() - interval '{DRIFT_LOOKBACK}'
   AND NOT EXISTS (SELECT 1 FROM sibyl.sentinel_finding s WHERE s.tenant_id = e.tenant_id
                    AND s.dedupe_key = 'drift:' || e.agent_id || ':' || $2)
 GROUP BY e.agent_id ORDER BY max(e.ts) DESC LIMIT $3
"""  # noqa: S608 (constant interval)
_TRACE_SQL = f"""
SELECT e.trace_id, max(e.ts) AS last_ts FROM sibyl.events e
 WHERE e.tenant_id = $1 AND e.agent_id = $2 AND e.event_type = 'tool.call'
   AND e.ts > now() - interval '{DRIFT_LOOKBACK}'
 GROUP BY e.trace_id ORDER BY last_ts DESC LIMIT $3
"""  # noqa: S608 (constant interval)
_STEPS_SQL = f"""
SELECT e.ts, e.event_type, e.status, e.error_class, e.latency_ms, e.model, e.tokens_in,
       e.tokens_out, e.capture_mode, e.payload_ref_id, e.attrs ->> 'tool_name' AS tool,
       e.attrs ->> 'tool_type' AS tool_type
  FROM sibyl.events e
 WHERE e.tenant_id = $1 AND e.agent_id = $2 AND e.trace_id IS NOT DISTINCT FROM $3
   AND e.event_type IN ('tool.call', 'gen_ai.request')
   AND e.ts > now() - interval '{DRIFT_LOOKBACK}'
 ORDER BY e.ts, e.seq LIMIT $4
"""  # noqa: S608 (constant interval)
_FLEET_SQL = """
SELECT
  (SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1 AND lifecycle <> 'retired') AS agents,
  (SELECT coalesce(jsonb_object_agg(band, n), '{}') FROM (
     SELECT band, count(*) AS n FROM (
       SELECT DISTINCT ON (agent_id) agent_id, band FROM sibyl.health_snapshot
        WHERE tenant_id = $1 AND evaluated_at > now() - interval '24 hours'
        ORDER BY agent_id, evaluated_at DESC) latest GROUP BY band) b) AS health_bands,
  (SELECT coalesce(jsonb_object_agg(severity, n), '{}') FROM (
     SELECT severity, count(*) AS n FROM sibyl.alert WHERE tenant_id = $1 AND state <> 'resolved'
      GROUP BY severity) s) AS open_alerts,
  (SELECT coalesce(jsonb_object_agg(code, n), '{}') FROM (
     SELECT r.code, count(*) AS n FROM sibyl.alert a JOIN sibyl.alert_rule r
         ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
      WHERE a.tenant_id = $1 AND a.first_fired_at > now() - interval '24 hours'
      GROUP BY r.code ORDER BY n DESC LIMIT 10) c) AS alerts_24h_by_rule,
  (SELECT coalesce(jsonb_object_agg(state, n), '{}') FROM (
     SELECT state, count(*) AS n FROM sibyl.failover
      WHERE tenant_id = $1 AND created_at > now() - interval '24 hours' GROUP BY state) f)
    AS incidents_24h,
  (SELECT coalesce(jsonb_object_agg(state, n), '{}') FROM (
     SELECT state, count(*) AS n FROM sibyl.held_action
      WHERE tenant_id = $1 AND created_at > now() - interval '24 hours' GROUP BY state) h)
    AS held_actions_24h,
  (SELECT coalesce(jsonb_object_agg(severity, n), '{}') FROM (
     SELECT severity, count(*) AS n FROM sibyl.sentinel_finding
      WHERE tenant_id = $1 AND created_at > now() - interval '24 hours'
        AND kind <> 'fleet_summary' GROUP BY severity) g) AS sentinel_findings_24h
"""
_WORST_SQL = """
SELECT a.slug, a.tier, l.band, l.score FROM (
  SELECT DISTINCT ON (agent_id) agent_id, band, score FROM sibyl.health_snapshot
   WHERE tenant_id = $1 AND evaluated_at > now() - interval '24 hours'
   ORDER BY agent_id, evaluated_at DESC) l
  JOIN sibyl.agent a ON a.tenant_id = $1 AND a.id = l.agent_id
 ORDER BY l.score ASC, a.slug LIMIT 5
"""


def _plain(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in "{[":
        try:
            return json.loads(value)
        except ValueError:
            return value
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def _doc(row: Mapping[str, Any], *skip: str) -> dict[str, Any]:
    return {k: _plain(v) for k, v in dict(row).items() if k not in skip}


async def capture_mode(conn: Any, tenant: UUID, agent_id: UUID) -> str:
    return str(await conn.fetchval(_CAPTURE_SQL, tenant, agent_id))


async def agent_profile(conn: Any, tenant: UUID, agent_id: UUID) -> dict[str, Any]:
    row = await conn.fetchrow(_AGENT_SQL, tenant, agent_id)
    if row is None:
        return {"id": str(agent_id), "missing": True}
    return _doc(row, "declared_tool_ids")


async def _content(conn: Any, tenant: UUID, ref: UUID | None, reader: ContentReader | None) -> Any:
    if ref is None or reader is None:
        return None
    value = await reader(conn, tenant, ref)
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text[:MAX_CONTENT_CHARS]


# --- incidents --------------------------------------------------------------------------------


async def new_incidents(conn: Any, tenant: UUID, limit: int) -> list[tuple[UUID, UUID]]:
    return [(r["id"], r["agent_id"]) for r in await conn.fetch(_NEW_INCIDENTS_SQL, tenant, limit)]


async def incident_doc(conn: Any, tenant: UUID, incident_id: UUID) -> dict[str, Any] | None:
    row = await conn.fetchrow(_INCIDENT_SQL, tenant, incident_id)
    if row is None:
        return None
    health = await conn.fetchrow(_HEALTH_SQL, tenant, row["agent_id"])
    return {
        "incident": _doc(row, "agent_id"),
        "agent": await agent_profile(conn, tenant, row["agent_id"]),
        "latest_health": _doc(health) if health is not None else None,
        "content_included": False,
    }


# --- held actions -------------------------------------------------------------------------------


async def pending_holds(conn: Any, tenant: UUID, limit: int) -> list[tuple[UUID, UUID]]:
    return [(r["id"], r["agent_id"]) for r in await conn.fetch(_PENDING_HOLDS_SQL, tenant, limit)]


async def hold_doc(
    conn: Any, tenant: UUID, held_id: UUID, reader: ContentReader | None
) -> dict[str, Any] | None:
    row = await conn.fetchrow(_HOLD_SQL, tenant, held_id)
    if row is None:
        return None
    mode = await capture_mode(conn, tenant, row["agent_id"])
    args = None
    if mode in CONTENT_MODES:
        args = await _content(conn, tenant, row["args_payload_ref"], reader)
    return {
        "held_action": _doc(row, "agent_id", "args_payload_ref"),
        "agent": await agent_profile(conn, tenant, row["agent_id"]),
        "capture_mode": mode,
        "content_included": args is not None,
        "arguments_scrubbed": args,
    }


# --- semantic drift -----------------------------------------------------------------------------


def drift_window(now: Any) -> str:
    return f"{now:%Y-%m-%d}T{now.hour // DRIFT_WINDOW_H * DRIFT_WINDOW_H:02d}"


async def drift_candidates(conn: Any, tenant: UUID, window: str, limit: int) -> list[UUID]:
    rows = await conn.fetch(_DRIFT_CANDIDATES_SQL, tenant, window, limit)
    return [r["agent_id"] for r in rows]


async def drift_doc(
    conn: Any, tenant: UUID, agent_id: UUID, reader: ContentReader | None
) -> dict[str, Any]:
    mode = await capture_mode(conn, tenant, agent_id)
    with_content = mode in CONTENT_MODES
    traces = []
    content_included = False
    for trace in await conn.fetch(_TRACE_SQL, tenant, agent_id, MAX_TRACES):
        steps = []
        for index, step in enumerate(
            await conn.fetch(_STEPS_SQL, tenant, agent_id, trace["trace_id"], MAX_STEPS)
        ):
            item = _doc(step, "payload_ref_id", "capture_mode")
            item["step"] = index
            if with_content and step["capture_mode"] in CONTENT_MODES:
                content = await _content(conn, tenant, step["payload_ref_id"], reader)
                if content is not None:
                    item["arguments_scrubbed"] = content
                    content_included = True
            steps.append(item)
        traces.append({"trace_id": _plain(trace["trace_id"]), "steps": steps})
    return {
        "agent": await agent_profile(conn, tenant, agent_id),
        "capture_mode": mode,
        "content_included": content_included,
        "trajectories": traces,
    }


# --- fleet ------------------------------------------------------------------------------------


async def fleet_doc(conn: Any, tenant: UUID) -> dict[str, Any]:
    row = await conn.fetchrow(_FLEET_SQL, tenant)
    worst = [_doc(r) for r in await conn.fetch(_WORST_SQL, tenant)]
    return {"fleet": _doc(row), "lowest_health_agents": worst, "content_included": False}
