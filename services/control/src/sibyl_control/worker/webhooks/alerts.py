"""Watch-only ``external_finding`` alerts for findings that asked for one (D53).

The api records ``alert_requested`` on a critical finding (or a warning with ``raise_alert``)
about an agent; this step raises or refires the agent's one live ``external_finding`` alert and
links it. The rule is a tenant ``alert_rule`` of kind ``leading`` outside the rules seed, created
here on first use: the scoring engine never evaluates it and the failover saga only starts from
``detected`` alerts, so an external monitor can never trigger automation (exactly like Sentinel).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final
from uuid import UUID

from sibyl_schemas.values import EXTERNAL_FINDING_ALERT_RULE

from ...core.outbox import OutboxMessage, OutboxWriter

BATCH: Final = 50
WHAT_TO_DO: Final = (
    "An external monitor flagged this agent (advisory, watch only). Read the finding and decide;"
    " monitors never act."
)
_ENSURE_RULE_SQL = """
INSERT INTO sibyl.alert_rule (tenant_id, code, kind, scope, metric, comparator, thresholds,
  window_s, min_samples, severity, penalty, what_to_do_template, origin)
VALUES ($1, $2, 'leading', 'agent', 'external_monitor', 'boolean',
  '{"watch_only": true, "source": "external_monitor", "tiers": {}}'::jsonb, 86400, 0, 'info', 0,
  $3, 'custom')
ON CONFLICT (tenant_id, code) DO NOTHING
"""
_RULE_SQL = (
    "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = $2 AND enabled"
    " AND kind = 'leading'"
)
_DUE_SQL = """
SELECT f.id, f.agent_id, f.severity, f.summary, f.kind, f.monitor_id, m.name AS monitor_name
  FROM sibyl.external_finding f
  JOIN sibyl.monitor m ON m.tenant_id = f.tenant_id AND m.id = f.monitor_id
 WHERE f.tenant_id = $1 AND f.alert_requested AND f.alert_checked_at IS NULL
 ORDER BY f.created_at
 LIMIT $2
 FOR UPDATE OF f SKIP LOCKED
"""
_LIVE_SQL = (
    "SELECT id FROM sibyl.alert WHERE tenant_id = $1 AND dedupe_key = $2 AND state <> 'resolved'"
    " FOR UPDATE"
)
_INSERT_SQL = """
INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, dedupe_key, what_to_do,
  evidence, summary)
VALUES ($1, $2, 'agent', $3, $4, $5, $6, $7::jsonb, $8)
RETURNING id
"""
_REFIRE_SQL = """
UPDATE sibyl.alert SET fired_count = fired_count + 1, last_evaluated_at = now(), summary = $3,
       evidence = $4::jsonb,
       severity = CASE WHEN severity = 'critical' OR $5 = 'critical' THEN 'critical' ELSE $5 END
 WHERE tenant_id = $1 AND id = $2
"""
_LINK_SQL = (
    "UPDATE sibyl.external_finding SET alert_id = $3, alert_checked_at = now()"
    " WHERE tenant_id = $1 AND id = $2"
)


async def raise_due(conn: Any, outbox: OutboxWriter, tenant: UUID) -> int:
    """Process up to ``BATCH`` findings waiting for an alert decision; returns alerts touched."""
    due = await conn.fetch(_DUE_SQL, tenant, BATCH)
    if not due:
        return 0
    await conn.execute(_ENSURE_RULE_SQL, tenant, EXTERNAL_FINDING_ALERT_RULE, WHAT_TO_DO)
    rule = await conn.fetchval(_RULE_SQL, tenant, EXTERNAL_FINDING_ALERT_RULE)
    touched = 0
    for row in due:
        alert_id = None
        if rule is not None and row["agent_id"] is not None:
            alert_id = await _raise(conn, outbox, tenant, rule, row)
            touched += 1
        await conn.execute(_LINK_SQL, tenant, row["id"], alert_id)
    return touched


async def _raise(
    conn: Any, outbox: OutboxWriter, tenant: UUID, rule: UUID, row: Mapping[str, Any]
) -> UUID:
    agent = row["agent_id"]
    key = f"{EXTERNAL_FINDING_ALERT_RULE}:agent:{agent}"
    evidence = {
        "finding_id": str(row["id"]),
        "kind": row["kind"],
        "monitor_id": str(row["monitor_id"]),
        "watch_only": True,
    }
    summary = f"{row['monitor_name']}: {row['summary']}"[:500]
    live = await conn.fetchval(_LIVE_SQL, tenant, key)
    if live is not None:
        await conn.execute(_REFIRE_SQL, tenant, live, summary, evidence, row["severity"])
        alert_id: UUID = live
        event = "alert.updated"
    else:
        alert_id = await conn.fetchval(
            _INSERT_SQL, tenant, rule, agent, row["severity"], key, WHAT_TO_DO, evidence, summary
        )
        event = "alert.fired"
    await outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            event,
            "alert",
            alert_id,
            {
                "alert_id": str(alert_id),
                "rule": EXTERNAL_FINDING_ALERT_RULE,
                "severity": row["severity"],
                "scope": "agent",
                "state": "open",
                "agent_id": str(agent),
            },
        ),
    )
    return alert_id
