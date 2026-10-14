"""What the alert loop still owns once fire / re-fire / resolve live in the scoring tick
(ML.md §3.7; sre §2.2-§2.4): silence expiry, the escalated ``what_to_do``, and the
unverdicted-backlog SLI.

* **Silence expiry**: a silenced alert is ``acked`` with ``silenced_until``; when that passes and
  the alert is still live it re-opens (``acked -> open``, ``fired_count + 1``, no new row), and
  ``alert.updated`` goes out. A resolved alert just drops the stale silence.
* **Escalation**: the scoring tick bumps ``escalation_level`` and severity on the third fire in
  ``escalate_window_s``; this switches ``what_to_do`` to the escalated wording once per level.
* **Unverdicted backlog SLI** (D33, R42): unverdicted resolved alerts older than 7 days divided
  by alerts resolved in the last 30 days; target < 20 %. Above it the console shows a banner;
  nothing writes a verdict (no auto-verdicts).

Requires ``alert.silenced_until`` / ``alert.silenced_by_user_id`` (change request INT-1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.outbox import OutboxMessage, OutboxWriter

BACKLOG_AGE = timedelta(days=7)
BACKLOG_WINDOW = timedelta(days=30)
BACKLOG_TARGET = 0.20

_EXPIRE_SQL = """
UPDATE sibyl.alert a
   SET silenced_until = NULL,
       state = CASE WHEN a.state = 'acked' THEN 'open' ELSE a.state END,
       fired_count = a.fired_count + CASE WHEN a.state = 'acked' THEN 1 ELSE 0 END,
       last_evaluated_at = CASE WHEN a.state = 'acked' THEN $2 ELSE a.last_evaluated_at END
 WHERE a.tenant_id = $1 AND a.silenced_until IS NOT NULL AND a.silenced_until <= $2
RETURNING a.id, a.state, a.severity, a.scope, a.agent_id, a.provider_id, a.provider_incident_id,
          (SELECT r.code FROM sibyl.alert_rule r
            WHERE r.tenant_id = a.tenant_id AND r.id = a.rule_id) AS rule_code
"""
# sre §2.3: the escalated variant of what_to_do ("third fire in an hour; this is not transient").
_ESCALATE_SQL = r"""
UPDATE sibyl.alert
   SET what_to_do = left(
         format('Escalated (level %s): this is not transient; consider failover or handoff. ',
                escalation_level)
         || regexp_replace(what_to_do,
              '^Escalated \(level [0-9]+\): this is not transient; consider failover or handoff\. ',
              ''),
         1000)
 WHERE tenant_id = $1 AND state <> 'resolved' AND escalation_level > 0
   AND what_to_do NOT LIKE format('Escalated (level %s):%%', escalation_level)
RETURNING id
"""
_BACKLOG_SQL = """
SELECT count(*) FILTER (WHERE verdict IS NULL AND resolved_at < $2) AS old_unverdicted,
       count(*) FILTER (WHERE resolved_at >= $3) AS resolved_30d,
       count(*) FILTER (WHERE verdict IS NULL) AS unverdicted,
       count(*) FILTER (WHERE verdict IS NULL AND verdict_wanted) AS verdict_wanted
  FROM sibyl.alert
 WHERE tenant_id = $1 AND state = 'resolved'
"""


@dataclass(frozen=True)
class BacklogSli:
    old_unverdicted: int
    resolved_30d: int
    unverdicted: int
    verdict_wanted: int
    ratio: float
    breached: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "unverdicted": self.unverdicted,
            "verdict_wanted": self.verdict_wanted,
            "unverdicted_older_than_7d": self.old_unverdicted,
            "resolved_last_30d": self.resolved_30d,
            "ratio": round(self.ratio, 4),
            "target": BACKLOG_TARGET,
            "banner": self.breached,
        }


@dataclass
class AlertsResult:
    reopened: list[UUID] = field(default_factory=list)
    silence_cleared: list[UUID] = field(default_factory=list)
    escalated: list[UUID] = field(default_factory=list)
    backlog: BacklogSli | None = None


async def expire_silences(
    conn: Any, tenant: UUID, now: datetime, outbox: OutboxWriter
) -> tuple[list[UUID], list[UUID]]:
    reopened: list[UUID] = []
    cleared: list[UUID] = []
    for r in await conn.fetch(_EXPIRE_SQL, tenant, now):
        if r["state"] != "open":
            cleared.append(r["id"])
            continue
        reopened.append(r["id"])
        payload: dict[str, Any] = {
            "alert_id": str(r["id"]),
            "rule": r["rule_code"] or "",
            "severity": r["severity"],
            "scope": r["scope"],
            "state": "open",
            "cause": "silence_expired",
        }
        for key in ("agent_id", "provider_id", "provider_incident_id"):
            if r[key] is not None:
                payload[key] = str(r[key])
        await outbox.emit(
            conn, tenant, OutboxMessage("alert", "alert.updated", "alert", r["id"], payload)
        )
    return reopened, cleared


async def escalate(conn: Any, tenant: UUID) -> list[UUID]:
    return [r["id"] for r in await conn.fetch(_ESCALATE_SQL, tenant)]


async def backlog_sli(conn: Any, tenant: UUID, now: datetime) -> BacklogSli:
    r = await conn.fetchrow(_BACKLOG_SQL, tenant, now - BACKLOG_AGE, now - BACKLOG_WINDOW)
    old, resolved = int(r["old_unverdicted"] or 0), int(r["resolved_30d"] or 0)
    ratio = old / resolved if resolved else 0.0
    return BacklogSli(
        old,
        resolved,
        int(r["unverdicted"] or 0),
        int(r["verdict_wanted"] or 0),
        ratio,
        ratio >= BACKLOG_TARGET and old > 0,
    )


async def run_tenant(conn: Any, tenant: UUID, now: datetime, outbox: OutboxWriter) -> AlertsResult:
    reopened, cleared = await expire_silences(conn, tenant, now, outbox)
    return AlertsResult(
        reopened=reopened,
        silence_cleared=cleared,
        escalated=await escalate(conn, tenant),
        backlog=await backlog_sli(conn, tenant, now),
    )
