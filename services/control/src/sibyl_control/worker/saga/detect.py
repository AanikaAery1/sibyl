"""Detected-failure triggers: open alerts from the health engine → sagas (ML §4.5 row 1).

A candidate is an open, un-actioned ``detected`` alert on an agent that is serving on its
primary (``active``/``degraded``), with no live saga and no saga already opened for that alert,
whose latest health snapshot is ``failed``. Members of an open critical provider incident also
qualify at ``degraded`` (the collapse is the corroboration). Guard rails:

* **Lone-agent corroboration** (ML §4.6 rail 2): a single failing agent whose provider is green
  and has no provider incident waits one extra scoring cycle before failing over.
* **Operator hold** (D21): a held agent is skipped and the alert's ``hold_suppressed_count``
  climbs (once per evaluation).
* **A person's deny holds for its episode** (S-26): an alert that was already open when a person
  denied a failover approval for the agent never opens another saga (``awaiting_approval →
  degraded: denied``); the next one would ask the same question a second later, and another
  person could approve what the first refused. An alert that fires after the deny is a new
  failure and may.
* **Provider collapse, batched** (sre §2.3): members of one provider incident are opened in one
  transaction, tier 1 first, with the incident's provider excluded from their viable targets.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from . import engine, entry
from .model import (
    LONE_AGENT_EXTRA,
    PROVIDER_LOOKBACK,
    RULE_FAILURE_MODE,
    Actor,
    Env,
    SagaError,
    SagaOpen,
)

_CANDIDATES_SQL = """
WITH latest AS (
  SELECT DISTINCT ON (agent_id) agent_id, id AS snapshot_id, band
    FROM sibyl.health_snapshot
   WHERE tenant_id = $1 AND evaluated_at > now() - interval '15 minutes'
   ORDER BY agent_id, evaluated_at DESC, id DESC
)
SELECT DISTINCT ON (a.agent_id) a.id AS alert_id, a.agent_id, a.rule_id, r.code, a.severity,
       a.first_fired_at, coalesce(a.health_snapshot_id, l.snapshot_id) AS snapshot_id, l.band,
       g.tier, rs.state AS routing_state, (rs.operator_hold_until > now()) AS held,
       pi.id AS incident_id, pi.provider_id AS incident_provider_id,
       (a.first_fired_at <= now() - $2::interval) AS corroborated_by_age,
       (SELECT m.provider_id FROM sibyl.agent_version v JOIN sibyl.model m
          ON m.tenant_id = v.tenant_id AND m.id = v.primary_model_id
         WHERE v.tenant_id = g.tenant_id AND v.id = g.current_version_id) AS primary_provider_id
  FROM sibyl.alert a
  JOIN sibyl.alert_rule r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id AND r.kind = 'detected'
  JOIN sibyl.agent g ON g.tenant_id = a.tenant_id AND g.id = a.agent_id AND g.lifecycle <> 'retired'
  JOIN sibyl.routing_state rs ON rs.tenant_id = a.tenant_id AND rs.agent_id = a.agent_id
  JOIN latest l ON l.agent_id = a.agent_id
  LEFT JOIN sibyl.provider_incident pi
    ON pi.tenant_id = a.tenant_id AND pi.id = a.provider_incident_id AND pi.state = 'open'
 WHERE a.tenant_id = $1 AND a.scope = 'agent' AND a.state IN ('open', 'acked')
   AND a.failover_id IS NULL AND rs.state IN ('active', 'degraded')
   AND (l.band = 'failed' OR (pi.id IS NOT NULL AND pi.severity = 'critical' AND l.band =
     'degraded'))
   AND NOT EXISTS (SELECT 1 FROM sibyl.failover f WHERE f.tenant_id = a.tenant_id
                     AND (f.trigger_alert_id = a.id
                          OR (f.agent_id = a.agent_id
                              AND f.state IN ('pending', 'running', 'waiting_approval'))))
   AND NOT EXISTS (SELECT 1 FROM sibyl.approval p WHERE p.tenant_id = a.tenant_id
                     AND p.agent_id = a.agent_id AND p.state = 'denied'
                     AND p.decided_at >= a.first_fired_at)
 ORDER BY a.agent_id, (a.severity = 'critical') DESC, a.first_fired_at
 LIMIT $3
"""
_UNHEALTHY_SQL = """
SELECT provider_id FROM sibyl.provider_status
 WHERE tenant_id = $1 AND status NOT IN ('operational', 'unknown') AND observed_at > now() -
   $2::interval
UNION
SELECT provider_id FROM sibyl.provider_incident WHERE tenant_id = $1 AND state = 'open'
"""


@dataclass(frozen=True)
class Detection:
    opened: tuple[UUID, ...]
    held: int
    waiting_corroboration: int
    batches: int


def _request(c: Any, batch: dict[str, Any] | None) -> SagaOpen:
    code = str(c["code"])
    return SagaOpen(
        agent_id=c["agent_id"],
        actor=Actor("rule", rule_id=c["rule_id"]),
        trigger="detected",
        idempotency_key=f"detected:{c['alert_id']}",
        trigger_alert_id=c["alert_id"],
        rule_codes=(code,),
        health_snapshot_id=c["snapshot_id"],
        failure_mode=RULE_FAILURE_MODE.get(code),
        priority="immediate" if int(c["tier"]) == 1 else "normal",
        reason=f"Detected failure: rule {code} with health band {c['band']}.",
        batch=batch,
        excluded_provider_ids=(c["incident_provider_id"],) if c["incident_provider_id"] else (),
    )


async def detect(conn: Any, env: Env, tenant: UUID, *, limit: int = 200) -> Detection:
    """Open sagas for detected failures in the caller's (worker) transaction."""
    rows = await conn.fetch(_CANDIDATES_SQL, tenant, LONE_AGENT_EXTRA, limit)
    unhealthy = {
        r["provider_id"] for r in await conn.fetch(_UNHEALTHY_SQL, tenant, PROVIDER_LOOKBACK)
    }
    failing_by_provider: dict[UUID, int] = defaultdict(int)
    for r in rows:
        if r["primary_provider_id"] is not None:
            failing_by_provider[r["primary_provider_id"]] += 1
    held = waiting = 0
    singles: list[Any] = []
    groups: dict[UUID, list[Any]] = defaultdict(list)
    for r in rows:
        if r["held"]:
            await engine.suppress_for_hold(conn, tenant, r["alert_id"])
            held += 1
            continue
        if r["incident_id"] is not None:
            groups[r["incident_id"]].append(r)
            continue
        provider = r["primary_provider_id"]
        lone = provider not in unhealthy and failing_by_provider.get(provider, 0) < 2
        if lone and not r["corroborated_by_age"]:
            waiting += 1
            continue
        singles.append(r)
    opened: list[UUID] = []
    for incident_id, members in groups.items():
        ordered = sorted(members, key=lambda m: (int(m["tier"]), m["first_fired_at"]))
        for position, m in enumerate(ordered):
            batch = {
                "provider_incident_id": str(incident_id),
                "position": position,
                "size": len(ordered),
                "tier": int(m["tier"]),
            }
            opened.extend(await _open(conn, env, tenant, [m], batch))
    for r in singles:
        opened.extend(await _open(conn, env, tenant, [r], {"tier": int(r["tier"])}))
    return Detection(tuple(opened), held, waiting, len(groups))


async def _open(
    conn: Any, env: Env, tenant: UUID, rows: Sequence[Any], batch: dict[str, Any]
) -> list[UUID]:
    out: list[UUID] = []
    for r in rows:
        try:
            row, created = await entry.open_saga(conn, tenant, _request(r, batch), env=env)
        except SagaError:
            continue  # a saga went live for this agent in the meantime
        if created:
            out.append(row["id"])
    return out
