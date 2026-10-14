"""The persisted per-agent pre-emptive breaker (sre guard rail 5; ML.md §4.6 item 5).

Two automated (``rule`` / ``policy``) routing transitions that were undone, or alerts of
automated failovers verdicted ``fp``, within ``BREAKER_WINDOW`` trip an agent's breaker. Only
automations after the last human clear count, so a clear is never undone by the evidence it
just reviewed.

* Trip (worker, ``trip_breakers``): ``agent.preemptive_breaker_tripped_at`` is set and
  ``preemptive.breaker_tripped`` (actor ``system``) appended in the same transaction, with
  ``sibyl.audit_lock`` taken before the agent rows are locked (G0). The worker role may update
  only that column.
* State: the column. While it is set, every predicted failover of the agent runs in
  ``approval`` mode (no automated pre-emptive action), across worker restarts and after the
  window has passed, until a human clears it. Tier 1 is always ``approval`` already and never
  trips.
* Clear (api, a human, ``clear_breaker``): ``tripped_at`` back to ``NULL``,
  ``cleared_at`` / ``cleared_by_user_id`` set and ``preemptive.breaker_cleared`` appended with
  the human's reason. The ``sibyl_app`` role runs it; no contract operation wires it yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.audit import AuditActor, AuditReceipt, AuditRecord, AuditWriter, PgAuditWriter

BREAKER_WINDOW = timedelta(days=7)
BREAKER_TRIPS = 2
TRIPPED_ACTION = "preemptive.breaker_tripped"
CLEARED_ACTION = "preemptive.breaker_cleared"
AUDIT_LOCK_SQL = "SELECT sibyl.audit_lock($1)"

# Every armed agent of the tenant with its trip count, in one statement (flat in agents).
_DUE_SQL = """
WITH armed AS (
  SELECT a.id, greatest($2::timestamptz,
                        coalesce(a.preemptive_breaker_cleared_at, '-infinity')) AS since
    FROM sibyl.agent a
   WHERE a.tenant_id = $1 AND a.preemptive_breaker_tripped_at IS NULL AND a.tier <> 1
     AND a.lifecycle <> 'retired'
), undone AS (
  SELECT t.agent_id, count(*) AS n
    FROM sibyl.routing_transition t JOIN armed ON armed.id = t.agent_id
   WHERE t.tenant_id = $1 AND t.actor_kind IN ('rule', 'policy') AND t.created_at > armed.since
     AND EXISTS (SELECT 1 FROM sibyl.routing_transition u
                  WHERE u.tenant_id = t.tenant_id AND u.inverse_of = t.id)
   GROUP BY t.agent_id
), fp AS (
  SELECT al.agent_id, count(*) AS n
    FROM sibyl.alert al JOIN armed ON armed.id = al.agent_id
   WHERE al.tenant_id = $1 AND al.verdict = 'fp' AND al.updated_at > armed.since
     AND EXISTS (SELECT 1 FROM sibyl.failover f
                  WHERE f.tenant_id = al.tenant_id AND f.actor_kind IN ('rule', 'policy')
                    AND (f.id = al.failover_id OR f.trigger_alert_id = al.id))
   GROUP BY al.agent_id
)
SELECT armed.id AS agent_id, coalesce(undone.n, 0) + coalesce(fp.n, 0) AS trips
  FROM armed
  LEFT JOIN undone ON undone.agent_id = armed.id
  LEFT JOIN fp ON fp.agent_id = armed.id
 WHERE coalesce(undone.n, 0) + coalesce(fp.n, 0) >= $3
 ORDER BY armed.id
"""
_TRIP_SQL = """
UPDATE sibyl.agent SET preemptive_breaker_tripped_at = $3
 WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND preemptive_breaker_tripped_at IS NULL
RETURNING id
"""
_CLEAR_SQL = """
WITH cur AS (
  SELECT id, preemptive_breaker_tripped_at AS tripped_at FROM sibyl.agent
   WHERE tenant_id = $1 AND id = $2 AND preemptive_breaker_tripped_at IS NOT NULL
   FOR UPDATE
)
UPDATE sibyl.agent a SET preemptive_breaker_tripped_at = NULL,
       preemptive_breaker_cleared_at = now(), preemptive_breaker_cleared_by_user_id = $3
  FROM cur
 WHERE a.tenant_id = $1 AND a.id = cur.id
RETURNING cur.tripped_at, a.preemptive_breaker_cleared_at AS cleared_at
"""


@dataclass(frozen=True)
class BreakerTrip:
    agent_id: UUID
    trips: int
    tripped_at: datetime


@dataclass(frozen=True)
class BreakerCleared:
    agent_id: UUID
    tripped_at: datetime
    cleared_at: datetime
    receipt: AuditReceipt


async def trip_breakers(
    conn: Any, tenant: UUID, now: datetime, *, audit: AuditWriter | None = None
) -> list[BreakerTrip]:
    """Trip every armed agent of ``tenant`` that crossed ``BREAKER_TRIPS`` (worker tx).

    Call before the transaction takes any other row lock: when something is due it takes
    ``sibyl.audit_lock`` first, then the agent rows, then appends one audit row per trip.
    """
    due = {
        r["agent_id"]: int(r["trips"])
        for r in await conn.fetch(_DUE_SQL, tenant, now - BREAKER_WINDOW, BREAKER_TRIPS)
    }
    if not due:
        return []
    await conn.execute(AUDIT_LOCK_SQL, tenant)
    updated = await conn.fetch(_TRIP_SQL, tenant, sorted(due, key=str), now)
    writer = audit or PgAuditWriter()
    trips = [BreakerTrip(r["id"], due[r["id"]], now) for r in updated]
    for trip in sorted(trips, key=lambda t: str(t.agent_id)):
        await writer.append(conn, tenant, _tripped_record(trip))
    return trips


def _tripped_record(trip: BreakerTrip) -> AuditRecord:
    return AuditRecord(
        action=TRIPPED_ACTION,
        actor_type="system",
        resource_type="agent",
        resource_id=trip.agent_id,
        detail={
            "agent_id": str(trip.agent_id),
            "trips": trip.trips,
            "window_s": int(BREAKER_WINDOW.total_seconds()),
        },
        occurred_at=trip.tripped_at,
    )


async def clear_breaker(
    conn: Any,
    tenant: UUID,
    agent: UUID,
    *,
    actor: AuditActor,
    reason: str,
    request_id: UUID | None = None,
    audit: AuditWriter | None = None,
) -> BreakerCleared | None:
    """A human re-arms ``agent``'s breaker (``sibyl_app`` tenant tx); ``None`` when not tripped.

    ``actor`` must be a human (the taxonomy refuses anything else) and ``reason`` non-blank.
    Takes ``sibyl.audit_lock`` before the agent row (idempotent if the caller already holds it).
    """
    text = reason.strip()
    if not text:
        raise ValueError("clearing the pre-emptive breaker needs a reason")
    if actor.actor_type != "human" or actor.actor_id is None:
        raise ValueError("only a human clears the pre-emptive breaker")
    await conn.execute(AUDIT_LOCK_SQL, tenant)
    row = await conn.fetchrow(_CLEAR_SQL, tenant, agent, actor.actor_id)
    if row is None:
        return None
    record = AuditRecord(
        action=CLEARED_ACTION,
        resource_type="agent",
        resource_id=agent,
        reason=text,
        detail={"agent_id": str(agent), "tripped_at": row["tripped_at"].isoformat()},
        request_id=request_id,
        **actor.fields(),
    )
    receipt = await (audit or PgAuditWriter()).append(conn, tenant, record)
    return BreakerCleared(agent, row["tripped_at"], row["cleared_at"], receipt)


__all__ = [
    "BREAKER_TRIPS",
    "BREAKER_WINDOW",
    "BreakerCleared",
    "BreakerTrip",
    "clear_breaker",
    "trip_breakers",
]
