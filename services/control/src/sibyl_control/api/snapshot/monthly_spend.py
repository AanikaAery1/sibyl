"""Observed month-to-date gateway spend, projected into policy snapshots.

WARNING: Telemetry is asynchronous, may contain unpriced requests, and does not
cover traffic that bypasses the gateway. This is a reporting figure, NOT an
authoritative hard-budget cap. Strict budget enforcement requires an atomic
shared reservation before dispatching each billable provider attempt.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import UUID

# The source filter avoids double counting SDK and gateway observations of a
# single model request. Exclude unknown/unpriced events rather than invent cost.
_MONTH_SPEND_SQL = """
SELECT agent_id, COALESCE(SUM(GREATEST(cost_usd, 0)), 0) AS month_spend
  FROM sibyl.events
 WHERE tenant_id = $1
   AND agent_id = ANY($2::uuid[])
   AND event_type = 'gen_ai.request'
   AND source = 'gateway'
   AND cost_usd IS NOT NULL
   AND ts >= (date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
   AND ts < ((date_trunc('month', now() AT TIME ZONE 'UTC') + interval '1 month')
             AT TIME ZONE 'UTC')
 GROUP BY agent_id
"""


async def observed_month_to_date_spend(
    conn: Any, tenant_id: UUID, agent_ids: set[UUID]
) -> dict[UUID, Decimal]:
    """Return non-negative amounts for agents with priced gateway telemetry."""
    if not agent_ids:
        return {}
    rows = await conn.fetch(_MONTH_SPEND_SQL, tenant_id, sorted(agent_ids, key=str))
    return {row["agent_id"]: Decimal(row["month_spend"]) for row in rows}
