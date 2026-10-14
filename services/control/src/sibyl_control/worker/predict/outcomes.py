"""Point-in-time outcomes for predictions whose horizon has passed (ML.md §7.3).

A prediction's outcome is ``failed`` when the agent reached band ``failed`` within
``(predicted_at, predicted_at + horizon_s]``, else ``no_event``; ``lead_time_s`` is the time
from the prediction to that first failed snapshot. Nothing after ``predicted_at + horizon_s``
is read, so outcomes are point-in-time. Predictions older than the snapshot retention resolve
``unknown``. Bounded per tick; ``ix_prediction_open`` serves the scan.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

BATCH = 500
SNAPSHOT_RETENTION = timedelta(days=3)

_FILL_SQL = """
WITH due AS (
  SELECT tenant_id, predicted_at, id, agent_id, horizon_s
    FROM sibyl.prediction
   WHERE tenant_id = $1 AND outcome IS NULL
     AND predicted_at + make_interval(secs => horizon_s) <= $2
   ORDER BY predicted_at
   LIMIT $3
), judged AS (
  SELECT d.*, (SELECT min(h.evaluated_at) FROM sibyl.health_snapshot h
                WHERE h.tenant_id = d.tenant_id AND h.agent_id = d.agent_id AND h.band = 'failed'
                  AND h.evaluated_at > d.predicted_at
                  AND h.evaluated_at <= d.predicted_at + make_interval(secs => d.horizon_s)
              ) AS failed_at
    FROM due d
)
UPDATE sibyl.prediction p
   SET outcome = CASE WHEN j.failed_at IS NOT NULL THEN 'failed'
                      WHEN j.predicted_at < $4 THEN 'unknown' ELSE 'no_event' END,
       outcome_at = coalesce(j.failed_at, j.predicted_at + make_interval(secs => j.horizon_s)),
       lead_time_s = CASE WHEN j.failed_at IS NULL THEN NULL
                          ELSE extract(epoch FROM j.failed_at - j.predicted_at)::int END
  FROM judged j
 WHERE p.tenant_id = j.tenant_id AND p.predicted_at = j.predicted_at AND p.id = j.id
RETURNING p.outcome
"""


async def fill_outcomes(conn: Any, tenant: UUID, now: datetime) -> dict[str, int]:
    rows = await conn.fetch(_FILL_SQL, tenant, now, BATCH, now - SNAPSHOT_RETENTION)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    return counts
