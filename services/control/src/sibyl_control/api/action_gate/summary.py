"""``GET /action-summary`` (lane AG-LIVE): per-agent Action Gate counts over a window, for the
fleet view's blocked / escalated badges.

Counted from the audit chain (the evidence), not from the tables: ``blocked`` and ``escalated``
are distinct ``call_id``s (an over-cap decision and the hold it leads to are one call),
``approved`` (final approvals only), ``denied`` and ``expired`` are distinct held actions. It
covers what reached the control plane: holds and cumulative decisions (a block an enforcement
point decides locally from the snapshot alone is reported through telemetry, not here).
``actions:read`` is tenant-wide for every role that holds it (0017 seeds), like
``GET /held-actions``, so there is no group filter.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, jsonable, run_read

router = APIRouter()
DEFAULT_WINDOW = timedelta(hours=24)
MAX_WINDOW = timedelta(days=31)
COUNTS = ("blocked", "escalated", "approved", "denied", "expired")
_SQL = """
SELECT e.detail ->> 'agent_id' AS agent_id,
       count(DISTINCT e.detail ->> 'call_id') FILTER (WHERE e.action = 'action.blocked') AS blocked,
       count(DISTINCT e.detail ->> 'call_id') FILTER (WHERE e.action = 'action.escalated')
         AS escalated,
       count(DISTINCT e.detail ->> 'held_action_id') FILTER (
         WHERE e.action = 'action.approved'
           AND (e.detail ->> 'approvals')::int >= (e.detail ->> 'approvals_required')::int)
         AS approved,
       count(DISTINCT e.detail ->> 'held_action_id') FILTER (WHERE e.action = 'action.denied')
         AS denied,
       count(DISTINCT e.detail ->> 'held_action_id') FILTER (WHERE e.action = 'action.expired')
         AS expired
  FROM sibyl.audit_events e
 WHERE e.tenant_id = $1
   AND e.action IN ('action.blocked', 'action.escalated', 'action.approved', 'action.denied',
                    'action.expired')
   AND e.recorded_at >= $2 AND e.recorded_at < $3
   AND e.detail ? 'agent_id'
"""


def window(
    start: datetime | None, end: datetime | None, now: datetime
) -> tuple[datetime, datetime]:
    """``[from, to)``: defaults to the last 24 hours, at most 31 days, ``from`` before ``to``."""
    stop = end or now
    begin = start or (stop - DEFAULT_WINDOW)
    if begin.tzinfo is None or stop.tzinfo is None:
        raise ProblemError("validation_failed", "from and to need a UTC offset")
    if begin >= stop:
        raise ProblemError("validation_failed", "from must be before to")
    if stop - begin > MAX_WINDOW:
        raise ProblemError("validation_failed", "the window is at most 31 days")
    return begin, stop


@router.get(API_PREFIX + "/action-summary")
async def get_action_summary(
    ctx: Annotated[AuthContext, Depends(guard("getActionSummary"))],
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
) -> Response:
    begin, stop = window(start, end, datetime.now(UTC))

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id, begin, stop]
        sql = _SQL
        if agent_id is not None:
            args.append(str(agent_id))
            sql += f" AND e.detail ->> 'agent_id' = ${len(args)}"
        sql += " GROUP BY 1 ORDER BY 1"
        rows = [
            {"agent_id": r["agent_id"], **{name: int(r[name]) for name in COUNTS}}
            for r in await conn.fetch(sql, *args)
        ]
        total = {name: sum(row[name] for row in rows) for name in COUNTS}
        body = {"from": begin, "to": stop, "data": rows, "total": total}
        return Outcome(jsonable(body))

    return await run_read(ctx, work)
