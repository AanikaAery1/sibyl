"""``partitions`` loop (lane U, G1 blocker): keep every partitioned table covered ahead.

Hourly, ``sibyl.partition_ensure_ahead(now())`` creates any missing partition from one period
back to each table's ``ahead`` window (7 days daily, 9 days for 3-day, 2 months monthly;
``partition_policy()``), each with the tenant RLS policy, serialised per table by an advisory
lock inside the function. There are no DEFAULT partitions, so without this loop inserts into
``outbox`` / ``events`` start failing about 7 days after deploy.

After ensuring, the horizon is checked: a table whose coverage ends within ``MIN_RUNWAY`` makes
the tick fail (the worker ``/healthz`` then reports the loop failing) instead of silently
running towards the edge.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from ..loops import LoopContext

MIN_RUNWAY = timedelta(days=2)


class PartitionRunwayLow(RuntimeError):
    """A partitioned table is covered for less than ``MIN_RUNWAY``."""


@dataclass(frozen=True)
class PartitionReport:
    created: int
    horizon: dict[str, datetime | None]
    short: tuple[str, ...]


async def ensure(db: Any, *, now: datetime | None = None) -> PartitionReport:
    async with db.system_tx() as conn:
        at = now or await conn.fetchval("SELECT now()")
        created = int(await conn.fetchval("SELECT sibyl.partition_ensure_ahead($1)", at))
        rows = await conn.fetch("SELECT table_name, covered_until FROM sibyl.partition_horizon()")
    horizon = {r["table_name"]: r["covered_until"] for r in rows}
    short = tuple(
        sorted(t for t, until in horizon.items() if until is None or until < at + MIN_RUNWAY)
    )
    return PartitionReport(created, horizon, short)


async def tick(ctx: LoopContext) -> None:
    report = await ensure(ctx.db)
    if report.created:
        ctx.log.info("partitions: created %d partition(s)", report.created)
    if report.short:
        raise PartitionRunwayLow("partition runway below 2 days: " + ", ".join(report.short))
