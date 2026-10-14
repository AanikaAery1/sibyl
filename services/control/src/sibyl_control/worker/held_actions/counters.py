"""``action_counters`` loop (lane AG-LIVE, hourly): retention for cumulative-cap windows.

``action_counter`` keeps one row per (agent, counter key, window length, window start); a
window that ended can never be incremented again (the decision and the approval paths both key
on the current window), so it is swept once it is past ``GRACE_S`` beyond its end. Per tenant
in its own transaction, oldest first, at most ``BATCH`` rows per tick (the index on
``(tenant_id, window_start)`` bounds the scan). Derived data: no audit row; the count is logged.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "action_counters"
GRACE_S = 3600
BATCH = 1000
log = logging.getLogger("sibyl.action_counters")
_SWEEP_SQL = """
DELETE FROM sibyl.action_counter c
 USING (SELECT agent_id, counter_key, window_s, window_start FROM sibyl.action_counter
         WHERE tenant_id = $1 AND window_start < now() - make_interval(secs => $2::int)
           AND window_start + make_interval(secs => window_s + $2::int) < now()
         ORDER BY window_start LIMIT $3) due
 WHERE c.tenant_id = $1 AND c.agent_id = due.agent_id AND c.counter_key = due.counter_key
   AND c.window_s = due.window_s AND c.window_start = due.window_start
"""


async def sweep_tenant(db: Any, tenant: UUID, *, limit: int = BATCH) -> int:
    """Delete up to ``limit`` ended windows of one tenant → how many."""
    async with db.tenant_tx(tenant) as conn:
        status = await conn.execute(_SWEEP_SQL, tenant, GRACE_S, limit)
    return int(str(status).rsplit(" ", 1)[-1] or 0)


async def tick(ctx: LoopContext) -> None:
    from ..rollup.tenancy import active_tenants

    for tenant in await active_tenants(ctx.db):
        try:
            swept = await sweep_tenant(ctx.db, tenant)
        except Exception:
            ctx.log.exception("action_counters sweep failed for tenant %s", tenant)
            continue
        if swept:
            ctx.log.info("action_counters: swept %d ended windows for tenant %s", swept, tenant)


__all__ = ["tick"]
