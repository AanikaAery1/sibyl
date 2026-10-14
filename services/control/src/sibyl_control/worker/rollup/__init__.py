"""Rollup loop (lane H): ``events`` -> ``agent_metrics_1m/5m/1h`` + ``provider_metrics_5m``."""

from __future__ import annotations

from ..loops import LoopContext
from .pipeline import RollupResult, rollup_tenant
from .tenancy import active_tenants, try_lock
from .trend import advance_trend_state

LOOP = "rollup"


async def tick(ctx: LoopContext) -> None:
    """One bounded rollup unit per tenant, each in its own transaction (ML.md §7.2)."""
    for tenant in await active_tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    continue
                result = await rollup_tenant(conn, tenant)
                if result.closed_5m:
                    await advance_trend_state(conn, tenant, result.closed_5m)
        except Exception:
            ctx.log.exception("rollup failed for tenant %s", tenant)
            continue
        if result.carryover:
            ctx.log.warning("rollup carryover for tenant %s (lag %.0f s)", tenant, result.lag_s)


__all__ = ["RollupResult", "advance_trend_state", "rollup_tenant", "tick"]
