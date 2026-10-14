"""Drift loop (lane DRIFT, D51, 60 s): model identity and behavioural drift per agent,
provider and requested model, against a frozen baseline. Deterministic (PSI and
Jensen-Shannon), explainable (every report keeps each feature's numbers) and watch-only
(``silent_drift`` / ``model_change`` are leading, cap-0 alerts; the ``drift_cusum`` factor has
cap 0), so drift alone never triggers automation.

Importing the package composes the drift feed into the health engine's extensions
(``factor.install``), like lane P's ``worker.predict`` does for its own feed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .factor import install

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "drift"

install()


async def tick(ctx: LoopContext) -> None:
    """One transaction per active tenant; a failing tenant never blocks the others."""
    from ..rollup.tenancy import active_tenants, try_lock
    from .runner import run_tenant

    for tenant in await active_tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    continue
                result = await run_tenant(conn, tenant)
            if result.fired or result.frozen:
                ctx.log.info(
                    "drift: tenant %s froze %d baselines, raised %d alerts",
                    tenant,
                    len(result.frozen),
                    len(result.fired),
                )
        except Exception:
            ctx.log.exception("drift loop failed for tenant %s", tenant)


__all__ = ["LOOP", "install", "tick"]
