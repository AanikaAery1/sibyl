"""Scoring loop (lane H): health score, bands, alerts, provider incidents (ML.md §3, §7.4).

The package root stays import-light (the rollup imports ``scoring.features``); the tick imports
its machinery on first use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "scoring"


async def tick(ctx: LoopContext) -> None:
    """Score every active tenant, one transaction each; a failing tenant never blocks others."""
    from ..rollup.tenancy import active_tenants, try_lock
    from .runner import score_tenant

    for tenant in await active_tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    continue
                await score_tenant(conn, tenant)
        except Exception:
            ctx.log.exception("scoring failed for tenant %s", tenant)


__all__ = ["tick"]
