"""Alert loop (lane P), re-scoped: fire / re-fire / resolve / auto-resolve and provider
collapse already run inside the scoring tick (``worker.scoring.alerts``). This loop keeps what
is left: silence expiry, the escalated ``what_to_do`` and the unverdicted-backlog SLI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .lifecycle import AlertsResult, BacklogSli, backlog_sli, escalate, expire_silences, run_tenant

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "alerts"


async def tick(ctx: LoopContext) -> None:
    """One transaction per active tenant; a failing tenant never blocks the others."""
    from ...core.outbox import PgOutboxWriter
    from ..rollup.tenancy import active_tenants, try_lock

    outbox = PgOutboxWriter()
    for tenant in await active_tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    continue
                now = await conn.fetchval("SELECT now()")
                result = await run_tenant(conn, tenant, now, outbox)
        except Exception:
            ctx.log.exception("alert loop failed for tenant %s", tenant)
            continue
        backlog = result.backlog
        if backlog is not None and backlog.breached:
            ctx.log.warning(
                "unverdicted alert backlog for tenant %s at %.0f%% (target < 20%%)",
                tenant,
                backlog.ratio * 100,
            )


__all__ = [
    "LOOP",
    "AlertsResult",
    "BacklogSli",
    "backlog_sli",
    "escalate",
    "expire_silences",
    "run_tenant",
    "tick",
]
