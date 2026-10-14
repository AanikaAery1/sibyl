"""Failback loop (lane S, 30 s): primary probe and the canary step (``probe``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "failback"


async def tick(ctx: LoopContext) -> None:
    from ..rollup.tenancy import active_tenants
    from ..saga.runner import worker_env, worker_id
    from .probe import run_tenant

    env = worker_env(ctx.settings, wid=worker_id().replace("saga:", "failback:", 1))
    for tenant in await active_tenants(ctx.db):
        try:
            await run_tenant(ctx.db, env, tenant)
        except Exception:
            ctx.log.exception("failback loop failed for tenant %s", tenant)


__all__ = ["tick"]
