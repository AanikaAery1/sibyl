"""Held-actions loop (lane AG-CORE, 5 s): expire pending holds as deny at ``hold_timeout_s``."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "held_actions"


async def tick(ctx: LoopContext) -> None:
    from ..rollup.tenancy import active_tenants
    from ..saga.runner import worker_env, worker_id
    from .expiry import run_tenant

    env = worker_env(ctx.settings, wid=worker_id().replace("saga:", "held_actions:", 1))
    for tenant in await active_tenants(ctx.db):
        try:
            await run_tenant(ctx.db, env, tenant)
        except Exception:
            ctx.log.exception("held_actions loop failed for tenant %s", tenant)


__all__ = ["tick"]
