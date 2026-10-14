"""Approvals loop (lane S, 5 s): approval timeouts with the D13/D22 outcome (``timeouts``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "approvals"


async def tick(ctx: LoopContext) -> None:
    from ..rollup.tenancy import active_tenants
    from ..saga.runner import worker_env, worker_id
    from .timeouts import run_tenant

    env = worker_env(ctx.settings, wid=worker_id().replace("saga:", "approvals:", 1))
    for tenant in await active_tenants(ctx.db):
        try:
            await run_tenant(ctx.db, env, tenant)
        except Exception:
            ctx.log.exception("approvals loop failed for tenant %s", tenant)


__all__ = ["tick"]
