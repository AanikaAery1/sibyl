"""Sibyl Sentinel loop (lane SENTINEL, D52, 60 s): the opt-in advisory monitoring agent.

Per enabled tenant it explains new incidents, reviews pending held actions (a recommendation,
never a decision), samples agent trajectories for semantic drift and writes a daily fleet
summary, on the tenant's own LLM key and within its daily budget. Advisory only: it never calls
an enforcement route and writes nothing but findings, usage, their audit rows and watch-only
``sentinel_finding`` alerts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "sentinel"


async def tick(ctx: LoopContext) -> None:
    from ...core.crypto.deks import kek_from_settings
    from ...core.problems import ProblemError
    from ..housekeeping.common import blob_store
    from ..rollup.tenancy import active_tenants
    from .content import payload_reader
    from .runner import Deps, run_tenant

    try:
        kek = kek_from_settings(ctx.settings)
    except ProblemError:
        ctx.log.warning("sentinel loop idle: no key-encryption key configured")
        return
    deps = Deps(
        settings=ctx.settings,
        kek=kek,
        content=payload_reader(lambda: blob_store(ctx.settings), kek),
    )
    for tenant in await active_tenants(ctx.db):
        try:
            await run_tenant(ctx.db, deps, tenant)
        except Exception:
            ctx.log.exception("sentinel loop failed for tenant %s", tenant)


__all__ = ["tick"]
