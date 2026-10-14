"""Saga loop (lane S): detected-failure triggers and the failover saga (API.md §6.2, B1).

Entry points for other lanes:

* ``request_predicted_failover(conn, tenant_id, agent_id, prediction_id, horizon, band,
  confidence, *, mode, settings)`` — lane P's agreed entry (P has gated; ``mode`` is its
  decision; the ``Env`` and the D36 band come from the worker's ``Settings``, B20);
* ``open_predicted(conn, tenant, PredictedTrigger(...), env=...)`` — the gated prediction path
  (tier gating, D36 from ``env.automation_band``, D39, breaker, D21 hold);
* ``open_saga(conn, tenant, SagaOpen(...))`` — the generic opener (detected, predicted,
  operator) used by the detector and by the incidents api.

The tick detects, then drives runnable sagas one committed step at a time (SKIP LOCKED).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .entry import (
    PredictedOutcome,
    PredictedTrigger,
    open_predicted,
    open_saga,
    request_predicted_failover,
)
from .model import Actor, SagaError, SagaOpen, Target

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "saga"


async def tick(ctx: LoopContext) -> None:
    """One pass over every active tenant; a failing tenant never blocks the others."""
    from ..rollup.tenancy import active_tenants
    from .runner import run_tenant, worker_env

    env = worker_env(ctx.settings)
    for tenant in await active_tenants(ctx.db):
        try:
            await run_tenant(ctx.db, env, tenant)
        except Exception:
            ctx.log.exception("saga loop failed for tenant %s", tenant)


__all__ = [
    "Actor",
    "PredictedOutcome",
    "PredictedTrigger",
    "SagaError",
    "SagaOpen",
    "Target",
    "open_predicted",
    "open_saga",
    "request_predicted_failover",
    "tick",
]
