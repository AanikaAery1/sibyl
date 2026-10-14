"""Pre-registered routers, one per API module directory (ROADMAP §4.1). No lane edits this file.

Order matters where literal paths share a prefix with parameterised ones: ``sse`` mounts
``GET /api/v1/events/stream`` before ``reads`` mounts ``GET /api/v1/events/{event_id}``.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI

from sibyl_control.api import (
    action_gate,
    alerts,
    approvals,
    auth,
    credentials,
    drift,
    findings,
    governance,
    incidents,
    keys,
    killswitch,
    monitors,
    policy,
    queue,
    reads,
    registry,
    sentinel,
    snapshot,
    sse,
    tenancy,
)
from sibyl_control.api._stubs import iter_api_routes

__all__ = ["ROUTER_MODULES", "include_all", "iter_api_routes"]

ROUTER_MODULES: tuple[str, ...] = (
    "auth",
    "tenancy",
    "keys",
    "registry",
    "policy",
    "credentials",
    "snapshot",
    "sse",
    "reads",
    "incidents",
    "approvals",
    "killswitch",
    "queue",
    "alerts",
    "governance",
    "action_gate",
    "drift",
    "sentinel",
    "monitors",
    "findings",
)

_ROUTERS: dict[str, APIRouter] = {
    "auth": auth.router,
    "tenancy": tenancy.router,
    "keys": keys.router,
    "registry": registry.router,
    "policy": policy.router,
    "credentials": credentials.router,
    "snapshot": snapshot.router,
    "sse": sse.router,
    "reads": reads.router,
    "incidents": incidents.router,
    "approvals": approvals.router,
    "killswitch": killswitch.router,
    "queue": queue.router,
    "alerts": alerts.router,
    "governance": governance.router,
    "action_gate": action_gate.router,
    "drift": drift.router,
    "sentinel": sentinel.router,
    "monitors": monitors.router,
    "findings": findings.router,
}


def include_all(app: FastAPI) -> None:
    for name in ROUTER_MODULES:
        app.include_router(_ROUTERS[name])
