"""registry API module (lane R): agents, lifecycle, identity, versions, graph, catalogs, providers.

Handlers live on per-area routers with full paths; ``stub_router("registry", router)`` comes
last so any contract operation not implemented here stays mounted as a 501. Route-level authz
comes from ``guard(operationId)``; object rules are evaluated in the handlers (``_kit``).
"""

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from . import agents, catalog, graph, identity, providers, versions


def build_router() -> APIRouter:
    router = APIRouter()
    for area in (agents, identity, versions, graph, catalog, providers):
        router.include_router(area.router)
    return stub_router("registry", router)


router = build_router()
