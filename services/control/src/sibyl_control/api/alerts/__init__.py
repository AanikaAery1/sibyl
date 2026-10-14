"""alerts API module (lane P): alerts with ack / silence / close-with-verdict and the D33
unverdicted queue, provider incidents (API.md §5.9, §6.5).

Handlers live on their own routers with full paths; ``stub_router("alerts", ...)`` runs last so
any contract operation without a handler stays mounted as a 501. Route-level authz is
``guard(operationId)``; object rules are evaluated through the ``AuthContext``.
"""

from fastapi import APIRouter, Depends

from sibyl_control.api._stubs import stub_router

from ..auth.common import record_denials
from . import incidents, routes


def build_router() -> APIRouter:
    router = APIRouter(dependencies=[Depends(record_denials)])
    router.include_router(routes.router)
    router.include_router(incidents.router)
    return router


router = stub_router("alerts", build_router())
