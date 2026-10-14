"""policy API module (lane R): capture policies, redaction profiles, continuity plans,
fallback chains and alert rules (API.md §5.6).

Handlers live on their own routers with full paths; ``stub_router("policy", ...)`` runs last so
any contract operation without a handler stays mounted as a 501. Route-level authz is
``guard(operationId)``; object rules are evaluated through the ``AuthContext``.
"""

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from . import alert_rules, capture, continuity


def build_router() -> APIRouter:
    router = APIRouter()
    router.include_router(capture.router)
    router.include_router(continuity.router)
    router.include_router(alert_rules.router)
    return router


router = stub_router("policy", build_router())
