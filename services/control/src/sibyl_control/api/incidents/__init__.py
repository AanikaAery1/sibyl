"""incidents API module (lane S): incident = failover saga row (B1), API.md §5.7 and §6.

Handlers live in ``routes`` (and ``breaker``, B19); operator actions in ``actions``; read
models in ``views``.
``stub_router("incidents", ...)`` runs last so any contract operation without a handler stays
mounted as a 501.
"""

from sibyl_control.api._stubs import stub_router

from .breaker import router as _breaker
from .routes import router as _routes

_routes.include_router(_breaker)
router = stub_router("incidents", _routes)
