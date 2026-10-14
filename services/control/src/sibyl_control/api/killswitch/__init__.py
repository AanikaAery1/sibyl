"""killswitch API module (lane S): list, pull (session or break-glass), release, gateway acks.

Handlers live in ``routes``; ``stub_router("killswitch", ...)`` runs last so any contract
operation without a handler stays mounted as a 501.
"""

from sibyl_control.api._stubs import stub_router

from .routes import router as _routes

router = stub_router("killswitch", _routes)
