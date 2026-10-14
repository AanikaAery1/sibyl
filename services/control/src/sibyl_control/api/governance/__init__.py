"""governance API module (lane U): audit log, anchors, verification, exports, erasure, holds.

API.md §5.11-§5.12 and §10.4. Handlers use the lane R handler kit (``api/registry/_kit.py``:
tenant transaction with retry, ``audit_lock`` first, fenced idempotency, object rules through
the ``AuthContext``). Anchors, export objects and erasure execution are written by the worker
(``worker/housekeeping``); this module records the human requests and reads their outcome.
``stub_router`` stays last so any operation not implemented here stays mounted as 501.
"""

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from . import audit, erasure, exports, holds

router = APIRouter()
for _module in (audit, exports, erasure, holds):
    router.include_router(_module.router)
router = stub_router("governance", router)
