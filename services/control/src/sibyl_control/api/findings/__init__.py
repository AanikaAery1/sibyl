"""findings API module (lane EXTMON, D53): advisory findings from Sentinel and external
monitors, read together; monitor keys submit, humans rate. No route here reaches an
enforcement table or route."""

from __future__ import annotations

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from .routes import router as _reads
from .routes import submit_router as _submit

_routes = APIRouter()
_routes.include_router(_submit)
_routes.include_router(_reads)

router = stub_router("findings", _routes)
