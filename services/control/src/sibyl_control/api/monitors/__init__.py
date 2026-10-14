"""monitors API module (lane EXTMON, D53): external monitor agents, their monitor-bound keys
and signed webhooks. Advisory only: no route here reaches an enforcement table or route."""

from __future__ import annotations

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from .routes import router as _monitors
from .webhooks import router as _webhooks

_routes = APIRouter()
_routes.include_router(_monitors)
_routes.include_router(_webhooks)

router = stub_router("monitors", _routes)
