"""sentinel API module (lane SENTINEL, D52): Sibyl Sentinel's configuration, findings,
feedback and on-demand explanations. Advisory only: no route here reaches an enforcement
table or route."""

from __future__ import annotations

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from .config_routes import router as _config
from .findings_routes import router as _findings

_routes = APIRouter()
_routes.include_router(_config)
_routes.include_router(_findings)

router = stub_router("sentinel", _routes)
