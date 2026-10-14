"""drift API module (lane DRIFT, D51): the fleet drift view, one agent's baselines and
reports, one report, the audited baseline reset and (wave 4 HARDEN) the tenant's drift
thresholds. Watch-only: nothing here changes routing."""

from __future__ import annotations

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from .routes import router as _reads_and_reset
from .thresholds import router as _thresholds

_routes = APIRouter()
_routes.include_router(_reads_and_reset)
_routes.include_router(_thresholds)

router = stub_router("drift", _routes)
