"""action_gate API module (lane AG-CORE, D48): action policies, held actions and the
authoritative cumulative decision. See ``docs/council/build/ACTION-GATE.md`` §3."""

from __future__ import annotations

from fastapi import APIRouter

from sibyl_control.api._stubs import stub_router

from .decisions import router as _decisions
from .holds import router as _holds
from .policies import router as _policies
from .simulate import router as _simulate
from .summary import router as _summary

_routes = APIRouter()
_routes.include_router(_policies)
_routes.include_router(_simulate)
_routes.include_router(_holds)
_routes.include_router(_decisions)
_routes.include_router(_summary)

router = stub_router("action_gate", _routes)
