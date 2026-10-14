"""reads API module (lane V): routing state and transitions, fleet and agent health, risk,
metrics, checkpoints, events, traces and payloads (API.md §5.7, §5.10).

``GET /jobs/{job_id}`` (B14) lives in ``jobs.py``, owned by the integration lane.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .._stubs import stub_router
from ..auth.common import record_denials
from . import agents, events, fleet, jobs, payloads, runs

router = APIRouter(dependencies=[Depends(record_denials)])
router.include_router(fleet.router)
router.include_router(agents.router)
router.include_router(events.router)
router.include_router(runs.router)
router.include_router(payloads.router)
router.include_router(jobs.router)
stub_router("reads", router)
