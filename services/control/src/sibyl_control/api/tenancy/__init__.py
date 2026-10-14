"""tenancy API module (lane A): tenant settings, tenant keys, users, sessions, memberships,
OIDC issuers and agent groups (API.md §5.1-§5.2)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .._stubs import stub_router
from ..auth.common import record_denials
from . import issuers, people, tenant

router = APIRouter(dependencies=[Depends(record_denials)])
router.include_router(tenant.router)
router.include_router(people.router)
router.include_router(issuers.router)
stub_router("tenancy", router)
