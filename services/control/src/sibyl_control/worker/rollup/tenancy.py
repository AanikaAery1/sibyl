"""Tenant iteration and per-tenant locking shared by the lane H loops.

The tenant list is the one allowlisted cross-tenant read (``sibyl.tenant`` is not RLS-scoped);
everything else runs inside ``Database.tenant_tx``. Two workers never run the same loop for the
same tenant: each unit takes ``pg_try_advisory_xact_lock`` and skips the tenant when it is held.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

ACTIVE_TENANTS_SQL = "SELECT id FROM sibyl.tenant WHERE status = 'active' ORDER BY id"
TRY_LOCK_SQL = "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))"


async def active_tenants(db: Any) -> list[UUID]:
    async with db.pre_tenant() as conn:
        rows = await conn.fetch(ACTIVE_TENANTS_SQL)
    return [row["id"] for row in rows]


async def try_lock(conn: Any, loop: str, tenant_id: UUID) -> bool:
    return bool(await conn.fetchval(TRY_LOCK_SQL, f"{loop}:{tenant_id}"))
