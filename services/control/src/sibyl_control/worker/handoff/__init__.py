"""Handoff loop (lane S, 30 s): SDK packets become tasks; queued tasks past their deadline
expire; lapsed claims return to the queue (``tasks``). Packets are assembled by ``packet``."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..loops import LoopContext

LOOP = "handoff"


async def tick(ctx: LoopContext) -> None:
    from ...core.audit import PgAuditWriter
    from ...core.outbox import PgOutboxWriter
    from ..rollup.tenancy import active_tenants
    from .tasks import build_sdk_tasks, expire, lapse_claims

    audit, outbox = PgAuditWriter(), PgOutboxWriter()
    for tenant in await active_tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
                await build_sdk_tasks(conn, tenant, audit=audit, outbox=outbox)
                await expire(conn, tenant, audit=audit, outbox=outbox)
                await lapse_claims(conn, tenant, audit=audit)
        except Exception:
            ctx.log.exception("handoff loop failed for tenant %s", tenant)


__all__ = ["tick"]
