"""Monitor webhooks loop (lane EXTMON, D53, 5 s; woken by the outbox channel).

Per tenant, under one advisory lock:

1. raise the watch-only ``external_finding`` alerts external findings asked for (``alerts``);
2. turn new outbox rows (alerts, incidents, held actions, drift) and failed runs into deliveries
   for the enabled webhooks of active monitors that watch the agents concerned (``enqueue``);
3. purge deliveries settled more than 14 days ago;
4. send due deliveries, signed, over the guarded network path, with retries, backoff and
   dead-lettering (``dispatch``; needs the key-encryption key to open the signing secrets).

Advisory only: nothing here can allow, block, approve, fail over or change policy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from ...core.audit import AuditWriter, PgAuditWriter
from ...core.outbox import OutboxWriter, PgOutboxWriter

if TYPE_CHECKING:
    from ..loops import LoopContext
    from .deliver import TransportFactory

LOOP: Final = "webhooks"
RETENTION_DAYS: Final = 14
PURGE_BATCH: Final = 1000
SEND_CONCURRENCY: Final = 5
_PURGE_SQL = """
DELETE FROM sibyl.webhook_delivery
 WHERE tenant_id = $1 AND id IN (
   SELECT id FROM sibyl.webhook_delivery
    WHERE tenant_id = $1 AND settled_at < now() - make_interval(days => $2)
    LIMIT $3)
"""


@dataclass
class Deps:
    settings: Any
    kek: Any = None  # KeyEncryptionKey | None: without it deliveries wait
    audit: AuditWriter = field(default_factory=PgAuditWriter)
    outbox: OutboxWriter = field(default_factory=PgOutboxWriter)
    transport_factory: TransportFactory | None = None
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))


@dataclass
class TenantReport:
    alerts: int = 0
    enqueued: int = 0
    purged: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)


async def prepare_tenant(conn: Any, deps: Deps, tenant: UUID, report: TenantReport) -> None:
    from .alerts import raise_due
    from .enqueue import load_targets, scan_outbox, scan_runs

    report.alerts = await raise_due(conn, deps.outbox, tenant)
    targets = await load_targets(conn, tenant)
    if targets:
        report.enqueued += await scan_outbox(conn, tenant, targets)
        report.enqueued += await scan_runs(conn, tenant, targets, deps.clock())
    status = await conn.execute(_PURGE_SQL, tenant, RETENTION_DAYS, PURGE_BATCH)
    report.purged = int(str(status).rsplit(" ", 1)[-1] or 0)


async def dispatch_tenant(db: Any, deps: Deps, tenant: UUID, report: TenantReport) -> None:
    from .dispatch import DispatchDeps, Prepared, claim, deliver_one, prepare, record

    dd = DispatchDeps(deps.kek, deps.audit, deps.settings, deps.transport_factory)
    async with db.tenant_tx(tenant) as conn:
        claimed = await claim(conn, tenant)
        batch = [await prepare(conn, dd, tenant, item) for item in claimed]
    gate = asyncio.Semaphore(SEND_CONCURRENCY)

    async def one(item: Prepared) -> None:
        result = None
        if item.skip is None:
            async with gate:
                result = await deliver_one(dd, item)
        async with db.tenant_tx(tenant) as conn:
            await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
            outcome = await record(conn, dd, tenant, item.claimed, result, item.skip)
        report.outcomes[outcome] = report.outcomes.get(outcome, 0) + 1

    await asyncio.gather(*(one(item) for item in batch))


async def run_tenant(db: Any, deps: Deps, tenant: UUID) -> TenantReport:
    from ..rollup.tenancy import try_lock

    report = TenantReport()
    async with db.tenant_tx(tenant) as conn:
        if not await try_lock(conn, LOOP, tenant):
            return report
        await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
        await prepare_tenant(conn, deps, tenant, report)
    if deps.kek is not None:
        await dispatch_tenant(db, deps, tenant, report)
    return report


async def tick(ctx: LoopContext) -> None:
    from ...core.crypto.deks import kek_from_settings
    from ...core.problems import ProblemError
    from ..rollup.tenancy import active_tenants

    try:
        kek = kek_from_settings(ctx.settings)
    except ProblemError:
        kek = None
        ctx.log.warning("webhooks loop: no key-encryption key configured; deliveries wait")
    deps = Deps(settings=ctx.settings, kek=kek)
    for tenant in await active_tenants(ctx.db):
        try:
            await run_tenant(ctx.db, deps, tenant)
        except Exception:
            ctx.log.exception("webhooks loop failed for tenant %s", tenant)


__all__ = ["Deps", "TenantReport", "run_tenant", "tick"]
