"""The saga loop (1 s, ``FOR UPDATE SKIP LOCKED``): detect, then drive runnable sagas.

One transaction per step: claim the row (``running``, ``claimed_by``, a 30 s claim lock), run one
step through ``engine.advance``, commit. A worker that dies mid-saga leaves the row ``running``
with a lapsing lock; the next worker resumes at the recorded step. Every transaction takes the
tenant's audit lock first (G0), so row locks are always acquired after it.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import UUID

from . import detect, engine
from .model import CLAIM_LOCK, SAGA_KINDS, Env

if TYPE_CHECKING:
    from ...core.settings import Settings

_RUNNABLE_SQL = """
SELECT id FROM sibyl.failover
 WHERE tenant_id = $1 AND kind = ANY($2::text[]) AND state IN ('pending', 'running')
   AND next_action_at <= now()
   AND (claim_lock_until IS NULL OR claim_lock_until < now() OR claimed_by = $3)
 ORDER BY (priority = 'immediate') DESC, coalesce((step_results #>> '{open,batch,tier}')::int, 9),
          next_action_at, id
 LIMIT $4
"""
_CLAIM_SQL = """
SELECT * FROM sibyl.failover
 WHERE tenant_id = $1 AND id = $2 AND state IN ('pending', 'running') AND next_action_at <= now()
   AND (claim_lock_until IS NULL OR claim_lock_until < now() OR claimed_by = $3)
 FOR UPDATE SKIP LOCKED
"""
log = logging.getLogger("sibyl.saga")
AUDIT_LOCK_SQL = "SELECT sibyl.audit_lock($1)"
TRY_LOCK_SQL = "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))"


def worker_id() -> str:
    return f"saga:{socket.gethostname()}:{os.getpid()}"


def worker_env(settings: Settings, *, wid: str | None = None) -> Env:
    """The worker loops' ``Env``: demo mode and the saga gates come from ``ctx.settings``."""
    return Env(
        worker_id=wid or worker_id(),
        can_build_handoff=True,
        completion_audit=True,
        demo_mode=settings.demo,
        automation_band=settings.predicted_automation_band,
        failback_ramp=settings.failback_ramp,
    )


@dataclass
class TenantRun:
    detected: tuple[UUID, ...] = ()
    progressed: dict[UUID, list[str]] = field(default_factory=dict)


async def run_saga(
    db: Any, env: Env, tenant: UUID, failover_id: UUID, *, max_steps: int = 8
) -> list[engine.Progress]:
    """Drive one saga, one committed step at a time, until it waits, ends or is not ours."""
    out: list[engine.Progress] = []
    for _ in range(max_steps):
        async with db.tenant_tx(tenant) as conn:
            await conn.execute(AUDIT_LOCK_SQL, tenant)
            raw = await conn.fetchrow(_CLAIM_SQL, tenant, failover_id, env.worker_id)
            if raw is None:
                break
            row = dict(raw)
            row = await engine.save(
                conn,
                env,
                tenant,
                row,
                state="running",
                claimed_by=env.worker_id,
                claim_lock_until=await conn.fetchval("SELECT now() + $1::interval", CLAIM_LOCK),
            )
            row, progress = await engine.advance(conn, env, tenant, row)
        out.append(progress)
        if progress.status != "continue":
            break
    return out


async def detect_tenant(db: Any, env: Env, tenant: UUID) -> tuple[UUID, ...]:
    async with db.tenant_tx(tenant) as conn:
        await conn.execute(AUDIT_LOCK_SQL, tenant)
        if not await conn.fetchval(TRY_LOCK_SQL, f"saga-detect:{tenant}"):
            return ()
        return (await detect.detect(conn, env, tenant)).opened


async def runnable(db: Any, env: Env, tenant: UUID, *, limit: int = 50) -> list[UUID]:
    async with db.tenant_tx(tenant, readonly=True) as conn:
        rows = await conn.fetch(_RUNNABLE_SQL, tenant, list(SAGA_KINDS), env.worker_id, limit)
    return [r["id"] for r in rows]


async def run_tenant(db: Any, env: Env, tenant: UUID) -> TenantRun:
    run = TenantRun(detected=await detect_tenant(db, env, tenant))
    for failover_id in await runnable(db, env, tenant):
        try:
            progress = await run_saga(db, env, tenant, failover_id)
        except Exception:
            # One saga whose transaction cannot even commit never starves the others.
            log.exception("saga %s could not be driven", failover_id)
            continue
        run.progressed[failover_id] = [p.status for p in progress]
    return run
