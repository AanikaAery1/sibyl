# ruff: noqa: S608 -- SQL is built once at import from the constant HELD fragment
"""``retention`` loop (lane U; DATAMODEL §6.6 steps 2-3).

Hourly, per tenant (own transaction, ``(retention, tenant)`` advisory lock):

1. **Expire holds** whose ``expires_at`` passed (``state = expired``). An erasure blocked by
   such a hold is not reopened here: its approval re-checks the holds (§10.4 rule 2).
2. **Sweep payload objects** whose ``expires_at`` passed, oldest first, ``BATCH`` per tick,
   **except** objects under an active legal hold (the hold predicate below: tenant holds, the
   hold's materialised ``agent_ids`` or its agent ``scope_ref``, within the hold window). The
   blob is deleted, then the row becomes ``swept`` (the payload route answers 404
   ``payload_swept``). One ``retention.objects_swept`` row per date prefix records objects,
   bytes and how many expired objects holds kept.

Then, cluster-wide, **partitions past their class retention** are dropped through
``sibyl.partition_retire_expired(now)`` and one ``retention.partition_dropped`` row is appended
per tenant that had rows in a dropped partition. The worker role cannot drop tables itself:
CHANGE REQUEST (INT-1) adds that SECURITY DEFINER function (proposed SQL in
``tests/worker/housekeeping/cr_sql/partition_retire_expired.sql``); until it exists the step is
skipped with a warning. ``audit_events`` partitions are never dropped here (export +
``partition_boundary`` anchor first, Phase 1.5).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord, PgAuditWriter
from ...core.blob.base import BlobStore
from ..loops import LoopContext
from .common import blob_store, tenants, try_lock

LOOP = "retention"
BATCH = 1_000
RETIRE_FN = "sibyl.partition_retire_expired(timestamptz)"
HELD = """EXISTS (SELECT 1 FROM sibyl.legal_hold h WHERE h.tenant_id = p.tenant_id
  AND h.state = 'active' AND (h.expires_at IS NULL OR h.expires_at > now())
  AND p.created_at >= h.window_from AND (h.window_to IS NULL OR p.created_at <= h.window_to)
  AND (h.scope_kind = 'tenant' OR p.agent_id = ANY (h.agent_ids)
       OR (h.scope_kind = 'agent' AND h.scope_ref = p.agent_id::text)))"""
_DUE_SQL = (
    "SELECT p.id, p.uri, p.size_bytes, p.created_at FROM sibyl.payload_refs p"
    " WHERE p.tenant_id = $1 AND p.state = 'stored' AND p.expires_at < now()"
    f" AND NOT {HELD} ORDER BY p.expires_at LIMIT $2 FOR UPDATE SKIP LOCKED"
)
_HELD_SQL = (
    "SELECT (p.created_at AT TIME ZONE 'UTC')::date AS day, count(*) AS n FROM sibyl.payload_refs p"
    " WHERE p.tenant_id = $1 AND p.state = 'stored' AND p.expires_at < now()"
    f" AND {HELD} GROUP BY 1"
)


@dataclass(frozen=True)
class SweepReport:
    swept: int
    bytes: int
    held: int


async def expire_holds(conn: Any, tenant: UUID) -> int:
    status = await conn.execute(
        "UPDATE sibyl.legal_hold SET state = 'expired' WHERE tenant_id = $1 AND state = 'active'"
        " AND expires_at IS NOT NULL AND expires_at <= now()",
        tenant,
    )
    return int(str(status).rsplit(" ", 1)[-1] or 0)


async def sweep(conn: Any, tenant: UUID, store: BlobStore) -> SweepReport:
    """Inside a transaction that already holds ``sibyl.audit_lock`` (taken before any row lock)."""
    rows = await conn.fetch(_DUE_SQL, tenant, BATCH)
    held = {r["day"]: int(r["n"]) for r in await conn.fetch(_HELD_SQL, tenant)}
    per_day: dict[Any, list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        await store.delete(row["uri"])
        await conn.execute(
            "UPDATE sibyl.payload_refs SET state = 'swept', swept_at = now()"
            " WHERE tenant_id = $1 AND id = $2 AND created_at = $3",
            tenant,
            row["id"],
            row["created_at"],
        )
        bucket = per_day[row["created_at"].date()]
        bucket[0] += 1
        bucket[1] += int(row["size_bytes"])
    for day in sorted(set(per_day) | set(held)):
        objects, size = per_day.get(day, [0, 0])
        if not objects:
            continue  # held-only days are reported when something of that day is swept
        await PgAuditWriter().append(
            conn,
            tenant,
            AuditRecord(
                action="retention.objects_swept",
                actor_type="system",
                resource_type="tenant",
                resource_id=tenant,
                detail={
                    "date_prefix": day.isoformat(),
                    "objects": objects,
                    "bytes": size,
                    "holds_skipped": held.get(day, 0),
                },
            ),
        )
    return SweepReport(
        sum(v[0] for v in per_day.values()), sum(v[1] for v in per_day.values()), sum(held.values())
    )


async def drop_partitions(ctx: LoopContext) -> int:
    """Retire partitions past retention; → partitions dropped (0 when unsupported)."""
    async with ctx.db.system_tx() as conn:
        if not await conn.fetchval("SELECT to_regprocedure($1) IS NOT NULL", RETIRE_FN):
            ctx.log.warning("retention: %s is missing; partition drops skipped", RETIRE_FN)
            return 0
        rows = await conn.fetch(
            "SELECT table_name, partition_name, tenant_id, rows"
            " FROM sibyl.partition_retire_expired(now())"
        )
    by_tenant: dict[UUID, list[Any]] = defaultdict(list)
    partitions = set()
    for row in rows:
        partitions.add((row["table_name"], row["partition_name"]))
        if row["tenant_id"] is not None:
            by_tenant[row["tenant_id"]].append(row)
    for tenant, dropped in by_tenant.items():
        async with ctx.db.tenant_tx(tenant) as conn:
            for row in dropped:
                await PgAuditWriter().append(
                    conn,
                    tenant,
                    AuditRecord(
                        action="retention.partition_dropped",
                        actor_type="system",
                        resource_type="partition",
                        resource_ref=f"{row['table_name']}/{row['partition_name']}",
                        detail={
                            "table": row["table_name"],
                            "partition": row["partition_name"],
                            "rows": int(row["rows"]),
                            "anchor_id": None,
                        },
                    ),
                )
    return len(partitions)


async def tick(ctx: LoopContext) -> None:
    store = blob_store(ctx.settings)
    for tenant in await tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    continue
                await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
                await expire_holds(conn, tenant)
                report = await sweep(conn, tenant, store)
            if report.swept:
                ctx.log.info("retention: tenant %s swept %d object(s)", tenant, report.swept)
        except Exception:
            ctx.log.exception("retention: tenant %s failed", tenant)
    dropped = await drop_partitions(ctx)
    if dropped:
        ctx.log.info("retention: dropped %d partition(s)", dropped)
