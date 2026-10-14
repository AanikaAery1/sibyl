"""``erasure_ledger`` loop (lane U, R63): keep the off-database erasure ledger whole.

Every minute:

1. **Back-fill.** A ``completed`` request (origin ``api``) that the ledger does not name gets
   its signed entry now (``erasure_exec`` writes it before completing, so this only repairs a
   lost or restored BlobStore). Requests completed by a restore re-application came *from* the
   ledger and are skipped.
2. **Materialise.** The create-only entry objects are verified (signatures, chain) and
   ``ledger.jsonl`` plus the signed ``head.json`` are rewritten, so the restore runbook and
   the backup manifest always read a verified ledger and its current head.

The ledger key comes from ``SIBYL_LEDGER_SIGNING_KEY_FILE`` and never enters Postgres. A ledger
that fails verification fails the tick loudly (``/healthz``); it is never rewritten over.
"""

from __future__ import annotations

from typing import Any

from sibyl_schemas.audit_chain import rfc3339

from ..loops import LoopContext
from . import ledger_store
from .common import blob_store, tenants

LOOP = "erasure_ledger"
_COMPLETED_SQL = (
    "SELECT r.*, (SELECT coalesce(array_agg(k.id::text ORDER BY k.purpose, k.version), '{}')"
    " FROM sibyl.tenant_key k WHERE k.tenant_id = r.tenant_id AND k.erasure_request_id = r.id)"
    " AS key_ids FROM sibyl.erasure_request r WHERE r.tenant_id = $1 AND r.state = 'completed'"
    " AND r.origin = 'api' ORDER BY r.completed_at, r.id"
)


async def backfill(ctx: LoopContext, store: Any, signing_key: Any) -> int:
    entries = await ledger_store.load(store)
    known = {str(e["erasure_request_id"]) for e in entries}
    added = 0
    for tenant in await tenants(ctx.db, include_erased=True):
        async with ctx.db.tenant_tx(tenant, readonly=True) as conn:
            rows = await conn.fetch(_COMPLETED_SQL, tenant)
        for row in rows:
            if str(row["id"]) in known:
                continue
            subject = (row["affected_objects"] or {}).get("subject_set")
            await ledger_store.append(
                store,
                signing_key,
                tenant_id=str(tenant),
                erasure_request_id=str(row["id"]),
                scope_kind=row["scope_kind"],
                scope_ref=row["scope_ref"],
                key_ids=list(row["key_ids"]),
                completed_at=rfc3339(row["completed_at"]) or "",
                subject_set=dict(subject) if row["scope_kind"] == "subject" and subject else None,
            )
            known.add(str(row["id"]))
            added += 1
            ctx.log.warning("erasure ledger: back-filled request %s", row["id"])
    return added


async def tick(ctx: LoopContext) -> None:
    signing_key = ledger_store.signing_key_from_settings(ctx.settings)
    store = blob_store(ctx.settings)
    await backfill(ctx, store, signing_key)
    async with ctx.db.pre_tenant() as conn:
        now = rfc3339(await conn.fetchval("SELECT now()")) or ""
    count, head = await ledger_store.materialise(store, signing_key, at=now)
    ctx.log.debug("erasure ledger: %d entries, head %s", count, head)
