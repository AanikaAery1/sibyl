"""``anchors`` loop (lane U): hourly signed anchors plus ``audit.anchor_now`` requests.

Per tenant, each unit in its own transaction under a ``(anchors, tenant)`` advisory lock:

1. **Requests.** ``audit.anchor_now`` outbox rows (topic ``audit``) are read through the
   commit-ordered cursor ``consumer_offsets('housekeeping.anchors', tenant, 'audit')`` (R60).
   ``payload.reason`` selects the work:

   * ``break_glass`` (default; killswitch lane) → an anchor of kind ``break_glass`` at the head;
   * ``export`` / ``verify``: no longer served here. Audit exports and large verifications are
     ``audit_export`` / ``audit_verify`` jobs (B14, ``worker.jobs.audit``); a request of either
     reason still in the outbox from before the switch is skipped (logged), never turned into
     a break-glass anchor.

   Each request runs in its own transaction that also advances the cursor, so a request is done
   exactly once. A request that fails is retried on the next ticks and skipped (cursor advanced,
   logged) after ``MAX_ATTEMPTS``.
2. **Hourly.** An ``hourly`` anchor at the head when the last anchor is older than
   ``HOURLY_EVERY`` and the chain has grown by more than that anchor's own ``audit.anchored`` row.

Every anchor is also published to the BlobStore (``anchors/<tenant>/<id>.json``).
CHANGE REQUEST (INT-1): the loop runner should wake this loop on ``sibyl_outbox`` NOTIFY
(``LoopSpec.channel`` is declared but not yet honoured) so break-glass anchors land within 10 s.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID

from ..loops import LoopContext
from .anchoring import NothingToAnchor, last_anchor, write_anchor
from .common import (
    SignerUnavailable,
    active_anchor_key,
    blob_store,
    resolve_signer,
    tenants,
    try_lock,
)

LOOP = "anchors"
CONSUMER_GROUP = "housekeeping.anchors"
TOPIC = "audit"
EVENT_TYPE = "audit.anchor_now"
HOURLY_EVERY = timedelta(minutes=55)
MAX_ATTEMPTS = 3
BATCH = 50
JOB_REASONS = frozenset({"export", "verify"})  # served by the jobs worker now (B14)
_attempts: Counter[UUID] = Counter()

_CURSOR_SQL = (
    "SELECT last_xid, last_id FROM sibyl.consumer_offsets"
    " WHERE consumer_group = $1 AND tenant_id = $2 AND topic = $3"
)
_SAVE_CURSOR_SQL = (
    "INSERT INTO sibyl.consumer_offsets (consumer_group, tenant_id, topic, last_xid, last_id,"
    " last_created_at) VALUES ($1, $2, $3, $4::xid8, $5, $6)"
    " ON CONFLICT (consumer_group, tenant_id, topic) DO UPDATE SET last_xid = EXCLUDED.last_xid,"
    " last_id = EXCLUDED.last_id, last_created_at = EXCLUDED.last_created_at"
)
_PENDING_SQL = "SELECT * FROM sibyl.outbox_read($1::xid8, $2::uuid, $3, $4::text[])"


@dataclass(frozen=True)
class Runtime:
    ctx: LoopContext

    def signer(self, key: Any) -> Any:
        return resolve_signer(key, self.ctx.settings)

    def blob(self) -> Any:
        try:
            return blob_store(self.ctx.settings)
        except Exception:  # an anchor must not wait for an unavailable off-DB copy
            self.ctx.log.warning("anchors: BlobStore unavailable; anchors are not published")
            return None


async def _signer(conn: Any, rt: Runtime) -> Any:
    key = await active_anchor_key(conn)
    if key is None:
        raise SignerUnavailable("no active audit_anchor signing key is published")
    return rt.signer(key)


async def _cursor(conn: Any, tenant: UUID) -> tuple[Any, UUID]:
    row = await conn.fetchrow(_CURSOR_SQL, CONSUMER_GROUP, tenant, TOPIC)
    if row is None:
        return 0, UUID(int=0)
    return row["last_xid"], row["last_id"]


async def _save_cursor(conn: Any, tenant: UUID, message: Any) -> None:
    await conn.execute(
        _SAVE_CURSOR_SQL,
        CONSUMER_GROUP,
        tenant,
        TOPIC,
        int(message["xid"]),
        message["id"],
        message["created_at"],
    )


async def _pending(db: Any, tenant: UUID) -> list[dict[str, Any]]:
    async with db.tenant_tx(tenant, readonly=True) as conn:
        xid, last_id = await _cursor(conn, tenant)
        rows = await conn.fetch(_PENDING_SQL, int(xid), last_id, BATCH, [TOPIC])
    return [dict(r) for r in rows]


async def handle(conn: Any, tenant: UUID, message: dict[str, Any], rt: Runtime) -> str:
    """Do one ``audit.anchor_now`` request inside ``conn``'s transaction; → what was done."""
    if message["event_type"] != EVENT_TYPE:
        return "ignored"
    payload = dict(message["payload"] or {})
    reason = str(payload.get("reason") or "break_glass")
    if reason in JOB_REASONS:
        return f"ignored: {reason} requests run as jobs"
    signer = await _signer(conn, rt)
    try:
        await write_anchor(conn, tenant, signer, kind="break_glass", publish=rt.blob())
    except NothingToAnchor:
        return "nothing to anchor"
    return "break_glass anchor"


async def _process(rt: Runtime, tenant: UUID) -> None:
    db = rt.ctx.db
    for message in await _pending(db, tenant):
        try:
            async with db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    return
                outcome = await handle(conn, tenant, message, rt)
                await _save_cursor(conn, tenant, message)
            _attempts.pop(message["id"], None)
            rt.ctx.log.info("anchors: tenant %s: %s", tenant, outcome)
        except SignerUnavailable:
            raise
        except Exception:
            _attempts[message["id"]] += 1
            rt.ctx.log.exception("anchors: request %s failed for tenant %s", message["id"], tenant)
            if _attempts[message["id"]] < MAX_ATTEMPTS:
                return
            async with db.tenant_tx(tenant) as conn:
                await _save_cursor(conn, tenant, message)
            _attempts.pop(message["id"], None)
            rt.ctx.log.error(
                "anchors: request %s skipped after %d attempts", message["id"], MAX_ATTEMPTS
            )


async def hourly(conn: Any, tenant: UUID, signer: Any, *, publish: Any = None) -> bool:
    """Write the hourly anchor when it is due and there is something new; → written."""
    head = await conn.fetchrow(
        "SELECT seq FROM sibyl.audit_chain_head WHERE tenant_id = $1", tenant
    )
    if head is None:
        return False
    last = await last_anchor(conn, tenant)
    if last is not None:
        fresh = await conn.fetchval(
            "SELECT $1::timestamptz > clock_timestamp() - $2::interval",
            last["anchored_at"],
            HOURLY_EVERY,
        )
        if fresh or int(head["seq"]) <= int(last["seq_to"]):
            return False
        if int(head["seq"]) == int(last["seq_to"]) + 1:
            newest = await conn.fetchval(
                "SELECT action FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2",
                tenant,
                int(head["seq"]),
            )
            if newest == "audit.anchored":  # only the last anchor's own row is new
                return False
    await write_anchor(conn, tenant, signer, kind="hourly", publish=publish)
    return True


async def tick(ctx: LoopContext) -> None:
    rt = Runtime(ctx)
    for tenant in await tenants(ctx.db, include_erased=True):
        try:
            await _process(rt, tenant)
            async with ctx.db.tenant_tx(tenant) as conn:
                if not await try_lock(conn, LOOP, tenant):
                    continue
                await hourly(conn, tenant, await _signer(conn, rt), publish=rt.blob())
        except SignerUnavailable:
            ctx.log.error("anchors: no usable audit-anchor signing key; no anchors written")
            raise
        except Exception:
            ctx.log.exception("anchors: tenant %s failed", tenant)
