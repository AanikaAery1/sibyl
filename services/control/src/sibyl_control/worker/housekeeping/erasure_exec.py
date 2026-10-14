"""``erasure_exec`` loop (lane U): drive approved erasure requests to ``completed``.

DATAMODEL §6.5 steps 3-8, one step per transaction (each re-reads and locks the request, so a
crash resumes where it stopped and two workers never run the same request):

``approved → executing``           tenant scope: ``tenant.status = erasing`` (ingest 429s)
``executing → keys_shredded``      tenant scope only: ``sibyl.tenant_key_shred``, ``erasure``
                                   anchor, ``erasure.keys_shredded``
``→ objects_deleted``              BlobStore objects of the scope first, then
                                   ``erasure_execute_phase(objects_deleted)``; tenant scope
                                   waits ``DEK_CACHE_TTL`` after the shred (risk T6)
``objects_deleted → derived_purged`` ``erasure_execute_phase(derived_purged)`` (not subject)
``→ verified``                     ``sibyl.erasure_residue`` must be empty, no object left
                                   under the scope, every payload key shredded (tenant scope)
``verified → completed``           signed ledger entry first (``migrate/ledger.py``, ledger key
                                   file), then the ``erasure`` anchor, the certificate,
                                   ``erasure.completed`` (critical) and, for tenant scope,
                                   ``tenant.status = erased`` with its non-key columns nulled.

Every step appends to ``execution_log`` and emits ``outbox(erasure.step)`` (tenant scope: not
after the derived purge, whose cascade empties the tenant's outbox). A step that fails
(an active hold, residue, a chain blocker) records ``error`` on the request and is retried on
later ticks; nothing is skipped. Holds are re-checked by the database in every phase.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sibyl_schemas.audit_chain import rfc3339

from ...core.audit import AuditRecord, PgAuditWriter
from ...core.outbox import OutboxMessage, PgOutboxWriter
from ...migrate import ledger as ledger_mod
from ..loops import LoopContext
from . import certificate, ledger_store
from .anchoring import write_anchor
from .common import (
    SignerUnavailable,
    active_anchor_key,
    blob_store,
    dek_provider,
    resolve_signer,
    tenants,
)

LOOP = "erasure_exec"
DEK_CACHE_TTL = timedelta(seconds=60)
MAX_STEPS_PER_TICK = 12
ACTIVE_STATES = (
    "approved",
    "executing",
    "keys_shredded",
    "objects_deleted",
    "derived_purged",
    "verified",
)
POST_PURGE = frozenset({"derived_purged", "verified", "completed"})
_CLAIM_SQL = (
    "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1 AND state = ANY($2::text[])"
    " ORDER BY (error IS NOT NULL), created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED"
)


class StepBlocked(Exception):
    """The step cannot run yet (DEK cache window); not an error."""


@dataclass
class Runtime:
    ctx: LoopContext

    @property
    def db(self) -> Any:
        return self.ctx.db

    def blob(self) -> Any:
        return blob_store(self.ctx.settings)


def _log_step(step: str, **extra: Any) -> list[dict[str, Any]]:
    return [{"step": step, **extra}]


async def _set_state(
    conn: Any, row: Mapping[str, Any], state: str, log: list[dict[str, Any]], **cols: Any
) -> None:
    sets = ["state = $3", "execution_log = execution_log || $4::jsonb", "error = NULL"]
    args: list[Any] = [row["tenant_id"], row["id"], state, log]
    for name, value in cols.items():
        args.append(value)
        sets.append(f"{name} = ${len(args)}")
    await conn.execute(
        f"UPDATE sibyl.erasure_request SET {', '.join(sets)}"  # noqa: S608 (fixed column names)
        " WHERE tenant_id = $1 AND id = $2",
        *args,
    )
    if row["scope_kind"] == "tenant" and state in POST_PURGE:
        return  # the tenant's outbox was purged; a new row would be residue
    message = OutboxMessage.for_event(
        "erasure.step",
        "erasure",
        row["id"],
        {"tenant_id": str(row["tenant_id"]), "request_id": str(row["id"]), "state": state},
    )
    await PgOutboxWriter().emit(conn, row["tenant_id"], message)


async def _audit(conn: Any, row: Mapping[str, Any], action: str, detail: dict[str, Any]) -> None:
    await PgAuditWriter().append(
        conn,
        row["tenant_id"],
        AuditRecord(
            action=action,
            actor_type="system",
            resource_type="erasure_request",
            resource_id=row["id"],
            detail={"request_id": str(row["id"]), **detail},
        ),
    )


def _counts(row: Mapping[str, Any]) -> dict[str, Any]:
    return dict((row["affected_objects"] or {}).get("counts") or {})


async def _save_counts(conn: Any, row: Mapping[str, Any], phase: str, counts: Any) -> None:
    await conn.execute(
        "UPDATE sibyl.erasure_request SET affected_objects = coalesce(affected_objects, '{}')"
        " || jsonb_build_object('counts', coalesce(affected_objects->'counts', '{}')"
        " || jsonb_build_object($3::text, $4::jsonb)) WHERE tenant_id = $1 AND id = $2",
        row["tenant_id"],
        row["id"],
        phase,
        counts,
    )


def _ts(text: Any) -> datetime | None:
    return None if text is None else datetime.fromisoformat(str(text).replace("Z", "+00:00"))


def _agents(row: Mapping[str, Any]) -> list[UUID]:
    if row["scope_kind"] == "agent":
        return [UUID(row["scope_ref"])]
    subject = (row["affected_objects"] or {}).get("subject_set") or {}
    return [UUID(a) for a in subject.get("agent_ids", [])]


async def _signer(conn: Any, rt: Runtime) -> Any:
    key = await active_anchor_key(conn)
    if key is None:
        raise SignerUnavailable("no active audit_anchor signing key is published")
    return resolve_signer(key, rt.ctx.settings)


# --- steps ----------------------------------------------------------------------------------


async def _start(conn: Any, row: Mapping[str, Any], rt: Runtime) -> None:
    if row["scope_kind"] == "tenant":
        await conn.execute(
            "UPDATE sibyl.tenant SET status = 'erasing' WHERE id = $1 AND status <> 'erased'",
            row["tenant_id"],
        )
        deks = dek_provider(rt.db, rt.ctx.settings)
        deks.invalidate(row["tenant_id"])
    await _set_state(conn, row, "executing", _log_step("executing", at=await _now(conn)))


async def _shred(conn: Any, row: Mapping[str, Any], rt: Runtime) -> None:
    shredded = int(await conn.fetchval("SELECT sibyl.tenant_key_shred($1)", row["id"]))
    dek_provider(rt.db, rt.ctx.settings).invalidate(row["tenant_id"])
    anchor = await write_anchor(
        conn, row["tenant_id"], await _signer(conn, rt), kind="erasure", publish=rt.blob()
    )
    await _save_counts(conn, row, "keys_shredded", {"tenant_key": shredded})
    await _audit(
        conn,
        row,
        "erasure.keys_shredded",
        {"counts": {"tenant_key": shredded}, "anchor_id": str(anchor.row["id"])},
    )
    await _set_state(
        conn, row, "keys_shredded", _log_step("keys_shredded", at=await _now(conn), keys=shredded)
    )


async def _object_keys(conn: Any, row: Mapping[str, Any], rt: Runtime) -> list[str]:
    tenant = row["tenant_id"]
    if row["scope_kind"] == "tenant":
        return sorted(await rt.blob().list_prefix(f"tenant/{tenant}/", limit=10_000_000))
    if row["scope_kind"] == "agent":
        rows = await conn.fetch(
            "SELECT uri FROM sibyl.payload_refs WHERE tenant_id = $1 AND agent_id = $2",
            tenant,
            UUID(row["scope_ref"]),
        )
    else:
        subject = (row["affected_objects"] or {}).get("subject_set") or {}
        rows = await conn.fetch(
            "SELECT uri FROM sibyl.payload_refs WHERE tenant_id = $1 AND agent_id = ANY($2::uuid[])"
            " AND created_at >= $3::timestamptz AND ($4::timestamptz IS NULL OR created_at < $4)",
            tenant,
            _agents(row),
            _ts(subject.get("window_from")),
            _ts(subject.get("window_to")),
        )
    return sorted({r["uri"] for r in rows})


async def _objects(conn: Any, row: Mapping[str, Any], rt: Runtime) -> None:
    if row["scope_kind"] == "tenant":
        shredded_at = await conn.fetchval(
            "SELECT max(shredded_at) FROM sibyl.tenant_key WHERE tenant_id = $1"
            " AND erasure_request_id = $2",
            row["tenant_id"],
            row["id"],
        )
        ready = await conn.fetchval(
            "SELECT $1::timestamptz IS NULL OR $1::timestamptz <= now() - $2::interval",
            shredded_at,
            DEK_CACHE_TTL,
        )
        if not ready:
            raise StepBlocked("waiting for cached DEKs to expire after the shred")
    store = rt.blob()
    keys = await _object_keys(conn, row, rt)
    removed = 0
    for key in keys:
        removed += 1 if await store.delete(key) else 0
    counts = dict(
        await conn.fetchval("SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')", row["id"])
    )
    counts["blob_objects"] = removed
    await _save_counts(conn, row, "objects_deleted", counts)
    await _audit(conn, row, "erasure.objects_deleted", {"counts": counts})
    await _set_state(
        conn, row, "objects_deleted", _log_step("objects_deleted", at=await _now(conn))
    )


async def _derived(conn: Any, row: Mapping[str, Any], rt: Runtime) -> None:
    counts = dict(
        await conn.fetchval("SELECT sibyl.erasure_execute_phase($1, 'derived_purged')", row["id"])
    )
    await _save_counts(conn, row, "derived_purged", counts)
    await _audit(conn, row, "erasure.derived_purged", {"counts": counts})
    await _set_state(conn, row, "derived_purged", _log_step("derived_purged", at=await _now(conn)))


async def residue(conn: Any, row: Mapping[str, Any], rt: Runtime) -> dict[str, int]:
    """What would stop ``verified``: residue rows, leftover objects, unshredded payload keys."""
    left = {
        r["table_name"]: int(r["remaining"])
        for r in await conn.fetch("SELECT * FROM sibyl.erasure_residue($1)", row["id"])
    }
    objects = await _object_keys(conn, row, rt)
    if row["scope_kind"] == "tenant" and objects:
        left["blob_objects"] = len(objects)
    if row["scope_kind"] == "tenant":
        live = await conn.fetchval(
            "SELECT count(*) FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'payload'"
            " AND state <> 'shredded'",
            row["tenant_id"],
        )
        if int(live):
            left["tenant_key.payload"] = int(live)
    return left


async def _verify(conn: Any, row: Mapping[str, Any], rt: Runtime) -> None:
    left = await residue(conn, row, rt)
    if left:
        raise ResidueFound(left)
    await _set_state(conn, row, "verified", _log_step("verified", at=await _now(conn), residue={}))


class ResidueFound(RuntimeError):
    def __init__(self, left: dict[str, int]) -> None:
        super().__init__(
            "erasure residue: " + ", ".join(f"{k}={v}" for k, v in sorted(left.items()))
        )
        self.left = left


async def _complete(conn: Any, row: Mapping[str, Any], rt: Runtime) -> None:
    tenant = row["tenant_id"]
    keys = [
        dict(k)
        for k in await conn.fetch(
            "SELECT id, purpose, version FROM sibyl.tenant_key WHERE tenant_id = $1"
            " AND erasure_request_id = $2 ORDER BY purpose, version",
            tenant,
            row["id"],
        )
    ]
    subject = (row["affected_objects"] or {}).get("subject_set")
    signing_key = ledger_store.signing_key_from_settings(rt.ctx.settings)
    completed_now = rfc3339(await conn.fetchval("SELECT now()"))
    entry = await ledger_store.append(
        rt.blob(),
        signing_key,
        tenant_id=str(tenant),
        erasure_request_id=str(row["id"]),
        scope_kind=row["scope_kind"],
        scope_ref=row["scope_ref"],
        key_ids=[str(k["id"]) for k in keys],
        completed_at=completed_now or "",
        subject_set=dict(subject) if row["scope_kind"] == "subject" and subject else None,
    )
    completed_at = str(entry["completed_at"])
    completed_dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    days = int(
        await conn.fetchval("SELECT backup_retention_days FROM sibyl.tenant WHERE id = $1", tenant)
    )
    expires = completed_dt + timedelta(days=days)
    anchor = await write_anchor(
        conn, tenant, await _signer(conn, rt), kind="erasure", publish=rt.blob()
    )
    retained = [
        r["table_name"]
        for r in await conn.fetch(
            "SELECT table_name FROM sibyl.erasure_cascade() WHERE action = 'keep' ORDER BY ord"
        )
    ] + ["tenant"]
    log = list(row["execution_log"] or [])
    requested_at = next((e.get("at") for e in log if e.get("step") == "requested"), None)
    cert = certificate.build(
        request=row,
        tenant_id=tenant,
        counts=_counts(row),
        shredded_keys=keys,
        anchor=anchor.row,
        ledger_entry=entry,
        ledger_entry_hash=ledger_mod.entry_hash(entry),
        completed_at=completed_at,
        backups_expire_at=rfc3339(expires) or "",
        backup_retention_days=days,
        retained_tables=retained,
        requested_at=requested_at if isinstance(requested_at, str) else None,
        approved_at=rfc3339(row["approved_at"]),
    )
    digest = certificate.digest(cert)
    await _audit(
        conn,
        row,
        "erasure.completed",
        {
            "certificate_sha256": digest.hex(),
            "anchor_id": str(anchor.row["id"]),
            "backups_expire_at": cert["backups_expire_at"],
            "ledger_seq": int(entry["seq"]),
        },
    )
    await _set_state(
        conn,
        row,
        "completed",
        _log_step(
            "completed",
            at=completed_at,
            certificate=cert,
            ledger={"seq": int(entry["seq"]), "entry_hash": ledger_mod.entry_hash(entry)},
        ),
        completed_at=completed_dt,
        backups_expire_at=expires,
        completion_anchor_id=anchor.row["id"],
        certificate_sha256=digest,
    )
    if row["scope_kind"] == "tenant":
        await conn.execute(
            "UPDATE sibyl.tenant SET status = 'erased', name = NULL, region_declared = NULL,"
            " unknown_agent_fail_mode = NULL, parent_tenant_id = NULL WHERE id = $1",
            tenant,
        )


async def _now(conn: Any) -> str:
    return rfc3339(await conn.fetchval("SELECT now()")) or ""


STEPS = {
    "approved": _start,
    "executing": None,  # tenant → _shred, else → _objects
    "keys_shredded": _objects,
    "objects_deleted": None,  # subject → _verify, else → _derived
    "derived_purged": _verify,
    "verified": _complete,
}


def step_for(row: Mapping[str, Any]) -> Any:
    state = row["state"]
    if state == "executing":
        return _shred if row["scope_kind"] == "tenant" else _objects
    if state == "objects_deleted":
        return _verify if row["scope_kind"] == "subject" else _derived
    return STEPS[state]


async def _record_error(rt: Runtime, tenant: UUID, request_id: UUID, error: str) -> None:
    async with rt.db.tenant_tx(tenant) as conn:
        await conn.execute(
            "UPDATE sibyl.erasure_request SET error = $3 WHERE tenant_id = $1 AND id = $2",
            tenant,
            request_id,
            error[:2000],
        )


async def advance(rt: Runtime, tenant: UUID) -> str | None:
    """Run one step of the oldest active request of ``tenant``; → the new state or None."""
    request_id: UUID | None = None
    try:
        async with rt.db.tenant_tx(tenant) as conn:
            await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
            row = await conn.fetchrow(_CLAIM_SQL, tenant, list(ACTIVE_STATES))
            if row is None:
                return None
            request_id = row["id"]
            await step_for(row)(conn, dict(row), rt)
            return str(
                await conn.fetchval(
                    "SELECT state FROM sibyl.erasure_request WHERE tenant_id = $1 AND id = $2",
                    tenant,
                    request_id,
                )
            )
    except StepBlocked:
        return None
    except SignerUnavailable:
        raise
    except Exception as exc:
        if request_id is None:
            raise
        rt.ctx.log.warning("erasure %s blocked: %s", request_id, exc)
        await _record_error(rt, tenant, request_id, _describe(exc))
        return None


def _describe(exc: Exception) -> str:
    message = str(getattr(exc, "message", "") or exc)
    if message.startswith("sibyl:"):
        return message.split(":", 2)[1].strip() + ": " + message.split(":", 2)[-1].strip()
    return f"{type(exc).__name__}: {message}"


async def tick(ctx: LoopContext) -> None:
    rt = Runtime(ctx)
    for tenant in await tenants(ctx.db):
        for _ in range(MAX_STEPS_PER_TICK):
            state = await advance(rt, tenant)
            if state is None or state == "completed":
                break
