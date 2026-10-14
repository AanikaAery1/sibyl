"""``audit_verify`` / ``audit_export`` job handlers over lane U's housekeeping code (B14, CR U-6).

Large verifications (beyond the synchronous row limit) and audit exports run as jobs. The work
itself is lane U's: ``worker.housekeeping.verification.verify_chain`` and
``worker.housekeeping.exports.run_export``. These adapters import them lazily: until that code
is merged the factories return ``None`` and the runner never claims these kinds (the jobs wait).

Params (written by the governance routes through ``core.jobs.enqueue_job``):

* ``audit_verify``: ``{"from_seq": int, "to_seq": int | null}`` → result = the verification
  body (``ok, rows, anchors_checked, first_break_seq, kind``); audit ``audit.verified`` or
  ``audit.verify_failed`` (actor ``system``).
* ``audit_export``: ``{"export_id", "from_seq", "to_seq", "format"}`` → result
  ``{payload_ref_id, anchor_id, export_sha256, rows}``; audit ``audit.export_completed``
  (ruling G0-12: ``audit.exported`` was written by the api at request time). The export
  anchor is published to the BlobStore (``external_ref`` set) like loop-made anchors (B21).
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord
from .runner import ClaimedJob, JobEnv, JobOutcome

_HK = "sibyl_control.worker.housekeeping"


def _module(name: str) -> ModuleType | None:
    try:
        return importlib.import_module(f"{_HK}.{name}")
    except ModuleNotFoundError as exc:
        if exc.name and f"{_HK}.{name}".startswith(exc.name):
            return None
        raise


def _seq(value: Any) -> int | None:
    return None if value is None else int(value)


class _AuditVerify:
    def __init__(self, env: JobEnv, verification: ModuleType) -> None:
        self.env = env
        self.verification = verification

    def exhausted(self, job: ClaimedJob, last: JobOutcome | None) -> tuple[AuditRecord, ...]:
        return ()

    async def run(self, job: ClaimedJob) -> JobOutcome:
        try:
            from_seq = int(job.params.get("from_seq", 0))
            to_seq = _seq(job.params.get("to_seq"))
        except (TypeError, ValueError):
            return JobOutcome.failed("invalid_params")
        async with self.env.db.tenant_tx(job.tenant_id, readonly=True) as conn:
            result = await self.verification.verify_chain(conn, job.tenant_id, from_seq, to_seq)
        record = AuditRecord(
            action=result.action,
            actor_type="system",
            resource_type="tenant",
            resource_id=job.tenant_id,
            detail={**result.audit_detail(), "job_id": job.id},
        )
        return JobOutcome.done(
            {**result.body(), "from_seq": from_seq, "to_seq": result.last_seq}, record
        )


class _AuditExport:
    def __init__(
        self, env: JobEnv, exports: ModuleType, common: ModuleType, payloads: ModuleType
    ) -> None:
        self.env = env
        self.exports = exports
        self.common = common
        self.payloads = payloads

    def exhausted(self, job: ClaimedJob, last: JobOutcome | None) -> tuple[AuditRecord, ...]:
        return ()

    async def run(self, job: ClaimedJob) -> JobOutcome:
        try:
            request = self.exports.ExportRequest.from_payload(dict(job.params))
        except (KeyError, TypeError, ValueError):
            return JobOutcome.failed("invalid_params")
        settings, db = self.env.settings, self.env.db
        store = self.common.blob_store(settings)
        sealer = self.payloads.PayloadSealer(store, self.common.dek_provider(db, settings))
        async with db.tenant_tx(job.tenant_id) as conn:
            await conn.execute("SELECT sibyl.audit_lock($1)", job.tenant_id)
            key = await self.common.active_anchor_key(conn)
            if key is None:
                return JobOutcome.retry("anchor_key_unavailable")
            try:
                signer = self.common.resolve_signer(key, settings)
            except self.common.SignerUnavailable:
                return JobOutcome.retry("anchor_key_unavailable")
            # B21: the export anchor is published off-database like a loop-made one.
            done = await self.exports.run_export(
                conn, job.tenant_id, request, signer=signer, sealer=sealer, publish=store
            )
        anchor_id: UUID | None = done.anchor_id if done.anchor_id.int else None
        result = {
            "export_id": request.export_id,
            "payload_ref_id": done.payload_ref_id,
            "anchor_id": anchor_id,
            "export_sha256": done.sha256,
            "rows": done.rows,
        }
        record = AuditRecord(
            action="audit.export_completed",
            actor_type="system",
            resource_type="tenant",
            resource_id=job.tenant_id,
            detail={**result, "job_id": job.id},
        )
        return JobOutcome.done(result, record)


def AuditVerify(env: JobEnv) -> _AuditVerify | None:
    verification = _module("verification")
    return None if verification is None else _AuditVerify(env, verification)


def AuditExport(env: JobEnv) -> _AuditExport | None:
    exports, common = _module("exports"), _module("common")
    if exports is None or common is None:
        return None
    payloads = importlib.import_module("sibyl_control.ingest.payloads")
    return _AuditExport(env, exports, common, payloads)
