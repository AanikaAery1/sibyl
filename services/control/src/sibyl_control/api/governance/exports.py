"""Audit exports (API.md §5.11) and the Phase 1.5 data export stub.

``POST /audit/exports`` validates the range against the chain head, appends ``audit.exported``
(the requester, ``resource_ref = audit_export:<id>``, ``export_sha256`` null: ruling G0-12) and
enqueues an ``audit_export`` job (B14; subject ``audit_export:<id>``, params ``export_id``,
``from_seq``, ``to_seq``, ``format``) in the same transaction, answering 202 ``AuditExport``
(``state = queued``, ``Location: /jobs/{job_id}``). The jobs worker (``worker.jobs.audit``)
writes the ``export`` anchor first, then the ``payload_refs(kind = anchor_export)`` object
(``worker/housekeeping/exports.py``), and records ``audit.export_completed`` (actor ``system``,
``export_sha256`` and ``anchor_id``) exactly once. ``GET /audit/exports/{id}``:

* ``done``: the export object exists (``export_sha256``, ``anchor_id``, ``download_url`` =
  ``/api/v1/payloads/{ref_id}``, the payload route that serves and audits downloads);
* otherwise the export job's state (``queued``, ``running`` or ``failed``).

``POST /exports`` (data export) is cut to Phase 1.5 (ROADMAP A8): the route is guarded and
answers 501 after authorisation, so its authz wall holds.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sibyl_schemas.values import JobKind

from ...core.jobs import Requester, enqueue_job
from ...core.problems import ProblemError
from ...worker.housekeeping.exports import EXPORT_KIND, EXPORT_SOURCE, MAX_EXPORT_ROWS
from ...worker.housekeeping.verification import head_seq
from ..auth.common import parse_uuid
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, audit, run_read, run_write, services_of
from .models import AuditExportCreate, ExportCreate

router = APIRouter()
REF_PREFIX = "audit_export:"
JOB_SUBJECT = "audit_export"
_JOB_STATE_SQL = (
    "SELECT state FROM sibyl.job WHERE tenant_id = $1 AND kind = $2 AND subject_kind = $3"
    " AND subject_id = $4 ORDER BY created_at DESC, id DESC LIMIT 1"
)


def _download_url(ctx: AuthContext, ref_id: UUID) -> str:
    settings = services_of(ctx).settings
    base = settings.public_url.rstrip("/") if settings is not None else ""
    return f"{base}{API_PREFIX}/payloads/{ref_id}"


def _export_view(
    export_id: UUID, request: dict[str, Any], state: str, **extra: Any
) -> dict[str, Any]:
    return {
        "id": str(export_id),
        "state": state,
        "from_seq": int(request["from_seq"]),
        "to_seq": int(request["to_seq"]),
        "format": request["format"],
        "anchor_id": extra.get("anchor_id"),
        "export_sha256": extra.get("export_sha256"),
        "payload_ref_id": extra.get("payload_ref_id"),
        "download_url": extra.get("download_url"),
        "download_expires_at": None,
    }


@router.post(API_PREFIX + "/audit/exports", status_code=202)
async def create_audit_export(
    body: AuditExportCreate,
    ctx: Annotated[AuthContext, Depends(guard("createAuditExport"))],
) -> Response:
    ctx.object_rule_checked("auditor_reveal")  # the export is always audited (audit.exported)
    if body.to_seq - body.from_seq + 1 > MAX_EXPORT_ROWS:
        raise ProblemError("validation_failed", f"an export holds at most {MAX_EXPORT_ROWS} rows")
    principal = ctx.principal
    if principal is None:  # guard() always resolves one; never enqueue an anonymous job
        raise ProblemError("unauthenticated")
    outbox = services_of(ctx).outbox

    async def work(conn: Any) -> Outcome:
        head = await head_seq(conn, ctx.tenant_id)
        if head is None or body.to_seq > head:
            raise ProblemError("validation_failed", "to_seq lies beyond the audit chain head")
        export_id: UUID = await conn.fetchval("SELECT sibyl.uuidv7()")
        request = {
            "from_seq": body.from_seq,
            "to_seq": body.to_seq,
            "format": body.format,
        }
        receipt = await audit(
            conn,
            ctx,
            "audit.exported",
            resource_type="tenant",
            resource_id=ctx.tenant_id,
            resource_ref=REF_PREFIX + str(export_id),
            detail={**request, "export_id": str(export_id), "export_sha256": None},
        )
        job = await enqueue_job(
            conn,
            outbox,
            ctx.tenant_id,
            kind=JobKind.AUDIT_EXPORT,
            requester=Requester.of(principal),
            params={"export_id": str(export_id), **request},
            subject=(JOB_SUBJECT, export_id),
        )
        return Outcome(
            _export_view(export_id, request, "queued"),
            status=202,
            receipt=receipt,
            headers={"Location": f"{API_PREFIX}/jobs/{job.id}"},
        )

    return await run_write(ctx, work, idempotent=True)


async def _state(conn: Any, tenant: UUID, export_id: UUID) -> str:
    """The export job's state; an export without a job (never enqueued) has failed."""
    state = await conn.fetchval(
        _JOB_STATE_SQL, tenant, JobKind.AUDIT_EXPORT.value, JOB_SUBJECT, export_id
    )
    return "failed" if state is None or state == "done" else str(state)


@router.get(API_PREFIX + "/audit/exports/{export_id}")
async def get_audit_export(
    export_id: str, ctx: Annotated[AuthContext, Depends(guard("getAuditExport"))]
) -> Response:
    eid = parse_uuid(export_id)

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT detail FROM sibyl.audit_events WHERE tenant_id = $1"
            " AND action = 'audit.exported' AND resource_ref = $2 LIMIT 1",
            ctx.tenant_id,
            REF_PREFIX + str(eid),
        )
        if row is None:
            raise ProblemError("not_found")
        request = dict(row["detail"])
        ref = await conn.fetchrow(
            "SELECT id, sha256 FROM sibyl.payload_refs WHERE tenant_id = $1 AND kind = $2"
            " AND source_kind = $3 AND source_id = $4 LIMIT 1",
            ctx.tenant_id,
            EXPORT_KIND,
            EXPORT_SOURCE,
            eid,
        )
        if ref is None:
            return Outcome(_export_view(eid, request, await _state(conn, ctx.tenant_id, eid)))
        anchor = await conn.fetchval(
            "SELECT id FROM sibyl.audit_anchors WHERE tenant_id = $1 AND seq_to = $2",
            ctx.tenant_id,
            int(request["to_seq"]),
        )
        return Outcome(
            _export_view(
                eid,
                request,
                "done",
                anchor_id=None if anchor is None else str(anchor),
                export_sha256=bytes(ref["sha256"]).hex(),
                payload_ref_id=str(ref["id"]),
                download_url=_download_url(ctx, ref["id"]),
            )
        )

    return await run_read(ctx, work)


@router.post(API_PREFIX + "/exports", status_code=202)
async def create_data_export(
    body: ExportCreate,
    ctx: Annotated[AuthContext, Depends(guard("createDataExport"))],
) -> Response:
    raise ProblemError(
        "not_implemented", "data exports are Phase 1.5 (ROADMAP A8); use /audit/exports"
    )
