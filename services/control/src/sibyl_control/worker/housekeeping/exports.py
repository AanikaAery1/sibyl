"""Audit export writer (API.md §5.11): anchor first, then the object.

Requested by ``POST /audit/exports`` as an ``audit_export`` job (B14, CR U-6; params
``{export_id, from_seq, to_seq, format}``) and run by ``worker.jobs.audit.AuditExport``, which
calls ``run_export`` inside one tenant transaction and records ``audit.export_completed``
(ruling G0-12). ``run_export`` writes ``audit_anchors(kind = 'export')`` at ``to_seq`` (or
reuses the anchor already there), builds the export, seals it under the tenant ``payload`` DEK
into the BlobStore and inserts ``payload_refs(kind = 'anchor_export', source_kind = 'export',
source_id = export_id)``. That row is the export's completion record: ``GET /audit/exports/{id}``
reads it, and ``GET /payloads/{ref_id}`` downloads it.

JSONL is ``sibyl.audit_export/1`` (``sibyl_schemas.audit_chain``) and verifies offline with
``sibyl audit verify``. CSV carries the same event columns (``detail`` as canonical JSON)
without anchors; it is for spreadsheets, not for verification.
"""

from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sibyl_schemas.audit_chain import anchor_view, event_line, export_header, jsonl

from ...core.canonical import canonicalize
from ...core.crypto.signing import Ed25519Signer
from .anchoring import write_anchor

EXPORT_KIND = "anchor_export"
EXPORT_SOURCE = "export"
EXPORT_RETENTION = timedelta(days=400)
BATCH_ROWS = 5_000
MAX_EXPORT_ROWS = 1_000_000
PROFILE_HASH = hashlib.sha256(b"sibyl.audit_export/1: audit detail holds no content").digest()
_ROWS_SQL = (
    "SELECT e.*, sibyl.rfc3339(e.occurred_at) AS occurred_at_text,"
    " sibyl.rfc3339(e.recorded_at) AS recorded_at_text FROM sibyl.audit_events e"
    " WHERE e.tenant_id = $1 AND e.seq >= $2 AND e.seq <= $3 ORDER BY e.seq LIMIT $4"
)
_ANCHORS_SQL = (
    "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 AND seq_to >= $2 AND seq_to <= $3"
    " ORDER BY seq_to"
)
CSV_COLUMNS = (
    "seq",
    "recorded_at",
    "occurred_at",
    "action",
    "actor_type",
    "actor_id",
    "actor_key_id",
    "actor_session_id",
    "resource_type",
    "resource_id",
    "resource_ref",
    "reason",
    "request_id",
    "severity",
    "is_evidence",
    "chain_version",
    "detail",
    "prev_hash",
    "hash",
)


@dataclass(frozen=True)
class ExportRequest:
    export_id: UUID
    from_seq: int
    to_seq: int
    format: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> ExportRequest:
        fmt = str(payload.get("format", "jsonl"))
        if fmt not in ("jsonl", "csv"):
            raise ValueError(f"unknown export format {fmt!r}")
        request = cls(
            UUID(str(payload["export_id"])),
            int(payload["from_seq"]),
            int(payload["to_seq"]),
            fmt,
        )
        if request.from_seq < 0 or request.to_seq < request.from_seq:
            raise ValueError("export range is empty")
        if request.to_seq - request.from_seq + 1 > MAX_EXPORT_ROWS:
            raise ValueError("export range exceeds the per-export row cap")
        return request


@dataclass(frozen=True)
class ExportResult:
    payload_ref_id: UUID
    anchor_id: UUID
    sha256: str
    rows: int


async def existing_export(conn: Any, tenant_id: UUID, export_id: UUID) -> Any:
    return await conn.fetchrow(
        "SELECT * FROM sibyl.payload_refs WHERE tenant_id = $1 AND kind = $2"
        " AND source_kind = $3 AND source_id = $4 LIMIT 1",
        tenant_id,
        EXPORT_KIND,
        EXPORT_SOURCE,
        export_id,
    )


async def _stored_result(
    conn: Any, tenant_id: UUID, request: ExportRequest, done: Any
) -> ExportResult:
    """The result of an export that already exists (a re-run of its job): same object, the
    export anchor at ``to_seq`` and the row count the export was cut with."""
    anchor_id = await conn.fetchval(
        "SELECT id FROM sibyl.audit_anchors WHERE tenant_id = $1 AND seq_to = $2",
        tenant_id,
        request.to_seq,
    )
    return ExportResult(
        done["id"],
        UUID(int=0) if anchor_id is None else anchor_id,
        bytes(done["sha256"]).hex(),
        request.to_seq - request.from_seq + 1,
    )


async def _rows(conn: Any, tenant_id: UUID, start: int, end: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor = start
    while cursor <= end:
        batch = await conn.fetch(_ROWS_SQL, tenant_id, cursor, end, BATCH_ROWS)
        if not batch:
            break
        for record in batch:
            row = dict(record)
            row["occurred_at"] = row.pop("occurred_at_text")
            row["recorded_at"] = row.pop("recorded_at_text")
            out.append(row)
        cursor = int(batch[-1]["seq"]) + 1
    return out


def _csv(rows: list[dict[str, Any]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        line = event_line(row)
        writer.writerow(
            [
                line["seq"],
                line["recorded_at"],
                line["occurred_at"] or "",
                line["action"],
                line["actor_type"],
                line["actor_id"] or "",
                line["actor_key_id"] or "",
                line["actor_session_id"] or "",
                line["resource_type"],
                line["resource_id"] or "",
                line["resource_ref"] or "",
                line["reason"] or "",
                line["request_id"] or "",
                line["severity"],
                "true" if line["is_evidence"] else "false",
                line["chain_version"],
                canonicalize(line["detail"]).decode(),
                line["prev_hash"],
                line["hash"],
            ]
        )
    return buffer.getvalue().encode()


def render(
    tenant_id: UUID,
    request: ExportRequest,
    rows: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
    anchor_id: UUID,
    exported_at: datetime,
) -> bytes:
    if request.format == "csv":
        return _csv(rows)
    header = export_header(
        tenant_id=tenant_id,
        export_id=request.export_id,
        from_seq=request.from_seq,
        to_seq=request.to_seq,
        anchor_id=anchor_id,
        exported_at=exported_at,
    )
    lines: list[dict[str, Any]] = [header]
    lines.extend(event_line(row) for row in rows)
    lines.extend({"type": "anchor", **anchor_view(a)} for a in anchors)
    return jsonl(lines)


async def run_export(
    conn: Any,
    tenant_id: UUID,
    request: ExportRequest,
    *,
    signer: Ed25519Signer | None,
    sealer: Any,
    publish: Any = None,
) -> ExportResult:
    """One export inside the caller's tenant transaction (idempotent by ``export_id``: an
    export that already exists is returned as stored, without ``signer`` / ``sealer``)."""
    done = await existing_export(conn, tenant_id, request.export_id)
    if done is not None:
        return await _stored_result(conn, tenant_id, request, done)
    if signer is None or sealer is None:
        raise ValueError("a new export needs the anchor signer and the payload sealer")
    anchor = await write_anchor(
        conn,
        tenant_id,
        signer,
        kind="export",
        seq_to=request.to_seq,
        seq_from=request.from_seq,
        publish=publish,
    )
    rows = await _rows(conn, tenant_id, request.from_seq, request.to_seq)
    if len(rows) != request.to_seq - request.from_seq + 1:
        raise ValueError("the audit chain has a gap in the export range")
    anchors = [
        dict(a) for a in await conn.fetch(_ANCHORS_SQL, tenant_id, request.from_seq, request.to_seq)
    ]
    exported_at: datetime = await conn.fetchval("SELECT clock_timestamp()")
    body = render(tenant_id, request, rows, anchors, anchor.row["id"], exported_at)
    content_type = "text/csv" if request.format == "csv" else "application/x-ndjson"
    sealed = await sealer.seal(
        tenant_id,
        body,
        kind=EXPORT_KIND,
        source_kind=EXPORT_SOURCE,
        content_type=content_type,
        parts=(),
        capture_mode="full",
        redaction_profile_hash=PROFILE_HASH,
        now=exported_at,
        retention=EXPORT_RETENTION,
        source_id=request.export_id,
    )
    await conn.execute(
        "INSERT INTO sibyl.payload_refs (tenant_id, id, created_at, kind, uri, content_type,"
        " sha256, size_bytes, stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
        " redaction_profile_hash, source_kind, source_id, expires_at)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        tenant_id,
        sealed.id,
        sealed.created_at,
        EXPORT_KIND,
        sealed.key,
        content_type,
        sealed.sha256,
        sealed.size_bytes,
        sealed.stored_bytes,
        sealed.tenant_key_id,
        sealed.key_version,
        sealed.nonce,
        "full",
        PROFILE_HASH,
        EXPORT_SOURCE,
        request.export_id,
        sealed.expires_at,
    )
    return ExportResult(sealed.id, anchor.row["id"], hashlib.sha256(body).hexdigest(), len(rows))
