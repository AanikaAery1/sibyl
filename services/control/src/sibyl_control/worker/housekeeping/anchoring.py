"""Write one signed audit anchor (DATAMODEL §6.4 step 4; ADR-12).

Runs inside the caller's tenant transaction: takes the audit lock first (the anchor is followed
by its own ``audit.anchored`` row), reads the chain head (or the row at an explicit ``seq_to``),
signs ``sibyl_schemas.audit_chain.anchor_document`` with the active ``audit_anchor`` key and inserts
``audit_anchors``. ``seq_to`` is unique per tenant: asking for an anchor at a position that is
already anchored returns the existing anchor instead of failing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sibyl_schemas.audit_chain import anchor_document, anchor_view, b64url_decode, jsonl

from ...core.audit import AuditRecord, PgAuditWriter
from ...core.blob.base import BlobExists, BlobStore
from ...core.crypto.signing import Ed25519Signer

SYSTEM = "system"
_HEAD_SQL = "SELECT seq, hash FROM sibyl.audit_chain_head WHERE tenant_id = $1"
_ROW_HASH_SQL = "SELECT hash FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2"
_AT_SQL = "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 AND seq_to = $2"
_LAST_SQL = (
    "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1"
    " ORDER BY seq_to DESC, anchored_at DESC LIMIT 1"
)
_INSERT_SQL = (
    "INSERT INTO sibyl.audit_anchors (tenant_id, id, kind, seq_from, seq_to, head_hash,"
    " prev_anchor_id, signing_kid, signature, anchored_at, external_ref)"
    " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *"
)


@dataclass(frozen=True)
class AnchorResult:
    row: dict[str, Any]
    created: bool


class NothingToAnchor(Exception):
    """The tenant has no audit chain yet, or the requested position does not exist."""


def anchor_blob_key(tenant_id: UUID, anchor_id: UUID) -> str:
    return f"anchors/{tenant_id}/{anchor_id}.json"


async def last_anchor(conn: Any, tenant_id: UUID) -> dict[str, Any] | None:
    row = await conn.fetchrow(_LAST_SQL, tenant_id)
    return None if row is None else dict(row)


async def write_anchor(
    conn: Any,
    tenant_id: UUID,
    signer: Ed25519Signer,
    *,
    kind: str,
    seq_to: int | None = None,
    seq_from: int | None = None,
    publish: BlobStore | None = None,
) -> AnchorResult:
    """Anchor ``seq_to`` (default: the chain head). With ``publish`` the signed anchor is also
    copied to the BlobStore under ``anchors/<tenant>/<anchor_id>.json`` (off-database copy for
    the restore drill, security-auditor §2.5) and ``external_ref`` names that key."""
    await conn.execute("SELECT sibyl.audit_lock($1)", tenant_id)
    head = await conn.fetchrow(_HEAD_SQL, tenant_id)
    if head is None:
        raise NothingToAnchor("no audit chain")
    target = int(head["seq"]) if seq_to is None else int(seq_to)
    if target > int(head["seq"]) or target < 0:
        raise NothingToAnchor(f"seq {target} is beyond the chain head")
    existing = await conn.fetchrow(_AT_SQL, tenant_id, target)
    if existing is not None:
        return AnchorResult(dict(existing), created=False)
    head_hash = bytes(head["hash"]) if target == int(head["seq"]) else None
    if head_hash is None:
        found = await conn.fetchval(_ROW_HASH_SQL, tenant_id, target)
        if found is None:
            raise NothingToAnchor(f"seq {target} is missing from the chain")
        head_hash = bytes(found)
    prev = await last_anchor(conn, tenant_id)
    if seq_from is None:
        seq_from = int(prev["seq_to"]) + 1 if prev and int(prev["seq_to"]) < target else 0
    anchor_id: UUID = await conn.fetchval("SELECT sibyl.uuidv7()")
    anchored_at = await conn.fetchval("SELECT clock_timestamp()")
    prev_id = None if prev is None else prev["id"]
    external_ref = None if publish is None else anchor_blob_key(tenant_id, anchor_id)
    document = anchor_document(
        anchor_id=anchor_id,
        tenant_id=tenant_id,
        kind=kind,
        seq_from=seq_from,
        seq_to=target,
        head_hash=head_hash,
        prev_anchor_id=prev_id,
        signing_kid=signer.kid,
        anchored_at=anchored_at,
    )
    signed = signer.sign_document(document)
    row = dict(
        await conn.fetchrow(
            _INSERT_SQL,
            tenant_id,
            anchor_id,
            kind,
            seq_from,
            target,
            head_hash,
            prev_id,
            signer.kid,
            b64url_decode(signed.signature),
            anchored_at,
            external_ref,
        )
    )
    if publish is not None and external_ref is not None:
        try:
            await publish.put(
                external_ref, jsonl([anchor_view(row)]), content_type="application/json"
            )
        except BlobExists:
            pass
    await PgAuditWriter().append(
        conn,
        tenant_id,
        AuditRecord(
            action="audit.anchored",
            actor_type=SYSTEM,
            resource_type="audit_anchor",
            resource_id=anchor_id,
            detail={
                "anchor_id": str(anchor_id),
                "seq_from": seq_from,
                "seq_to": target,
                "kid": signer.kid,
                "kind": kind,
            },
        ),
    )
    return AnchorResult(row, created=True)
