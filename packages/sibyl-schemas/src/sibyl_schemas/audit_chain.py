"""Audit chain documents: row hash, signed anchor document and the export format (ADR-12).

One definition shared by the worker (anchors loop, export writer), the api verify route and the
Apache-2 offline verifier (``sibyl audit verify`` in ``sibyl-sdk``). Pure functions only (no
database, no crypto): callers sign / verify ``canonicalize(anchor_document(...))`` with Ed25519.

Row hash (DATAMODEL §5, ``sibyl.audit_append``)::

    envelope_sha256 = sha256(JCS(envelope))            the 15 flat ENVELOPE_FIELDS
    detail_sha256   = sha256(JCS(detail))
    hash            = sha256(prev_hash ‖ envelope_sha256 ‖ detail_sha256)

Anchor document (``sibyl.audit_anchor/1``): the anchor id, tenant, kind, covered range, head
hash (hex), previous anchor and signing time, so an anchor cannot be replayed onto another
tenant, range or chain position. ``signature`` is stored raw (64 bytes) and published as unpadded
base64url.

Export (``sibyl.audit_export/1``, JSONL): a ``header`` line, one ``event`` line per row in
``[from_seq, to_seq]`` and an ``anchor`` line per anchor whose ``seq_to`` falls in the range.

Writers build documents with the coercing ``envelope`` / ``anchor_document_of`` (database rows
carry ``UUID`` / ``datetime`` / ``bytes``). A verifier of untrusted bytes uses the strict
variants ``envelope_strict`` / ``anchor_document_of_strict`` (fields taken exactly as they are,
so an upper-cased UUID or a string ``seq`` that was never signed changes the digest) and passes
``allow_floats=False`` to the digests (the audit contract forbids floats).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

from sibyl_schemas.canonical import canonicalize

ANCHOR_FORMAT: Final = "sibyl.audit_anchor/1"
EXPORT_FORMAT: Final = "sibyl.audit_export/1"
GENESIS_HASH: Final = bytes(32)
ENVELOPE_FIELDS: Final = (
    "action",
    "actor_id",
    "actor_key_id",
    "actor_session_id",
    "actor_type",
    "chain_version",
    "occurred_at",
    "reason",
    "recorded_at",
    "request_id",
    "resource_id",
    "resource_ref",
    "resource_type",
    "seq",
    "tenant_id",
)
ANCHOR_FIELDS: Final = (
    "id",
    "tenant_id",
    "kind",
    "seq_from",
    "seq_to",
    "head_hash",
    "prev_anchor_id",
    "signing_kid",
    "anchored_at",
)
_UUID_FIELDS: Final = frozenset(
    {"actor_id", "actor_key_id", "actor_session_id", "request_id", "resource_id", "tenant_id"}
)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if len(text) % 4 == 1 or not all(c.isalnum() or c in "-_" for c in text):
        raise ValueError("not unpadded base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def rfc3339(value: datetime | None) -> str | None:
    """``sibyl.rfc3339``: UTC, microseconds, ``Z`` (``YYYY-MM-DDTHH:MM:SS.ffffffZ``)."""
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError("timestamps in chain documents must carry a timezone")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uuid_text(value: Any) -> str | None:
    return None if value is None else str(UUID(str(value)))


def envelope(row: Mapping[str, Any]) -> dict[str, Any]:
    """The envelope ``sibyl.audit_envelope`` hashes, from an audit row or an export line.

    ``occurred_at`` / ``recorded_at`` are ``sibyl.rfc3339`` text (datetimes are formatted the
    same way); UUID columns become their canonical text; ``seq`` / ``chain_version`` integers.
    """
    out: dict[str, Any] = {}
    for name in ENVELOPE_FIELDS:
        value = row.get(name)
        if name in _UUID_FIELDS:
            value = _uuid_text(value)
        elif name in ("occurred_at", "recorded_at") and isinstance(value, datetime):
            value = rfc3339(value)
        elif name in ("seq", "chain_version"):
            value = int(value) if value is not None else None
        out[name] = value
    return out


def envelope_strict(row: Mapping[str, Any]) -> dict[str, Any]:
    """The envelope exactly as ``row`` holds it (no coercion; absent fields are ``null``).

    For verifying untrusted export lines: ``envelope`` would normalise e.g. an upper-cased
    UUID or a string ``seq`` back to the signed form and hide the tampering."""
    return {name: row.get(name) for name in ENVELOPE_FIELDS}


def envelope_sha256(envelope_doc: Mapping[str, Any], *, allow_floats: bool = True) -> bytes:
    return hashlib.sha256(canonicalize(dict(envelope_doc), allow_floats=allow_floats)).digest()


def detail_sha256(detail: Mapping[str, Any], *, allow_floats: bool = True) -> bytes:
    return hashlib.sha256(canonicalize(dict(detail), allow_floats=allow_floats)).digest()


def row_hash(
    prev_hash: bytes,
    envelope_doc: Mapping[str, Any],
    detail: Mapping[str, Any],
    *,
    allow_floats: bool = True,
) -> bytes:
    return hashlib.sha256(
        prev_hash
        + envelope_sha256(envelope_doc, allow_floats=allow_floats)
        + detail_sha256(detail, allow_floats=allow_floats)
    ).digest()


def anchor_document(
    *,
    anchor_id: UUID | str,
    tenant_id: UUID | str,
    kind: str,
    seq_from: int,
    seq_to: int,
    head_hash: bytes | str,
    prev_anchor_id: UUID | str | None,
    signing_kid: str,
    anchored_at: datetime | str,
) -> dict[str, Any]:
    """The signed content of one anchor (sign / verify ``canonicalize`` of it)."""
    stamp = anchored_at if isinstance(anchored_at, str) else rfc3339(anchored_at)
    head = head_hash if isinstance(head_hash, str) else bytes(head_hash).hex()
    return {
        "format": ANCHOR_FORMAT,
        "id": str(anchor_id),
        "tenant_id": str(tenant_id),
        "kind": kind,
        "seq_from": int(seq_from),
        "seq_to": int(seq_to),
        "head_hash": head,
        "prev_anchor_id": None if prev_anchor_id is None else str(prev_anchor_id),
        "signing_kid": signing_kid,
        "anchored_at": stamp,
    }


def anchor_document_of(row: Mapping[str, Any]) -> dict[str, Any]:
    """From a stored ``audit_anchors`` row or a published anchor view / export line."""
    return anchor_document(
        anchor_id=row["id"],
        tenant_id=row["tenant_id"],
        kind=row["kind"],
        seq_from=row["seq_from"],
        seq_to=row["seq_to"],
        head_hash=row["head_hash"],
        prev_anchor_id=row["prev_anchor_id"],
        signing_kid=row["signing_kid"],
        anchored_at=row["anchored_at"],
    )


def anchor_document_of_strict(row: Mapping[str, Any]) -> dict[str, Any]:
    """The anchor document exactly as a published view / export line holds it (no coercion).

    For verifying untrusted anchors: the signature must cover these very values."""
    return {"format": ANCHOR_FORMAT, **{name: row.get(name) for name in ANCHOR_FIELDS}}


def anchor_view(row: Mapping[str, Any]) -> dict[str, Any]:
    """``AuditAnchor`` (API) and the export's ``anchor`` line, from a stored row (raw bytes)."""
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "kind": row["kind"],
        "seq_from": int(row["seq_from"]),
        "seq_to": int(row["seq_to"]),
        "head_hash": bytes(row["head_hash"]).hex(),
        "signing_kid": row["signing_kid"],
        "signature": b64url(bytes(row["signature"])),
        "anchored_at": rfc3339(row["anchored_at"]),
        "prev_anchor_id": None if row["prev_anchor_id"] is None else str(row["prev_anchor_id"]),
    }


def event_line(row: Mapping[str, Any]) -> dict[str, Any]:
    """One exported audit row: envelope fields, detail and the stored hashes (hex)."""
    line: dict[str, Any] = {"type": "event", **envelope(row)}
    line.update(
        {
            "severity": row["severity"],
            "is_evidence": bool(row["is_evidence"]),
            "detail": dict(row["detail"]),
            "detail_sha256": bytes(row["detail_sha256"]).hex(),
            "envelope_sha256": bytes(row["envelope_sha256"]).hex(),
            "prev_hash": bytes(row["prev_hash"]).hex(),
            "hash": bytes(row["hash"]).hex(),
        }
    )
    return line


def export_header(
    *,
    tenant_id: UUID | str,
    export_id: UUID | str,
    from_seq: int,
    to_seq: int,
    anchor_id: UUID | str,
    exported_at: datetime,
) -> dict[str, Any]:
    return {
        "type": "header",
        "format": EXPORT_FORMAT,
        "tenant_id": str(tenant_id),
        "export_id": str(export_id),
        "from_seq": int(from_seq),
        "to_seq": int(to_seq),
        "anchor_id": str(anchor_id),
        "exported_at": rfc3339(exported_at),
    }


def jsonl(lines: Sequence[Mapping[str, Any]]) -> bytes:
    """Compact, key-sorted JSON lines (each line parses back to the same document)."""
    return b"".join(
        json.dumps(dict(line), separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
        + b"\n"
        for line in lines
    )


def decode_jsonl(body: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in body.decode().splitlines() if line.strip()]
