"""The off-database erasure ledger (R63; G0 security review H1), owned by W0-DB / FIX-DB.

JSONL, append-only, one entry per completed erasure. Each entry is Ed25519-signed by the
ledger key, which never enters Postgres, and hash-chained::

    body       = {seq, prev_hash, tenant_id, scope_kind, scope_ref, erasure_request_id,
                  key_ids, completed_at, subject_set}
    sig        = base64url(Ed25519(JCS(body)))            (unpadded, 86 characters)
    entry      = body + {sig}
    entry_hash = hex(sha256(JCS(entry)))                 prev_hash of the next entry

``seq`` starts at 0 and is gapless; the genesis ``prev_hash`` is 64 zeros. ``subject_set``
is the operator-resolved set of a subject-scope erasure (``{agent_ids, window_from,
window_to}``) and ``null`` otherwise, so a restore can re-apply subject erasures too.

A signed head record ``{count, head_hash, at, sig}`` sits alongside the ledger; the backup
manifest records ``(count, head_hash)`` at backup time. Verification checks every signature,
the chain, and that the ledger reaches the expected head (it may have grown since: erasures
completed after the backup are exactly what a restore re-applies). The database re-checks
chain and head in ``sibyl.erasure_reapply_from_ledger(jsonl, expected_count, expected_head)``.

Keys: ``SIBYL_LEDGER_SIGNING_KEY_FILE`` (PEM PKCS#8, or the raw 32-byte seed, or its base64url)
for the writer; ``SIBYL_LEDGER_PUBLIC_KEY`` (PEM, or base64url of the raw 32-byte key) for
verifiers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from sibyl_schemas.canonical import CanonicalizationError, canonicalize, parse_json_strict

GENESIS_PREV_HASH = "0" * 64
SCOPE_KINDS = frozenset({"tenant", "agent", "subject"})
BODY_FIELDS = (
    "seq",
    "prev_hash",
    "tenant_id",
    "scope_kind",
    "scope_ref",
    "erasure_request_id",
    "key_ids",
    "completed_at",
    "subject_set",
)
ENTRY_FIELDS = frozenset({*BODY_FIELDS, "sig"})
HEAD_FIELDS = frozenset({"count", "head_hash", "at", "sig"})


class LedgerError(ValueError):
    """The ledger, an entry, a signature or the head is invalid."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _jcs(value: Any) -> bytes:
    return canonicalize(value, allow_floats=False)


# --- keys ----------------------------------------------------------------------------------


def generate_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_of(key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return key.public_key()


def private_key_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def public_key_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _raw32(data: bytes) -> bytes | None:
    if len(data) == 32:
        return data
    try:
        raw = _b64url_decode(data.decode("ascii").strip())
    except (UnicodeDecodeError, binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


def load_private_key(data: bytes) -> Ed25519PrivateKey:
    """PEM PKCS#8, the raw 32-byte seed, or its base64url text."""
    if data.lstrip().startswith(b"-----BEGIN"):
        key = load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise LedgerError("the ledger signing key must be Ed25519")
        return key
    seed = _raw32(data)
    if seed is None:
        raise LedgerError("unreadable ledger signing key")
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_public_key(data: bytes) -> Ed25519PublicKey:
    """PEM SubjectPublicKeyInfo, the raw 32-byte key, or its base64url text."""
    if data.lstrip().startswith(b"-----BEGIN"):
        key = load_pem_public_key(data)
        if not isinstance(key, Ed25519PublicKey):
            raise LedgerError("the ledger public key must be Ed25519")
        return key
    raw = _raw32(data)
    if raw is None:
        raise LedgerError("unreadable ledger public key")
    return Ed25519PublicKey.from_public_bytes(raw)


# --- entries -------------------------------------------------------------------------------


def entry_hash(entry: Mapping[str, Any]) -> str:
    return hashlib.sha256(_jcs(dict(entry))).hexdigest()


def head_of(entries: Sequence[Mapping[str, Any]]) -> tuple[int, str]:
    """``(count, head_hash)``: what a backup manifest records."""
    return len(entries), entry_hash(entries[-1]) if entries else GENESIS_PREV_HASH


def append(
    entries: Sequence[Mapping[str, Any]],
    *,
    signing_key: Ed25519PrivateKey,
    tenant_id: str,
    erasure_request_id: str,
    scope_kind: str,
    scope_ref: str | None,
    key_ids: Sequence[str],
    completed_at: str,
    subject_set: Mapping[str, Any] | None = None,
) -> tuple[Mapping[str, Any], ...]:
    """Return a new ledger with one signed entry appended (the input is not modified)."""
    if scope_kind not in SCOPE_KINDS:
        raise LedgerError(f"scope_kind {scope_kind!r}")
    if (scope_kind == "subject") != (subject_set is not None):
        raise LedgerError("subject_set is required for, and only for, subject scope")
    body = {
        "seq": len(entries),
        "prev_hash": head_of(entries)[1],
        "tenant_id": tenant_id,
        "scope_kind": scope_kind,
        "scope_ref": scope_ref,
        "erasure_request_id": erasure_request_id,
        "key_ids": list(key_ids),
        "completed_at": completed_at,
        "subject_set": None if subject_set is None else dict(subject_set),
    }
    entry = {**body, "sig": _b64url(signing_key.sign(_jcs(body)))}
    return (*entries, entry)


def to_jsonl(entries: Iterable[Mapping[str, Any]]) -> str:
    return "".join(_jcs(dict(e)).decode() + "\n" for e in entries)


def _signature_ok(public_key: Ed25519PublicKey, signature: Any, message: bytes) -> bool:
    if not isinstance(signature, str) or len(signature) != 86:
        return False
    try:
        public_key.verify(_b64url_decode(signature), message)
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True


def _parse(line: str, seq: int) -> dict[str, Any]:
    try:
        entry = parse_json_strict(line)
    except CanonicalizationError as exc:
        raise LedgerError(f"entry {seq} is not JSON: {exc}") from exc
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        raise LedgerError(f"entry {seq} does not have exactly the ledger fields")
    if entry["scope_kind"] not in SCOPE_KINDS:
        raise LedgerError(f"entry {seq} has scope_kind {entry['scope_kind']!r}")
    if (entry["scope_kind"] == "subject") != isinstance(entry["subject_set"], dict):
        raise LedgerError(f"entry {seq}: subject_set is required for, and only for, subject scope")
    return entry


def verify(
    jsonl: str,
    public_key: Ed25519PublicKey,
    *,
    expected_count: int | None = None,
    expected_head: str | None = None,
) -> tuple[Mapping[str, Any], ...]:
    """Parse and verify a ledger; raise LedgerError at the first problem.

    With ``expected_count``/``expected_head`` (from the backup manifest) the ledger must hold
    at least that many entries and entry ``expected_count - 1`` must hash to the head, which
    detects truncation and substitution.
    """
    prev = GENESIS_PREV_HASH
    out: list[Mapping[str, Any]] = []
    for line in (ln for ln in jsonl.splitlines() if ln.strip()):
        seq = len(out)
        entry = _parse(line, seq)
        if entry["seq"] != seq or entry["prev_hash"] != prev:
            raise LedgerError(f"chain broken at seq {seq}")
        body = {k: entry[k] for k in BODY_FIELDS}
        if not _signature_ok(public_key, entry["sig"], _jcs(body)):
            raise LedgerError(f"bad signature at seq {seq}")
        prev = entry_hash(entry)
        out.append(entry)
    if (expected_count is None) != (expected_head is None):
        raise LedgerError("expected_count and expected_head go together")
    if expected_count is not None:
        if expected_count < 0 or len(out) < expected_count:
            raise LedgerError(
                f"ledger has {len(out)} entries; the backup expects at least {expected_count}"
            )
        if head_of(out[:expected_count])[1] != expected_head:
            raise LedgerError(f"ledger does not reach the expected head at entry {expected_count}")
    return tuple(out)


def sign_head(
    entries: Sequence[Mapping[str, Any]], signing_key: Ed25519PrivateKey, *, at: str
) -> dict[str, Any]:
    count, head = head_of(entries)
    body = {"count": count, "head_hash": head, "at": at}
    return {**body, "sig": _b64url(signing_key.sign(_jcs(body)))}


def verify_head(
    record: Mapping[str, Any], entries: Sequence[Mapping[str, Any]], public_key: Ed25519PublicKey
) -> None:
    """The signed head is genuine and describes exactly ``entries`` (no truncated tail)."""
    if set(record) != HEAD_FIELDS:
        raise LedgerError("the head record does not have exactly count, head_hash, at, sig")
    body = {k: record[k] for k in ("count", "head_hash", "at")}
    if not _signature_ok(public_key, record["sig"], _jcs(body)):
        raise LedgerError("bad signature on the ledger head")
    if (record["count"], record["head_hash"]) != head_of(entries):
        raise LedgerError("the ledger does not end at its signed head")


def load_head(text: str) -> dict[str, Any]:
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LedgerError(f"the head record is not JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise LedgerError("the head record is not an object")
    return record
