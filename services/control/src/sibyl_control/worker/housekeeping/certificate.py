"""The erasure certificate (D26; security-auditor §7.4; API.md §5.12).

A JCS JSON document plus its sha256, built once by the worker when the request completes and
kept in the request's ``execution_log`` (``erasure_request`` is a retained table), so the
certificate survives the erasure it describes and ``GET …/certificate`` serves exactly the
bytes that were hashed. It names the scope and legal basis, the requester and approver only as
hashed refs, per-phase row counts, every shredded ``tenant_key (purpose, version)``, the
``erasure`` anchor (id, signing kid, signature), the ledger entry, ``backups_expire_at =
completed_at + tenant.backup_retention_days`` and the retained-tables list with the statement on
inline rows and audit identifiers (U3). PDF rendering is Phase 1.5 (ROADMAP A8).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

from ...core.canonical import canonicalize
from ...core.crypto.signing import b64url

CERTIFICATE_FORMAT = "sibyl.erasure_certificate/1"
STATEMENT = (
    "Erasure covers the scope's rows in every purged table and its objects in the BlobStore; "
    "for tenant scope the tenant's data keys are crypto-shredded. Inline handoff-packet and "
    "checkpoint rows are deleted, not shredded. Identifiers inside audit_events are retained "
    "as evidence and are not claimed deleted. Backups taken before completion expire at "
    "backups_expire_at; restores re-apply this erasure from the signed erasure ledger (R63)."
)


def actor_ref(user_id: Any) -> str | None:
    return (
        None
        if user_id is None
        else "sha256:" + hashlib.sha256(f"user:{user_id}".encode()).hexdigest()
    )


def build(
    *,
    request: Mapping[str, Any],
    tenant_id: Any,
    counts: Mapping[str, Any],
    shredded_keys: Sequence[Mapping[str, Any]],
    anchor: Mapping[str, Any],
    ledger_entry: Mapping[str, Any],
    ledger_entry_hash: str,
    completed_at: str,
    backups_expire_at: str,
    backup_retention_days: int,
    retained_tables: Sequence[str],
    requested_at: str | None,
    approved_at: str | None,
) -> dict[str, Any]:
    return {
        "format": CERTIFICATE_FORMAT,
        "request_id": str(request["id"]),
        "tenant_id": str(tenant_id),
        "scope_kind": request["scope_kind"],
        "scope_ref": request["scope_ref"],
        "resolution": "agent_window" if request["scope_kind"] == "subject" else None,
        "legal_basis": request["legal_basis"],
        "requested_by_ref": actor_ref(request["requested_by"]),
        "approved_by_ref": actor_ref(request["approved_by"]),
        "requested_at": requested_at,
        "approved_at": approved_at,
        "completed_at": completed_at,
        "affected_objects": {phase: dict(c) for phase, c in counts.items()},
        "shredded_keys": [
            {"purpose": k["purpose"], "version": int(k["version"])} for k in shredded_keys
        ],
        "anchor": {
            "id": str(anchor["id"]),
            "kind": anchor["kind"],
            "seq_to": int(anchor["seq_to"]),
            "head_hash": bytes(anchor["head_hash"]).hex(),
            "signing_kid": anchor["signing_kid"],
            "signature": b64url(bytes(anchor["signature"])),
        },
        "ledger": {"seq": int(ledger_entry["seq"]), "entry_hash": ledger_entry_hash},
        "backups_expire_at": backups_expire_at,
        "backup_retention_days": int(backup_retention_days),
        "retained_tables": list(retained_tables),
        "statement": STATEMENT,
    }


def digest(certificate: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(canonicalize(dict(certificate))).digest()
