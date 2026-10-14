"""Row → API document views of the governance module (OpenAPI components)."""

from __future__ import annotations

from typing import Any

from sibyl_schemas.audit_chain import anchor_view, b64url, rfc3339

from ..registry._kit import jsonable

ANCHOR_VIEW = anchor_view
RETAINED_NOTE = (
    "Inline handoff-packet and checkpoint rows are deleted, not crypto-shredded; identifiers "
    "inside audit_events are retained as evidence and are not claimed deleted (U3)."
)


def audit_event_view(row: Any) -> dict[str, Any]:
    return {
        "seq": int(row["seq"]),
        "id": str(row["id"]),
        "action": row["action"],
        "actor_type": row["actor_type"],
        "actor_id": jsonable(row["actor_id"]),
        "actor_key_id": jsonable(row["actor_key_id"]),
        "actor_session_id": jsonable(row["actor_session_id"]),
        "resource_type": row["resource_type"],
        "resource_id": jsonable(row["resource_id"]),
        "resource_ref": row["resource_ref"],
        "reason": row["reason"],
        "detail": jsonable(row["detail"]),
        "occurred_at": rfc3339(row["occurred_at"]),
        "recorded_at": rfc3339(row["recorded_at"]),
        "request_id": jsonable(row["request_id"]),
        "is_evidence": bool(row["is_evidence"]),
        "severity": row["severity"],
        "chain_version": int(row["chain_version"]),
        "detail_sha256": bytes(row["detail_sha256"]).hex(),
        "envelope_sha256": bytes(row["envelope_sha256"]).hex(),
        "prev_hash": bytes(row["prev_hash"]).hex(),
        "hash": bytes(row["hash"]).hex(),
    }


def signing_key_view(row: Any) -> dict[str, Any]:
    return {
        "kid": row["kid"],
        "purpose": row["purpose"],
        "algorithm": row["algorithm"],
        "public_key": b64url(bytes(row["public_key"])),
        "state": row["state"],
        "activated_at": rfc3339(row["activated_at"]),
        "retiring_until": rfc3339(row["retiring_until"]),
    }


def erasure_view(row: Any, retained_tables: list[str]) -> dict[str, Any]:
    log = list(row["execution_log"] or [])
    requested: dict[str, Any] = next((e for e in log if e.get("step") == "requested"), {})
    return {
        "id": str(row["id"]),
        "scope_kind": row["scope_kind"],
        "scope_ref": row["scope_ref"],
        "legal_basis": row["legal_basis"],
        "reason": requested.get("reason"),
        "state": row["state"],
        "origin": row["origin"],
        "requested_by": jsonable(row["requested_by"]),
        "approved_by": jsonable(row["approved_by"]),
        "approved_at": rfc3339(row["approved_at"]),
        "blocking_hold_ids": [str(h) for h in row["blocking_hold_ids"] or []],
        "execution_log": jsonable(log),
        "affected_objects": jsonable(row["affected_objects"] or {}),
        "retained_tables": retained_tables,
        "resolution": "agent_window" if row["scope_kind"] == "subject" else None,
        "error": row["error"],
        "backups_expire_at": rfc3339(row["backups_expire_at"]),
        "completion_anchor_id": jsonable(row["completion_anchor_id"]),
        "created_at": rfc3339(row["created_at"]),
        "completed_at": rfc3339(row["completed_at"]),
    }


def hold_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "scope_kind": row["scope_kind"],
        "scope_ref": row["scope_ref"],
        "provider_incident_id": jsonable(row["provider_incident_id"]),
        "agent_ids": [str(a) for a in row["agent_ids"] or []],
        "window_from": rfc3339(row["window_from"]),
        "window_to": rfc3339(row["window_to"]),
        "reason": row["reason"],
        "state": row["state"],
        "expires_at": rfc3339(row["expires_at"]),
        "placed_by": jsonable(row["placed_by"]),
        "placed_at": rfc3339(row["placed_at"]),
        "released_by": jsonable(row["released_by"]),
        "released_at": rfc3339(row["released_at"]),
        "release_reason": row["release_reason"],
        "created_at": rfc3339(row["created_at"]),
    }
