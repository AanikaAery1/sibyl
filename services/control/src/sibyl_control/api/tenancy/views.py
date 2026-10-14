"""Row → contract representation for the identity/tenancy schemas (never secrets or hashes)."""

from __future__ import annotations

from typing import Any

from ...core.etag import etag_for_row
from ..auth.common import iso


def _s(value: Any) -> str | None:
    return str(value) if value is not None else None


def tenant_view(row: Any) -> dict[str, Any]:
    limits = row["ingest_rate_limit"] or {}
    return {
        "id": str(row["id"]),
        "slug": row["slug"],
        "name": row["name"],
        "status": row["status"],
        "region_declared": row["region_declared"],
        "unknown_agent_fail_mode": row["unknown_agent_fail_mode"],
        "hold_on_incident": row["hold_on_incident"],
        "raw_retention_days": row["raw_retention_days"],
        "audit_retention_days": row["audit_retention_days"],
        "backup_retention_days": row["backup_retention_days"],
        "routing_version": row["routing_version"],
        "graph_version": row["graph_version"],
        "limits": {
            "max_agents": row["max_agents"],
            "ingest_rate_limit": int(limits.get("events_per_s", 0)),
            "ingest_burst": int(limits.get("burst", 0)),
        },
    }


def row_etag(row: Any) -> str:
    return etag_for_row(row["updated_at"], row["id"])


def user_view(row: Any) -> dict[str, Any]:
    deprovisioned = row["status"] == "deprovisioned"
    return {
        "id": str(row["id"]),
        "email": None if deprovisioned else row["email"],
        "display_name": None if deprovisioned else row["display_name"],
        "status": row["status"],
        "oidc_issuer_id": str(row["oidc_issuer_id"]),
        "last_login_at": iso(row["last_login_at"]),
        "created_at": iso(row["created_at"]),
    }


def membership_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]),
        "role_name": row["role_name"],
        "scope_kind": row["scope_kind"],
        "scope_id": _s(row["scope_id"]),
        "expires_at": iso(row["expires_at"]),
        "created_at": iso(row["created_at"]),
    }


def issuer_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "issuer_url": row["issuer_url"],
        "client_id": row["client_id"],
        "allowed_email_domains": list(row["allowed_email_domains"] or []),
        "role_claim": row["role_claim"],
        "role_claim_map": row["role_claim_map"] or None,
        "jit_default_role": row["jit_default_role"],
        "is_active": row["status"] == "active",
        "created_at": iso(row["created_at"]),
    }


def group_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "slug": row["slug"],
        "name": row["name"],
        "description": row["description"],
        "parent_group_id": _s(row["parent_group_id"]),
        "owner_user_id": _s(row["owner_user_id"]),
        "created_at": iso(row["created_at"]),
    }


def session_view(row: Any, current: Any = None) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]),
        "created_at": iso(row["created_at"]),
        "last_seen_at": iso(row["last_seen_at"]),
        "expires_at": iso(min(row["absolute_expires_at"], row["idle_expires_at"])),
        "step_up_at": iso(row["step_up_at"]),
        "ip_hash": bytes(row["ip_hash"]).hex() if row["ip_hash"] is not None else None,
        "user_agent": row["ua_class"],
        "current": current is not None and row["id"] == current,
    }


def tenant_key_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "purpose": row["purpose"],
        "version": row["version"],
        "algorithm": row["algorithm"],
        "kek_id": row["kek_id"],
        "state": row["state"],
        "activated_at": iso(row["activated_at"]),
        "retired_at": iso(row["retired_at"]),
        "shredded_at": iso(row["shredded_at"]),
    }
