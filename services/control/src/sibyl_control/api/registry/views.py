"""Read projections of the registry (agent summary/detail, versions, identity) and their ETags."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from sibyl_schemas.canonical import canonicalize

from ...core.etag import etag_for_row, etag_for_version
from ._kit import JSON, jsonable

AGENT_SELECT = """
SELECT a.*,
       rs.state AS r_state, rs.target_kind AS r_target_kind, rs.routing_version AS r_version,
       rs.state_since AS r_since,
       hs.band AS h_band, hs.score AS h_score, hs.evaluated_at AS h_at,
       cp.rto_s AS c_rto, cp.row_version AS c_row_version
  FROM sibyl.agent a
  LEFT JOIN sibyl.routing_state rs ON rs.tenant_id = a.tenant_id AND rs.agent_id = a.id
  LEFT JOIN LATERAL (
        SELECT h.band, h.score, h.evaluated_at FROM sibyl.health_snapshot h
         WHERE h.tenant_id = a.tenant_id AND h.agent_id = a.id
         ORDER BY h.evaluated_at DESC LIMIT 1) hs ON true
  LEFT JOIN sibyl.continuity_plan cp ON cp.tenant_id = a.tenant_id AND cp.agent_id = a.id
 WHERE a.tenant_id = $1"""


def agent_etag(row: dict[str, Any]) -> str:
    return etag_for_row(row["updated_at"], row["id"])


def identity_etag(version: int) -> str:
    return etag_for_version(version)


def _trace_hex(value: Any) -> str | None:
    return value.hex if isinstance(value, UUID) else None


def agent_summary(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "slug": row["slug"],
        "name": row["name"],
        "kind": row["kind"],
        "tier": row["tier"],
        "risk_class": row["risk_class"],
        "lifecycle": row["lifecycle"],
        "fail_mode": row["fail_mode"],
        "is_provisional": row["is_provisional"],
        "discovered_via": row.get("discovered_via"),
        "first_trace_id": _trace_hex(row.get("first_trace_id")),
        "confirmed_at": jsonable(row.get("confirmed_at")),
        "agent_group_id": jsonable(row["agent_group_id"]),
        "routing": {
            "state": row.get("r_state"),
            "target_kind": row.get("r_target_kind"),
            "routing_version": row.get("r_version"),
            "state_since": jsonable(row.get("r_since")),
        },
        "health": {
            "band": row.get("h_band"),
            "score": row.get("h_score"),
            "evaluated_at": jsonable(row.get("h_at")),
        },
        "continuity": ({"rto_s": row["c_rto"]} if row.get("c_rto") is not None else None),
    }


def version_view(row: dict[str, Any]) -> JSON:
    sha = row["prompt_sha256"]
    return {
        "id": str(row["id"]),
        "agent_id": str(row["agent_id"]),
        "version_no": row["version_no"],
        "primary_model_id": str(row["primary_model_id"]),
        "prompt_sha256": bytes(sha).hex() if sha is not None else None,
        "prompt_ref_id": jsonable(row["prompt_ref_id"]),
        "config": jsonable(row["config"]),
        "declared_tool_ids": jsonable(row["declared_tool_ids"]),
        "declared_data_source_ids": jsonable(row["declared_data_source_ids"]),
        "source": row["source"],
        "created_at": jsonable(row["created_at"]),
    }


def identity_view(agent_id: UUID, row: dict[str, Any] | None) -> JSON:
    if row is None:
        return {
            "agent_id": str(agent_id),
            "allowed_tools": [],
            "allowed_models": [],
            "allowed_providers": [],
            "enforcement": "observe",
            "identity_version": 0,
            "tools_hash": tools_hash([]).hex(),
        }
    return {
        "agent_id": str(agent_id),
        "allowed_tools": list(row["allowed_tools"]),
        "allowed_models": list(row["allowed_models"]),
        "allowed_providers": [str(p) for p in row["allowed_providers"]],
        "enforcement": row["enforcement"],
        "identity_version": row["identity_version"],
        "tools_hash": bytes(row["tools_hash"]).hex(),
    }


def tools_hash(tools: list[str]) -> bytes:
    return hashlib.sha256(canonicalize(sorted(set(tools)))).digest()


async def agent_detail(conn: Any, tenant_id: UUID, agent_id: UUID) -> tuple[JSON, str]:
    """The full ``Agent`` representation and its ETag."""
    row = dict(await conn.fetchrow(AGENT_SELECT + " AND a.id = $2", tenant_id, agent_id))
    body = agent_summary(row)
    version = None
    if row["current_version_id"] is not None:
        vrow = await conn.fetchrow(
            "SELECT * FROM sibyl.agent_version WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            row["current_version_id"],
        )
        version = version_view(dict(vrow)) if vrow is not None else None
    irow = await conn.fetchrow(
        "SELECT * FROM sibyl.agent_identity WHERE tenant_id = $1 AND agent_id = $2",
        tenant_id,
        agent_id,
    )
    body.update(
        {
            "description": row["description"],
            "framework": row["framework"],
            "owner_user_id": jsonable(row["owner_user_id"]),
            "business_process_id": jsonable(row["business_process_id"]),
            "cost_center": row["cost_center"],
            "tags": list(row["tags"]),
            "current_version": version,
            "identity": identity_view(agent_id, dict(irow) if irow is not None else None),
            "continuity_plan_etag": (
                etag_for_version(row["c_row_version"]) if row["c_row_version"] is not None else None
            ),
            "created_at": jsonable(row["created_at"]),
            "updated_at": jsonable(row["updated_at"]),
        }
    )
    return body, agent_etag(row)


def profile_hash(row: dict[str, Any]) -> str:
    """sha256 of the agent's declared profile (asset.* audit ``profile_hash``)."""
    keys = (
        "slug",
        "name",
        "description",
        "kind",
        "framework",
        "tier",
        "risk_class",
        "fail_mode",
        "agent_group_id",
        "owner_user_id",
        "business_process_id",
        "cost_center",
        "tags",
        "current_version_id",
        "is_provisional",
        "lifecycle",
    )
    return hashlib.sha256(canonicalize(jsonable({k: row.get(k) for k in keys}))).hexdigest()
