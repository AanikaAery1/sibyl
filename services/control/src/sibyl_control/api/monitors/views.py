"""Response bodies of the monitor routes (OpenAPI ``Monitor``, ``MonitorWebhook``).

Key and webhook secrets never appear: a monitor lists its keys by prefix and its webhooks by URL
and delivery health. ``advisory`` is always true.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final
from uuid import UUID

from ..registry._kit import JSON, jsonable

MONITOR_COLUMNS: Final = (
    "id, name, kind, description, owner_user_id, all_groups, group_ids, state,"
    " rate_limit_per_min, version, created_by_user_id, revoked_at, revoke_reason, created_at,"
    " updated_at"
)
WEBHOOK_COLUMNS: Final = (
    "id, monitor_id, url, event_types, state, consecutive_failures, last_delivery_at,"
    " last_delivery_status, last_response_code, disabled_reason, created_at, updated_at"
)
_KEYS_SQL = (
    "SELECT id, monitor_id, name, prefix, env, status, expires_at, last_used_at, created_at"
    " FROM sibyl.api_key WHERE tenant_id = $1 AND monitor_id = ANY($2::uuid[])"
    " AND status IN ('active', 'rotating') ORDER BY created_at, id"
)
_WEBHOOKS_SQL = (
    f"SELECT {WEBHOOK_COLUMNS} FROM sibyl.monitor_webhook"  # noqa: S608 (constant columns)
    " WHERE tenant_id = $1 AND monitor_id = ANY($2::uuid[]) ORDER BY created_at, id"
)
_STATS_SQL = (
    "SELECT monitor_id, count(*) FILTER (WHERE created_at > now() - interval '24 hours') AS n24,"
    " max(created_at) AS last_at FROM sibyl.external_finding"
    " WHERE tenant_id = $1 AND monitor_id = ANY($2::uuid[]) GROUP BY monitor_id"
)


def key_ref(row: Mapping[str, Any]) -> JSON:
    return {
        "id": jsonable(row["id"]),
        "name": row["name"],
        "prefix": row["prefix"],
        "env": row["env"],
        "status": row["status"],
        "expires_at": jsonable(row["expires_at"]),
        "last_used_at": jsonable(row["last_used_at"]),
        "created_at": jsonable(row["created_at"]),
    }


def webhook_view(row: Mapping[str, Any]) -> JSON:
    return {
        "id": jsonable(row["id"]),
        "monitor_id": jsonable(row["monitor_id"]),
        "url": row["url"],
        "event_types": list(row["event_types"] or ()),
        "state": row["state"],
        "consecutive_failures": int(row["consecutive_failures"]),
        "last_delivery_at": jsonable(row["last_delivery_at"]),
        "last_delivery_status": row["last_delivery_status"],
        "last_response_code": row["last_response_code"],
        "disabled_reason": row["disabled_reason"],
        "created_at": jsonable(row["created_at"]),
        "updated_at": jsonable(row["updated_at"]),
    }


def monitor_view(
    row: Mapping[str, Any],
    keys: Sequence[Mapping[str, Any]] = (),
    webhooks: Sequence[Mapping[str, Any]] = (),
    stats: Mapping[str, Any] | None = None,
) -> JSON:
    return {
        "id": jsonable(row["id"]),
        "name": row["name"],
        "kind": row["kind"],
        "description": row["description"],
        "owner_user_id": jsonable(row["owner_user_id"]),
        "all_groups": bool(row["all_groups"]),
        "group_ids": [str(g) for g in row["group_ids"] or ()],
        "state": row["state"],
        "rate_limit_per_min": int(row["rate_limit_per_min"]),
        "version": int(row["version"]),
        "keys": [key_ref(k) for k in keys],
        "webhooks": [webhook_view(w) for w in webhooks],
        "findings_24h": int(stats["n24"]) if stats else 0,
        "last_finding_at": jsonable(stats["last_at"]) if stats else None,
        "created_by_user_id": jsonable(row["created_by_user_id"]),
        "revoked_at": jsonable(row["revoked_at"]),
        "revoke_reason": row["revoke_reason"],
        "created_at": jsonable(row["created_at"]),
        "updated_at": jsonable(row["updated_at"]),
        "advisory": True,
    }


async def hydrate(conn: Any, tenant: UUID, rows: Sequence[Mapping[str, Any]]) -> list[JSON]:
    """Monitor views with their keys, webhooks and finding counts (three queries per page)."""
    if not rows:
        return []
    ids = [r["id"] for r in rows]
    keys: dict[UUID, list[Any]] = {}
    for k in await conn.fetch(_KEYS_SQL, tenant, ids):
        keys.setdefault(k["monitor_id"], []).append(k)
    hooks: dict[UUID, list[Any]] = {}
    for w in await conn.fetch(_WEBHOOKS_SQL, tenant, ids):
        hooks.setdefault(w["monitor_id"], []).append(w)
    stats = {s["monitor_id"]: s for s in await conn.fetch(_STATS_SQL, tenant, ids)}
    return [
        monitor_view(r, keys.get(r["id"], ()), hooks.get(r["id"], ()), stats.get(r["id"]))
        for r in rows
    ]
