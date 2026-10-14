"""Monitor-bound API keys (D53): what a key bound to an external monitor may reach.

A monitor key holds ``monitor:read`` and/or ``findings:write`` only (DB CHECK
``ck_api_key_monitor``). When it authenticates, its grants are narrowed to the monitor's watched
agent groups (the listed groups and their descendants, like a group membership) so every route
that evaluates the ``group`` object rule filters for it; ``None`` means every group. A key whose
monitor is revoked, or cannot be found, fails closed with the uniform 401. A paused monitor still
reads; the findings route refuses it (409 ``not_active``).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from .authz import Grant

__all__ = [
    "MonitorBinding",
    "MonitorLookup",
    "descendants",
    "monitor_grants",
    "pg_monitor_lookup",
]

_MONITOR_SQL = (
    "SELECT state, all_groups, group_ids FROM sibyl.monitor WHERE tenant_id = $1 AND id = $2"
)
_GROUPS_SQL = "SELECT id, parent_group_id FROM sibyl.agent_group WHERE tenant_id = $1"


@dataclass(frozen=True)
class MonitorBinding:
    monitor_id: UUID
    state: str  # active | paused | revoked
    group_ids: frozenset[UUID] | None  # None = every agent group (and ungrouped agents)

    @property
    def usable(self) -> bool:
        return self.state != "revoked"


MonitorLookup = Callable[[UUID, UUID], Awaitable[MonitorBinding | None]]


def descendants(roots: Iterable[UUID], edges: Mapping[UUID, UUID | None]) -> frozenset[UUID]:
    """``roots`` plus every group below them (cycle-safe)."""
    children: dict[UUID, list[UUID]] = {}
    for child, parent in edges.items():
        if parent is not None:
            children.setdefault(parent, []).append(child)
    out: set[UUID] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        if node in out:
            continue
        out.add(node)
        stack.extend(children.get(node, ()))
    return frozenset(out)


async def load_binding(conn: Any, tenant_id: UUID, monitor_id: UUID) -> MonitorBinding | None:
    row = await conn.fetchrow(_MONITOR_SQL, tenant_id, monitor_id)
    if row is None:
        return None
    if row["all_groups"]:
        return MonitorBinding(monitor_id, row["state"], None)
    edges = {r["id"]: r["parent_group_id"] for r in await conn.fetch(_GROUPS_SQL, tenant_id)}
    return MonitorBinding(monitor_id, row["state"], descendants(row["group_ids"] or (), edges))


def pg_monitor_lookup(db: Any) -> MonitorLookup:
    """Reads the monitor in the key's tenant (one read-only tenant transaction)."""

    async def lookup(tenant_id: UUID, monitor_id: UUID) -> MonitorBinding | None:
        async with db.tenant_tx(tenant_id, readonly=True) as conn:
            return await load_binding(conn, tenant_id, monitor_id)

    return lookup


def monitor_grants(scopes: Iterable[str], binding: MonitorBinding) -> dict[str, Grant]:
    """The key's scopes, each limited to the monitor's watched groups."""
    return {scope: Grant(scope, binding.group_ids) for scope in frozenset(scopes)}
