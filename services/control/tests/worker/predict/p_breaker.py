"""PG17 helpers for the per-agent breaker: rows written as other lanes would write them."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4


def replica(kit: Any, t: UUID, sql: str, *args: Any) -> None:
    """Run ``sql`` in tenant ``t`` as the admin with triggers off (rows owned by other lanes)."""

    async def go() -> None:
        async with kit.admin.transaction():
            await kit.admin.execute("SET LOCAL session_replication_role = replica")
            await kit.admin.execute("SELECT sibyl.set_tenant($1)", t)
            await kit.admin.execute(sql, *args)

    kit.run(go())


def undone_automated_transition(kit: Any, t: UUID, a: UUID, n: int, at: datetime) -> None:
    """One automated (``rule``) transition at ``at`` and the human undo that inverts it."""
    base = 900_000 + n * 2
    first, undo = uuid4(), uuid4()
    for tid, kind, trigger, inverse, version in (
        (first, "rule", "rule", None, base),
        (undo, "system", "undo", first, base + 1),
    ):
        replica(
            kit,
            t,
            "INSERT INTO sibyl.routing_transition (tenant_id, id, agent_id, from_state, to_state,"
            " from_target, to_target, trigger, actor_kind, inverse_of, routing_version, audit_seq,"
            " idempotency_key, created_at) VALUES ($1, $2, $3, 'active', 'degraded', '{}', '{}',"
            " $9, $4, $5, $6, 1, $7, $8)",
            t,
            tid,
            a,
            kind,
            inverse,
            version,
            f"breaker-{tid}",
            at,
            trigger,
        )
