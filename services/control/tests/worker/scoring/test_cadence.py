"""R9 heartbeat input: ``continuity_plan.expected_cadence_s`` is a real column (migration 0008).

The tick reads it directly in its agents statement; nothing probes the catalogue for it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sibyl_control.worker.scoring import store

from .h_testkit import Kit


class Recorder:
    """Forwards to the tick's connection and keeps every statement it was given."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn
        self.sql: list[str] = []

    async def fetch(self, sql: str, *args: Any) -> Sequence[Any]:
        self.sql.append(sql)
        return await self._conn.fetch(sql, *args)  # type: ignore[no-any-return]

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        self.sql.append(sql)
        return await self._conn.fetchrow(sql, *args)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        self.sql.append(sql)
        return await self._conn.fetchval(sql, *args)

    async def execute(self, sql: str, *args: Any) -> Any:
        self.sql.append(sql)
        return await self._conn.execute(sql, *args)


def _load(kit: Kit, tenant: UUID) -> tuple[store.TenantData | None, list[str]]:
    async def go() -> tuple[store.TenantData | None, list[str]]:
        async with kit.worker.tenant_tx(tenant) as conn:
            rec = Recorder(conn)
            now = await conn.fetchval("SELECT now()")
            return await store.load_tenant(rec, tenant, now), rec.sql

    return kit.run(go())  # type: ignore[no-any-return]


def test_the_cadence_column_is_read_directly(kit: Kit) -> None:
    t = kit.tenant()
    declared, silent = kit.agent(t, tier=2), kit.agent(t, tier=3)
    kit.exe(
        "UPDATE sibyl.continuity_plan SET expected_cadence_s = 30 WHERE agent_id = $1", declared
    )
    data, sql = _load(kit, t)
    assert data is not None
    cadence = {a.agent_id: a.cadence_s for a in data.agents}
    assert cadence[declared] == 30 and cadence[silent] is None
    assert not [s for s in sql if "information_schema" in s], "no catalogue probe"
    assert any("cp.expected_cadence_s" in s for s in sql), "the agents statement selects it"
