"""Drive synthetic traffic -> rollup -> scoring on a simulated 10 s clock."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sibyl_control.core.outbox import OutboxMessage
from sibyl_control.worker.rollup.pipeline import rollup_tenant
from sibyl_control.worker.scoring.extensions import Extensions
from sibyl_control.worker.scoring.runner import ScoreResult, score_tenant

from .h_testkit import Kit

TICK = timedelta(seconds=10)
SETTLE_S = 30.0


async def settle(kit: Kit, tenant: UUID, expected: int, *, now: datetime | None = None) -> int:
    """Roll up until ``expected`` new events are consumed.

    ``sibyl.commit_horizon()`` is cluster-wide: another lane's open transaction on the shared
    dev cluster holds it back, and the rollup rightly waits (R60). Tests wait with it.
    """
    consumed = 0
    deadline = asyncio.get_running_loop().time() + SETTLE_S
    while True:
        async with kit.worker.tenant_tx(tenant) as conn:
            consumed += (await rollup_tenant(conn, tenant, now=now)).events
        if consumed >= expected or asyncio.get_running_loop().time() > deadline:
            return consumed
        await asyncio.sleep(0.05)


class RecordingOutbox:
    """Writes through to the real outbox and keeps what it wrote for assertions."""

    def __init__(self) -> None:
        from sibyl_control.core.outbox import PgOutboxWriter

        self.inner = PgOutboxWriter()
        self.messages: list[OutboxMessage] = []

    async def emit(self, conn: Any, tenant_id: UUID, message: OutboxMessage) -> None:
        self.messages.append(message)
        await self.inner.emit(conn, tenant_id, message)

    def of(self, event_type: str) -> list[OutboxMessage]:
        return [m for m in self.messages if m.event_type == event_type]


@dataclass
class Sim:
    kit: Kit
    tenant: UUID
    now: datetime = field(
        default_factory=lambda: datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=40)
    )
    outbox: RecordingOutbox = field(default_factory=RecordingOutbox)
    results: list[ScoreResult] = field(default_factory=list)
    extensions: Extensions = field(default_factory=Extensions)

    def tick(
        self, traffic: Callable[[datetime], Sequence[dict[str, Any]]] | None = None
    ) -> ScoreResult:
        pending = 0
        if traffic is not None:
            rows = traffic(self.now - TICK)
            if rows:
                self.kit.events(self.tenant, rows)
                pending = len(rows)

        async def go() -> ScoreResult:
            await settle(self.kit, self.tenant, pending, now=self.now)
            async with self.kit.worker.tenant_tx(self.tenant) as conn:
                return await score_tenant(
                    conn, self.tenant, now=self.now, extensions=self.extensions, outbox=self.outbox
                )

        result = self.kit.run(go())
        self.results.append(result)
        self.now += TICK
        return result  # type: ignore[no-any-return]

    def run(
        self, n: int, traffic: Callable[[datetime], Sequence[dict[str, Any]]] | None = None
    ) -> list[ScoreResult]:
        return [self.tick(traffic) for _ in range(n)]

    def bands(self, agent: UUID, results: Sequence[ScoreResult] | None = None) -> list[str]:
        return [r.evaluations[agent].band for r in (results or self.results)]

    def alerts(self, agent: UUID | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT a.*, r.code FROM sibyl.alert a JOIN sibyl.alert_rule r ON r.tenant_id = "
            "a.tenant_id AND r.id = a.rule_id WHERE a.tenant_id = $1"
        )
        rows = self.kit.q(sql + " ORDER BY a.first_fired_at, r.code", self.tenant)
        return [dict(r) for r in rows if agent is None or r["agent_id"] == agent]
