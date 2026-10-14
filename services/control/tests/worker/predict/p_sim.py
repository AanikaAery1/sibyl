"""Deterministic PG17 driver: traffic -> rollup -> trend state -> scoring with lane P's
extensions -> sparse predictions + gate, on a simulated clock aligned to 5-minute buckets.

Each tick also records what the console would see (fired rules, 15 m band, confidence), so the
scenario tests can measure lead times: from the first leading signal / first band rise to the
failure onset the scenario injected.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from sibyl_control.core.settings import Settings
from sibyl_control.worker.predict import EXTENSIONS
from sibyl_control.worker.predict.outcomes import fill_outcomes
from sibyl_control.worker.predict.writer import PredictResult, write_predictions
from sibyl_control.worker.rollup.pipeline import rollup_tenant
from sibyl_control.worker.rollup.trend import advance_trend_state
from sibyl_control.worker.scoring.extensions import Extensions
from sibyl_control.worker.scoring.runner import ScoreResult, score_tenant

SETTLE_S = 30.0
Traffic = Callable[[datetime, datetime], Sequence[dict[str, Any]]]


def bucket_floor(ts: datetime, seconds: int = 300) -> datetime:
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, UTC)


def request(
    agent: UUID,
    ts: datetime,
    *,
    model: str = "large-1",
    latency_ms: int = 400,
    status: str = "ok",
    error_class: str | None = None,
    http_status: int = 200,
    cost: Decimal = Decimal("0.0001"),
    headroom: float | None = None,
    provider: str = "provider-one",
) -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    if headroom is not None:
        attrs["ratelimit"] = {"headroom": round(headroom, 4)}
    return {
        "agent_id": agent,
        "ts": ts,
        "provider": provider,
        "model": model,
        "status": status,
        "error_class": error_class,
        "http_status": http_status,
        "latency_ms": latency_ms,
        "ttfb_ms": max(1, latency_ms // 4),
        "tokens_in": 100,
        "tokens_out": 0 if status == "error" else 50,
        "cost_usd": cost,
        "attrs": attrs,
    }


def spread(lo: datetime, hi: datetime, n: int) -> list[datetime]:
    step = (hi - lo) / max(n, 1)
    return [lo + step * i + timedelta(milliseconds=1) for i in range(n)]


@dataclass
class Point:
    at: datetime
    fired: frozenset[str]
    band: str
    score: int
    h15: str
    conf15: str
    rules15: tuple[str, ...]
    h1h: str
    h24: str


@dataclass
class PSim:
    kit: Any
    tenant: UUID
    minutes: int
    tick_s: int = 10
    requester: Any = None
    extensions: Extensions | None = EXTENSIONS  # None: whatever is registered
    settings: Settings = field(default_factory=lambda: Settings(predicted_automation_band="0.90"))
    now: datetime = field(init=False)
    points: dict[UUID, list[Point]] = field(default_factory=dict)
    scores: list[ScoreResult] = field(default_factory=list)
    predictions: list[PredictResult] = field(default_factory=list)

    def __post_init__(self) -> None:
        start = bucket_floor(datetime.now(UTC) - timedelta(minutes=self.minutes + 6))
        self.now = start
        self.kit.ensure_partitions(
            "prediction", start - timedelta(days=1), start + timedelta(days=2)
        )

    @property
    def tick(self) -> timedelta:
        return timedelta(seconds=self.tick_s)

    def step(self, traffic: Traffic | None = None) -> ScoreResult:
        lo, hi = self.now, self.now + self.tick
        self.now = hi
        rows = list(traffic(lo, hi)) if traffic else []
        if rows:
            self.kit.events(self.tenant, rows)
        result = self.kit.run(self._tick(len(rows)))
        self._record(result)
        return result  # type: ignore[no-any-return]

    def run(self, seconds: int, traffic: Traffic | None = None) -> None:
        for _ in range(max(1, seconds // self.tick_s)):
            self.step(traffic)

    async def _tick(self, expected: int) -> ScoreResult:
        consumed = 0
        deadline = asyncio.get_running_loop().time() + SETTLE_S
        while True:
            async with self.kit.worker.tenant_tx(self.tenant) as conn:
                res = await rollup_tenant(conn, self.tenant, now=self.now)
                if res.closed_5m:
                    await advance_trend_state(conn, self.tenant, res.closed_5m)
                consumed += res.events
            if consumed >= expected or asyncio.get_running_loop().time() > deadline:
                break
            await asyncio.sleep(0.05)
        async with self.kit.worker.tenant_tx(self.tenant) as conn:
            score = await score_tenant(conn, self.tenant, now=self.now, extensions=self.extensions)
        async with self.kit.worker.tenant_tx(self.tenant) as conn:
            pred = await write_predictions(
                conn, self.tenant, self.now, settings=self.settings, requester=self.requester
            )
            await fill_outcomes(conn, self.tenant, self.now)
        self.scores.append(score)
        self.predictions.append(pred)
        return score

    def _record(self, result: ScoreResult) -> None:
        for agent, ev in result.evaluations.items():
            h = ev.horizons or {}
            m15 = h.get("15m") or {}
            self.points.setdefault(agent, []).append(
                Point(
                    self.now,
                    ev.fired,
                    ev.band,
                    ev.score,
                    m15.get("probability_band", "0.05"),
                    m15.get("confidence", "low"),
                    tuple(m15.get("contributing_rules") or ()),
                    (h.get("1h") or {}).get("probability_band", "0.05"),
                    (h.get("24h") or {}).get("probability_band", "0.05"),
                )
            )

    # ------------------------------------------------------------------ measurements

    def first(self, agent: UUID, pred: Callable[[Point], bool]) -> datetime | None:
        return next((p.at for p in self.points.get(agent, []) if pred(p)), None)

    def fired_at(self, agent: UUID, code: str) -> datetime | None:
        return self.first(agent, lambda p: code in p.fired)

    def band_rise_at(self, agent: UUID, key: str = "15m", floor: str = "0.25") -> datetime | None:
        order = ("0.05", "0.25", "0.60", "0.90")
        attr = {"15m": "h15", "1h": "h1h", "24h": "h24"}[key]
        return self.first(agent, lambda p: order.index(getattr(p, attr)) >= order.index(floor))

    def gate_calls(self) -> list[Any]:
        return [c for r in self.predictions for c in r.gate_calls]

    # ------------------------------------------------------------------ setup helpers

    def provider_status(self, provider: UUID, status: str) -> None:
        self.kit.in_tenant(
            self.tenant,
            "INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status,"
            " observed_at)"
            " VALUES ($1, $2, 'status_feed', $3, $4)",
            self.tenant,
            provider,
            status,
            self.now,
        )

    def seed_spend(self, agent: UUID, usd: Decimal) -> None:
        """Month-to-date spend from earlier this month (one event an hour before the start)."""
        at = max(self.now - timedelta(hours=1), self.now.replace(day=1, hour=0, minute=1))
        self.kit.events(self.tenant, [request(agent, at, cost=usd)])
        self.kit.run(self._drain(1, at + timedelta(minutes=10)))

    async def _drain(self, expected: int, now: datetime) -> None:
        consumed = 0
        deadline = asyncio.get_running_loop().time() + SETTLE_S
        while consumed < expected and asyncio.get_running_loop().time() < deadline:
            async with self.kit.worker.tenant_tx(self.tenant) as conn:
                consumed += (await rollup_tenant(conn, self.tenant, now=now)).events
            await asyncio.sleep(0.05)

    def predictions_for(self, agent: UUID, horizon_s: int = 900) -> list[Any]:
        return self.kit.q(
            "SELECT * FROM sibyl.prediction WHERE tenant_id = $1 AND agent_id = $2 AND horizon_s ="
            " $3"
            " ORDER BY predicted_at",
            self.tenant,
            agent,
            horizon_s,
        )

    def open_release_gate(self) -> None:
        """Open the D36 release gate the only way it opens (B20): the deployment setting. A
        tenant scoring config asking for ``"0.60"`` changes nothing (see ``test_gate``)."""
        self.settings = Settings(predicted_automation_band="0.60")


class FakeSaga:
    """Lane S's ``request_predicted_failover`` stand-in: records every call."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        conn: Any,
        tenant_id: UUID,
        agent_id: UUID,
        prediction_id: UUID,
        horizon: str,
        band: str,
        confidence: str,
        *,
        mode: str,
        settings: Settings,
    ) -> UUID | None:
        exists = await conn.fetchval(
            "SELECT count(*) FROM sibyl.prediction WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            prediction_id,
        )
        assert exists == 1, "the prediction row is visible in the caller's transaction"
        self.calls.append(
            {
                "agent_id": agent_id,
                "prediction_id": prediction_id,
                "horizon": horizon,
                "band": band,
                "confidence": confidence,
                "mode": mode,
                "automation_band": settings.predicted_automation_band,
            }
        )
        return None
