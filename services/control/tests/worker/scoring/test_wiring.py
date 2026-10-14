"""Loop wiring (worker/loops.py targets) and lane P's extension points, end to end on PG17."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sibyl_control.worker.loops import LOOPS, LoopContext, resolve_tick
from sibyl_control.worker.scoring.extensions import (
    Extensions,
    register,
    registered,
    reset,
)
from sibyl_control.worker.scoring.rules import RuleOutcome

from .h_sim import Sim
from .h_testkit import Kit, calls

PER_TICK = 6


def healthy(agent: Any) -> Any:
    return lambda ts: calls(agent, ts, PER_TICK, spread_s=9.5)


def test_pre_registered_targets_resolve_to_lane_h_ticks() -> None:
    for name in ("rollup", "scoring", "status_poller"):
        spec = next(s for s in LOOPS if s.name == name)
        assert spec.owner == "H"
        assert resolve_tick(spec) is not None, f"{spec.target} is implemented"


def test_scoring_loop_tick_scores_every_tenant(kit: Kit) -> None:
    tick = resolve_tick(next(s for s in LOOPS if s.name == "scoring"))
    assert tick is not None
    t = kit.tenant()
    a = kit.agent(t)
    kit.run(tick(LoopContext("scoring", kit.worker, None, logging.getLogger("t"))))
    rows = kit.q("SELECT write_reason FROM sibyl.health_snapshot WHERE agent_id = $1", a)
    assert [r["write_reason"] for r in rows] == ["change"], "first snapshot for an idle agent"


def test_register_keeps_existing_hooks() -> None:
    def leading(*_: Any) -> list[RuleOutcome]:
        return []

    def horizons(*_: Any) -> tuple[dict[str, Any], None]:
        return {}, None

    # another module in this process (lane P's wiring) may have registered hooks already:
    # start from an empty registry and put them back afterwards (order-independent, xdist)
    before = registered()
    reset()
    try:
        register(leading=leading)
        register(horizons=horizons)
        assert registered() == Extensions(leading=leading, horizons=horizons)
        reset()
        assert registered() == Extensions()
    finally:
        reset()
        register(leading=before.leading, horizons=before.horizons, prepare=before.prepare)
    assert registered() == before


def test_lane_p_extensions_plug_in_leading_factors_and_horizons(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    sim = Sim(kit, t)
    sim.run(6, healthy(a))
    band = {"value": "0.05"}

    def leading(inputs: Any, config: Any, now: datetime) -> list[RuleOutcome]:
        sev = 1.0 if band["value"] == "0.60" else 0.0
        return [
            RuleOutcome(
                "fallback_pressure",
                "leading",
                True,
                sev,
                0.5,
                0.25,
                explanation="inline fallback share 50%",
                evidence="/api/v1/events",
            ),
            RuleOutcome(
                "error_trend",
                "leading",
                True,
                sev,
                0.1,
                0.1,
                explanation="errors rising",
                evidence="/api/v1/events",
            ),
        ]

    def horizons(inputs: Any, ev: Any, config: Any, now: datetime) -> tuple[dict, str | None]:
        doc = {"probability_band": band["value"], "source": "rules/v1", "confidence": "medium"}
        mode = "provider_outage" if band["value"] == "0.60" else None
        return {"15m": doc, "1h": doc, "24h": doc}, mode

    sim.extensions = Extensions(leading=leading, horizons=horizons)
    start = sim.now
    sim.run(2, healthy(a))
    band["value"] = "0.60"
    tail = sim.run(14, healthy(a))
    rows = [
        dict(r)
        for r in kit.q(
            "SELECT * FROM sibyl.health_snapshot WHERE agent_id = $1 AND evaluated_at >= $2 "
            "ORDER BY evaluated_at",
            a,
            start,
        )
    ]
    changed = [r for r in rows if r["horizons"].get("15m", {}).get("probability_band") == "0.60"]
    assert changed and changed[0]["predicted_failure_mode"] == "provider_outage"
    assert changed[0]["write_reason"] == "change", "a horizon band change forces a write"
    bands = sim.bands(a, tail)
    assert bands[10] == "healthy" and bands[11] == "watch", "score 70; tier 3 leading: 12 ticks"
    factors = tail[-1].evaluations[a].factors
    fp = [f for f in factors if f["rule"] == "fallback_pressure"]
    assert fp and fp[0]["kind"] == "leading" and fp[0]["penalty"] == 20
