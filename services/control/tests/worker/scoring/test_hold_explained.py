"""A band held by recovery hysteresis after every rule has cleared is still explained (ML §3.6).

S-18: R9 ``heartbeat_missing`` clears after 3 clean ticks (hysteresis out) while a tier-1 band
needs 18 clean ticks to improve, so for 15 ticks nothing fires and the score is 100 while the
band stays ``watch``. Each such snapshot must still name the band and the rule that put it there.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.engine import EngineState, Evaluation, evaluate

from .h_inputs import NOW, inputs

CFG = EngineConfig.from_seed(load(Path(__file__).resolve().parents[5] / "rules/v1/defaults.yaml"))
TICK = 10


def _explained(ev: Evaluation) -> bool:
    if ev.band == "healthy" or any(f["penalty"] > 0 for f in ev.factors):
        return True
    return any(
        f["direction"] == "equals"
        and f["value"] == ev.band
        and f["explanation"]
        and not str(f["rule"]).startswith("_")
        for f in ev.factors
    )


def test_band_held_after_r9_clears_names_the_rule() -> None:
    base = replace(inputs(tier=1, req=30), cadence_s=30)
    state: EngineState | None = None
    evs: list[Evaluation] = []
    for i in range(40):
        now = NOW + timedelta(seconds=i * TICK)
        silent = 3 <= i < 12
        last = now - timedelta(seconds=120) if silent else now - timedelta(seconds=2)
        ev = evaluate(replace(base, last_request_at=last), state, CFG, now)
        state = ev.state
        evs.append(ev)
    assert any(e.band == "watch" for e in evs), "R9 takes the tier-1 band to watch"
    held = [e for e in evs if e.band == "watch" and not e.fired]
    assert held, "the scenario reproduces a watch band with nothing firing"
    for ev in evs:
        assert _explained(ev), (ev.band, ev.score, ev.factors)
    assert all(any(f["rule"] == "heartbeat_missing" for f in e.factors) for e in held)
    assert evs[-1].band == "healthy"


def test_held_rules_survive_the_bookkeeping_round_trip() -> None:
    state = EngineState(band="watch", held_by=("heartbeat_missing",))
    doc = state.to_bookkeeping()
    assert EngineState.from_bookkeeping(doc).held_by == ("heartbeat_missing",)
