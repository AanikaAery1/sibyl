"""S-16 status page that lies (ML §8.2, qa-expert §2): the band a status-only outage reaches.

The provider's page says ``major_outage`` while the agent's own calls are clean. R4 still fires
(the provider-scope alert is the status page's own row) and still costs points, but status alone
must not take a tier-2 agent below ``watch`` or put any tier into the detected-failure path.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.engine import Evaluation, evaluate
from sibyl_control.worker.scoring.features import AgentInputs

from .h_inputs import NOW, inputs

CFG = EngineConfig.from_seed(load(Path(__file__).resolve().parents[5] / "rules/v1/defaults.yaml"))
TICK = 10


def _settle(inp: AgentInputs, ticks: int = 12) -> Evaluation:
    state, ev = None, None
    for i in range(ticks):
        ev = evaluate(inp, state, CFG, NOW + timedelta(seconds=i * TICK))
        state = ev.state
    assert ev is not None
    return ev


def test_tier2_status_only_outage_stops_at_watch() -> None:
    lie = replace(inputs(tier=2, req=60), provider_status="major_outage", provider_status_age_s=5)
    ev = _settle(lie)
    assert ev.band == "watch" and ev.floor is None
    r4 = [f for f in ev.factors if f["rule"] == "provider_status"]
    assert r4 and r4[0]["penalty"] > 0 and r4[0]["kind"] == "leading", "penalty applied"


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_status_only_outage_never_fails_an_agent(tier: int) -> None:
    lie = replace(
        inputs(tier=tier, req=60), provider_status="major_outage", provider_status_age_s=5
    )
    ev = _settle(lie)
    assert ev.band != "failed" and ev.floor is None


def test_corroborated_outage_still_fails() -> None:
    real = replace(
        inputs(tier=2, req=60, err=40, server_errors=40),
        provider_status="major_outage",
        provider_status_age_s=5,
        provider_error_rate_fleet=0.6,
    )
    assert _settle(real).band == "failed"
