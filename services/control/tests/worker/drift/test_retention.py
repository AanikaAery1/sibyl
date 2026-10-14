"""Ruling B24: superseded drift baselines are purged 30 days after supersession by the drift
loop's retention (their remaining reports first); recent and current baselines stay."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sibyl_drift_kit import Traffic, make_traffic
from sibyl_lane_s_world import SWorld


@pytest.fixture(scope="module")
def traffic(sworld: SWorld) -> Traffic:
    return make_traffic(sworld)


def _superseded(sworld: SWorld, agent: object, model: str, age: timedelta) -> object:
    return sworld.val(
        "INSERT INTO sibyl.drift_baseline (tenant_id, agent_id, provider, model, state,"
        " window_start, superseded_at) VALUES ($1, $2, 'openai', $3, 'superseded',"
        " now() - interval '60 days', now() - $4::interval) RETURNING id",
        sworld.a.id,
        agent,
        model,
        age,
    )


def test_superseded_baselines_are_purged_after_30_days(traffic: Traffic, sworld: SWorld) -> None:
    agent = traffic.agent()
    old = _superseded(sworld, agent, "gpt-4o", timedelta(days=31))
    recent = _superseded(sworld, agent, "gpt-4o", timedelta(days=5))
    sworld.admin.execute(
        "INSERT INTO sibyl.drift_report (tenant_id, baseline_id, agent_id, provider, model,"
        " evaluated_at, window_start, window_end, sample_count, verdict, behaviour_evaluated,"
        " features) VALUES ($1, $2, $3, 'openai', 'gpt-4o', now() - interval '20 days',"
        " now() - interval '21 days', now() - interval '20 days', 1, 'none', false, '[]')",
        sworld.a.id,
        old,
        agent,
    )
    result = traffic.run(traffic.now())
    assert result.purged_baselines >= 1
    left = {b["id"] for b in traffic.baselines(agent)}
    assert old not in left and recent in left
    assert traffic.reports(agent) == []
    assert traffic.run(traffic.now()).purged_baselines == 0
