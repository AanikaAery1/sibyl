"""Traffic plans are pure functions of (seed, scenario, agent, profile) (qa-expert §1.1 rule 5)."""

from __future__ import annotations

import math

from sibyl_sim.actors.traffic import Arrival, plan_arrivals, rng_for, stable_id
from sibyl_sim.scenarios.model import AgentRef, Profile

AGENT = AgentRef("meridian", "kb-summarizer")


def test_same_inputs_same_plan() -> None:
    p = Profile("busy", rps=0.5)
    a = plan_arrivals(7, "S-01", AGENT, p, duration_s=120)
    b = plan_arrivals(7, "S-01", AGENT, p, duration_s=120)
    assert a == b and a
    assert all(isinstance(x, Arrival) for x in a)
    assert [x.n for x in a] == list(range(len(a)))
    assert all(0 <= x.t < 120 for x in a)
    assert all(a[i].t < a[i + 1].t for i in range(len(a) - 1))


def test_seed_scenario_and_agent_each_change_the_plan() -> None:
    p = Profile("busy", rps=0.5)
    base = plan_arrivals(7, "S-01", AGENT, p, duration_s=120)
    assert plan_arrivals(8, "S-01", AGENT, p, duration_s=120) != base
    assert plan_arrivals(7, "S-02", AGENT, p, duration_s=120) != base
    assert plan_arrivals(7, "S-01", AgentRef("meridian", "faq-bot"), p, duration_s=120) != base


def test_rate_is_respected_on_average() -> None:
    p = Profile("hot", rps=2.0)
    arrivals = plan_arrivals(1, "S-24", AGENT, p, duration_s=600)
    assert math.isclose(len(arrivals) / 600, 2.0, rel_tol=0.1)


def test_zero_rate_is_silent_and_first_arrival_is_jittered() -> None:
    assert plan_arrivals(1, "S-01", AGENT, Profile("idle", rps=0.0), duration_s=60) == []
    starts = {
        plan_arrivals(1, "S-01", AgentRef("meridian", s), Profile("p", rps=1), duration_s=10)[0].t
        for s in ("a", "b", "c", "d")
    }
    assert len(starts) == 4  # agents do not fire in lockstep


def test_request_ids_and_prompts_are_deterministic() -> None:
    p = Profile("busy", rps=0.5)
    a = plan_arrivals(7, "S-01", AGENT, p, duration_s=60)[0]
    b = plan_arrivals(7, "S-01", AGENT, p, duration_s=60)[0]
    assert a.request_id == b.request_id == stable_id(7, "S-01", AGENT, 0)
    assert a.prompt == b.prompt and "kb-summarizer" not in a.prompt  # no identity in content
    assert len(a.request_id) == 36


def test_rng_streams_are_independent_of_call_order() -> None:
    x = rng_for(1, "S-01", AGENT, "arrivals").random()
    rng_for(1, "S-01", AgentRef("meridian", "other"), "arrivals").random()
    assert rng_for(1, "S-01", AGENT, "arrivals").random() == x
