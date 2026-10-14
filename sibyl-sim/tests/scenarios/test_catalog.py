"""The catalogue itself: every scenario parses, references the seeded world, and is gated the
way ROADMAP §3.4 and WAVE2 say (no PG needed)."""

from __future__ import annotations

from typing import Any

import pytest
from sibyl_control.cli import seed
from sibyl_sim.scenarios.load import load, load_catalog
from sibyl_sim.scenarios.model import AgentRef, ScenarioError

CATALOG = load_catalog()
WORLD = {t.slug: {a.slug: a for a in t.agents} for t in seed.WORLD}
PROVIDERS = {t.slug: {p.slug for p in t.providers} for t in seed.WORLD}


def test_all_33_scenarios_present_in_order() -> None:
    # S-01..S-28 the ML §8.2 catalogue; S-29/S-30 Action Gate (A-5); S-31 silent model swap
    # (drift, report-only); S-32 the quiet-agent outage (wave-3 detection gap); S-33 Sentinel
    assert list(CATALOG) == [f"S-{n:02d}" for n in range(1, 34)]


def test_smoke_set_matches_the_ci_shape() -> None:
    assert [s.id for s in CATALOG.values() if s.smoke] == ["S-01", "S-09", "S-21", "S-22"]
    for s in CATALOG.values():
        if s.smoke:
            assert not s.requires, f"{s.id}: a smoke scenario cannot be lane-gated"
            assert s.duration_s <= 200


def test_lane_gating_matches_wave2() -> None:
    gated = {sid for sid, s in CATALOG.items() if s.requires}
    assert gated == {
        "S-02",
        "S-03",
        "S-05",
        "S-06",
        "S-12",
        "S-15",
        "S-20",
        "S-23",
        "S-25",
        "S-26",
        "S-27",
        "S-28",
    }
    assert CATALOG["S-12"].phase == "1.5"
    runnable = set(CATALOG) - gated
    assert runnable == {
        "S-01",
        "S-04",
        "S-07",
        "S-08",
        "S-09",
        "S-10",
        "S-11",
        "S-13",
        "S-14",
        "S-16",
        "S-17",
        "S-18",
        "S-19",
        "S-21",
        "S-22",
        "S-24",
        "S-29",
        "S-30",
        "S-31",
        "S-32",
        "S-33",
    }


def test_action_gate_scenarios_gate_on_zero_unauthorised_actions() -> None:
    for sid in ("S-29", "S-30"):
        acts = [e for e in CATALOG[sid].expect if e.predicate == "actions"]
        assert acts and all(e.severity == "CRITICAL" for e in acts), sid
        assert all(e.args.get("forbid") or e.args.get("cap") for e in acts), sid
    covered = {k for e in CATALOG["S-29"].expect for k in (e.args.get("min") or {})}
    # both human-decision legs are real gates: a second human's approval, a timeout's deny
    assert {"blocked", "executed", "expired", "approved"} <= covered


def test_silent_swap_gates_on_both_drift_alerts() -> None:
    s = CATALOG["S-31"]
    drift = [e for e in s.expect if e.predicate == "detect"]
    assert {r for e in drift for r in e.args["rule"]} == {"model_change", "silent_drift"}
    assert not any(e.report_only for e in drift), "DRIFT merged: the gate is real"
    swap = min(c.at for c in s.chaos if c.patch.get("served_model"))
    # the baseline opens one eval window before t=0 and must freeze before the swap
    assert s.drift["baseline_min_span_s"] - s.drift["eval_window_s"] < swap
    assert not s.labels, "a label would arm the detected-rule recall gate"
    assert any(e.predicate == "no_action" and not e.report_only for e in s.expect)


def test_quiet_agent_outage_is_gated_and_quiet() -> None:
    s = CATALOG["S-32"]
    assert s.gate_class == "hard" and s.warmup_agents == {AgentRef("meridian", "kb-summarizer"): 0}
    assert any(e.predicate == "action" for e in s.expect)


def _refs(s: Any) -> list[AgentRef]:
    refs = [lab.agent for lab in s.labels]
    for exp in s.expect:
        if isinstance(exp.args.get("agent"), str):
            refs.append(AgentRef.parse(exp.args["agent"]))
    for step in s.chaos:
        refs += list(step.agents)
        if step.kind == "actor":
            refs.append(AgentRef.parse(step.target))
    for step in s.personas:
        if isinstance(step.args.get("agent"), str):
            refs.append(AgentRef.parse(step.args["agent"]))
    for tenant in s.tenants.values():
        refs += [AgentRef(tenant.slug, slug) for slug in tenant.agents]
    return refs


@pytest.mark.parametrize("sid", list(CATALOG))
def test_every_agent_and_provider_exists_in_the_seeded_world(sid: str) -> None:
    s = CATALOG[sid]
    for ref in _refs(s):
        assert ref.slug in WORLD.get(ref.tenant, {}), f"{sid}: {ref} is not seeded"
    for exp in s.expect:
        if "provider" in exp.args:
            tenant = exp.args.get("tenant", "meridian")
            assert exp.args["provider"] in PROVIDERS[tenant], f"{sid}: {exp.args['provider']}"


@pytest.mark.parametrize("sid", list(CATALOG))
def test_isolation_by_construction(sid: str) -> None:
    """ML §8.1 rule 7: chaos never targets northstar or sandbox."""
    for step in CATALOG[sid].chaos:
        assert all(r.tenant == "meridian" for r in step.agents), sid
        assert set(step.tenants) <= {"meridian"}, sid
        if step.kind in ("ingest", "actor"):
            assert step.target.startswith("meridian"), sid


@pytest.mark.parametrize("sid", list(CATALOG))
def test_labels_fall_inside_the_run_and_onsets_follow_chaos(sid: str) -> None:
    s = CATALOG[sid]
    first_chaos = min((c.at for c in s.chaos), default=None)
    for lab in s.labels:
        assert 0 <= lab.t <= s.duration_s, f"{sid}: label at {lab.t}"
        if lab.kind == "onset" and first_chaos is not None:
            assert lab.t >= first_chaos, f"{sid}: onset before any chaos"


def test_detect_scenarios_declare_a_gate_class() -> None:
    for s in CATALOG.values():
        if any(e.predicate == "detect" and "agent" in e.args for e in s.expect):
            assert s.gate_class in ("hard", "silent", "ramp", "none"), s.id


def test_load_by_id_and_unknown_id() -> None:
    assert load("s-09").id == "S-09"
    with pytest.raises(ScenarioError, match="unknown scenario"):
        load("S-99")


# B35: an outage fully masked by inline fallback starts no saga. Tier 2 has inline fallback to a
# vaulted alt provider by default, so a scenario gating a tier-2 failover opts its actor out of
# inline fallback (`X-Sibyl-Fallback: none`) and every other tier-2 onset it labels is masked.
@pytest.mark.parametrize("sid", ["S-07", "S-13", "S-20", "S-25", "S-28"])
def test_tier2_failover_gates_are_not_masked_by_inline_fallback(sid: str) -> None:
    s = CATALOG[sid]
    actions = [
        AgentRef.parse(e.args["agent"])
        for e in s.expect
        if e.predicate == "single_failover"
        or (e.predicate == "action" and e.args.get("to_state") == "failed_over")
    ]

    def unmasked(ref: AgentRef) -> bool:
        plan = s.tenant(ref.tenant)
        profile = s.profile(plan.agents.get(ref.slug, plan.default_profile))
        return profile.via == "sdk" or profile.fallback == "none"  # SDK calls skip the gateway

    for ref in actions:
        if WORLD[ref.tenant][ref.slug].tier == 2:
            assert unmasked(ref), f"{sid}: {ref} fails over only if its outage is not masked"
    for lab in s.labels:
        if lab.kind == "onset" and WORLD[lab.agent.tenant][lab.agent.slug].tier == 2:
            assert lab.masked != unmasked(lab.agent), f"{sid}: {lab.agent} masked label"
