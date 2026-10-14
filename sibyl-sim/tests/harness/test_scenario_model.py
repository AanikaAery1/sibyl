"""Scenario DSL: parsing, validation, agent references and chaos compilation."""

from __future__ import annotations

import pytest
from sibyl_sim.scenarios.model import (
    LANES,
    AgentRef,
    ScenarioError,
    parse_scenario,
)

MINIMAL = {
    "id": "S-99",
    "title": "test",
    "duration_s": 60,
    "tenants": {"meridian": {"agents": {"kb-summarizer": "busy"}}},
    "chaos": [{"at": 10, "double": "openai-stub", "set": {"outage": True}}],
    "labels": [{"agent": "kb-summarizer", "kind": "onset", "t": 10, "failure_mode": "outage"}],
    "expect": [{"detect": {"agent": "kb-summarizer", "rule": "consecutive_failures", "by_t": 70}}],
}


def test_minimal_scenario_parses_with_defaults() -> None:
    s = parse_scenario(MINIMAL)
    assert s.id == "S-99" and s.seed == 20261011 and s.duration_s == 60
    assert s.requires == () and not s.smoke
    assert s.agents_with_profile("busy") == (AgentRef("meridian", "kb-summarizer"),)
    # northstar always runs the steady script (ML §8.1 isolation by construction)
    assert s.tenant("northstar").default_profile == "steady"
    assert s.tenant("meridian").default_profile == "steady"
    assert s.labels[0].agent == AgentRef("meridian", "kb-summarizer")
    exp = s.expect[0]
    assert exp.predicate == "detect" and exp.args["rule"] == "consecutive_failures"
    assert exp.requires == ()


def test_budgets_name_agents_and_money() -> None:
    assert parse_scenario(MINIMAL).budgets == {}
    s = parse_scenario(
        {**MINIMAL, "budgets": {"kb-summarizer": "4.4100", "northstar/x": "12.0000"}}
    )
    assert s.budgets == {
        AgentRef("meridian", "kb-summarizer"): "4.4100",
        AgentRef("northstar", "x"): "12.0000",
    }


def test_agent_refs_accept_tenant_prefix() -> None:
    assert AgentRef.parse("northstar/claims-coder") == AgentRef("northstar", "claims-coder")
    assert AgentRef.parse("faq-bot") == AgentRef("meridian", "faq-bot")
    assert str(AgentRef("northstar", "x")) == "northstar/x"
    with pytest.raises(ScenarioError):
        AgentRef.parse("a/b/c")


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"id": "X-1"}, "id"),
        ({"duration_s": 0}, "duration_s"),
        ({"requires": ["Q"]}, "requires"),
        ({"expect": [{"nonsense": {}}]}, "unknown predicate"),
        ({"expect": [{"detect": {}, "quiet": {}}]}, "exactly one predicate"),
        ({"chaos": [{"at": 999, "double": "openai-stub", "set": {}}]}, "after the end"),
        ({"chaos": [{"at": 1, "double": "nope", "set": {}}]}, "unknown double"),
        ({"chaos": [{"at": 1}]}, "target"),
        ({"labels": [{"agent": "x", "kind": "boom", "t": 1}]}, "kind"),
        ({"tenants": {"elsewhere": {}}}, "tenant"),
        ({"personas": [{"at": 1, "persona": "operator", "do": "dance"}]}, "verb"),
        ({"budgets": {"kb-summarizer": 4.41}}, "budgets"),
        ({"budgets": {"kb-summarizer": "4.41"}}, "budgets"),
        ({"budgets": {"kb-summarizer": "0.0000"}}, "budgets"),
        ({"budgets": ["kb-summarizer"]}, "budgets"),
    ],
)
def test_invalid_scenarios_name_the_problem(patch: dict, message: str) -> None:
    with pytest.raises(ScenarioError, match=message):
        parse_scenario({**MINIMAL, **patch})


def test_expectation_level_requires_and_severity() -> None:
    s = parse_scenario(
        {
            **MINIMAL,
            "expect": [
                {
                    "action": {"agent": "kb-summarizer", "to_state": "failed_over"},
                    "requires": ["S"],
                },
                {"isolated": {"tenant": "northstar"}},
            ],
        }
    )
    assert s.expect[0].requires == ("S",)
    assert s.expect[1].severity == "CRITICAL"  # isolation is always critical (ML §8.3)
    assert s.lanes_needed() == frozenset({"S"})
    assert set(LANES) == {"S", "P", "U"}


def test_scenario_requires_union_includes_personas() -> None:
    s = parse_scenario(
        {
            **MINIMAL,
            "requires": ["P"],
            "personas": [{"at": 30, "persona": "operator", "do": "close_alert", "verdict": "tp"}],
        }
    )
    assert s.requires == ("P",)
    assert s.personas[0].requires == ("P",)  # close_alert needs the alerts lane
    assert s.lanes_needed() == frozenset({"P"})


def test_chaos_targets_compile_to_admin_calls() -> None:
    s = parse_scenario(
        {
            **MINIMAL,
            "chaos": [
                {
                    "at": 5,
                    "double": "openai-stub",
                    "set": {"truncation_rate": 0.5},
                    "agents": ["kb-summarizer"],
                },
                {"at": 6, "status": "openai", "set": {"mode": "lies"}},
                {"at": 7, "ingest": "meridian", "pause_s": 90},
                {"at": 8, "actor": "meridian/faq-bot", "set": {"silent_s": 240}},
                {"at": 9, "double": "openai-stub", "reset": True},
            ],
        }
    )
    kinds = [(c.kind, c.target) for c in s.chaos]
    assert kinds == [
        ("double", "openai-stub"),
        ("status", "openai"),
        ("ingest", "meridian"),
        ("actor", "meridian/faq-bot"),
        ("double", "openai-stub"),
    ]
    assert s.chaos[0].agents == (AgentRef("meridian", "kb-summarizer"),)
    assert s.chaos[4].reset


def test_chaos_is_sorted_by_time_and_stable() -> None:
    s = parse_scenario(
        {
            **MINIMAL,
            "chaos": [
                {"at": 20, "double": "openai-stub", "set": {"outage": False}},
                {"at": 10, "double": "openai-stub", "set": {"outage": True}},
                {"at": 10, "status": "openai", "set": {"mode": "truthful"}},
            ],
        }
    )
    assert [(c.at, c.kind) for c in s.chaos] == [(10, "double"), (10, "status"), (20, "double")]


def test_repeat_expands_flapping_timelines() -> None:
    s = parse_scenario(
        {
            **MINIMAL,
            "duration_s": 1500,
            "chaos": [
                {
                    "at": 60,
                    "double": "openai-stub",
                    "set": {"outage": True},
                    "repeat": {
                        "every_s": 240,
                        "times": 3,
                        "then_after_s": 120,
                        "then": {"outage": False},
                    },
                }
            ],
        }
    )
    timeline = [(c.at, c.patch.get("outage")) for c in s.chaos]
    assert timeline == [
        (60, True),
        (180, False),
        (300, True),
        (420, False),
        (540, True),
        (660, False),
    ]


def test_profile_fallback_header_opts_a_client_out_of_inline_fallback() -> None:
    """B35: a masked outage starts no saga, so a scenario gating a tier-2 failover sends
    `X-Sibyl-Fallback: none` (API §3, a documented per-request opt-out) from its actor."""
    raw = {**MINIMAL, "profiles": {"busy_no_inline": {"rps": 0.5, "fallback": "none"}}}
    raw["tenants"] = {"meridian": {"agents": {"kb-summarizer": "busy_no_inline"}}}
    s = parse_scenario(raw)
    assert s.profile("busy_no_inline").fallback == "none"
    assert s.profile("busy").fallback is None
    with pytest.raises(ScenarioError, match="fallback"):
        parse_scenario({**MINIMAL, "profiles": {"x": {"fallback": "never"}}})
