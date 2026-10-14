"""Oracle predicates (qa-expert §1.5): one per `expect` key, naming the first offending object."""

from __future__ import annotations

from typing import Any

from sibyl_sim.oracle.predicates import PREDICATE_FUNCS, evaluate, evaluate_all
from sibyl_sim.oracle.record import CrossRead, RunRecord, SseEvent
from sibyl_sim.scenarios.model import PREDICATES, Expectation, parse_scenario

from .conftest import BILL, CLAIMS, FAQ, IDS, KB, OPENAI_M, M, N, factor, fired, health, transition


def scenario(*expect: dict[str, Any], **extra: Any) -> Any:
    raw = {
        "id": "S-99",
        "title": "t",
        "duration_s": 120,
        "tenants": {M: {"agents": {"kb-summarizer": "busy"}}},
        "labels": [{"agent": "kb-summarizer", "kind": "onset", "t": 20}],
        "expect": list(expect),
    } | extra
    return parse_scenario(raw)


def run(rec: RunRecord, exp: dict[str, Any], **extra: Any) -> Any:
    s = scenario(exp, **extra)
    return evaluate(s.expect[0], rec, s)


def test_every_catalogue_predicate_has_an_implementation() -> None:
    assert set(PREDICATES) == set(PREDICATE_FUNCS)


def test_detect_measures_ttd_from_the_onset_label(record: RunRecord) -> None:
    record.sse.append(fired(31.5, M, KB, "consecutive_failures"))
    v = run(record, {"detect": {"agent": "kb-summarizer", "rule": "R3", "by_t": 60}})
    assert v.status == "pass" and v.measured["ttd_s"] == 11.5 and v.measured["tier"] == 3
    late = run(record, {"detect": {"agent": "kb-summarizer", "rule": "R3", "by_t": 30}})
    assert late.status == "fail" and "31.5" in late.detail


def test_detect_deadline_scales_with_measured_tick_lag(record: RunRecord) -> None:
    """B38: the deadline stretches after the onset (t=20) by the measured dilation, plus the
    actors' measured send lateness; the raw ttd is still reported."""
    from sibyl_sim.oracle.timing import Timing

    record.sse.append(fired(70, M, KB, "consecutive_failures"))
    exp = {"detect": {"agent": "kb-summarizer", "rule": "R3", "by_t": 60}}
    assert run(record, exp).status == "fail"
    record.timing = Timing(dilation=1.25, actor_late_s=2.0)  # 20 + 40 x 1.25 + 2 = 72
    v = run(record, exp)
    assert v.status == "pass", v.detail
    assert v.measured["deadline_t"] == 72.0 and v.measured["ttd_s"] == 50.0
    record.timing = Timing(dilation=1.1)  # 64: still late
    late = run(record, exp)
    assert late.status == "fail" and "deadline 64.0" in late.detail


def test_detect_fails_when_only_another_agent_fired(record: RunRecord) -> None:
    record.sse.append(fired(25, M, FAQ, "consecutive_failures"))
    v = run(record, {"detect": {"agent": "kb-summarizer", "rule": "consecutive_failures"}})
    assert v.status == "fail" and "no alert.fired" in v.detail


def test_detect_any_of_several_rules(record: RunRecord) -> None:
    record.sse.append(fired(40, M, KB, "error_rate"))
    v = run(record, {"detect": {"agent": "kb-summarizer", "rule": ["R3", "R1"]}})
    assert v.status == "pass" and v.measured["rule"] == "error_rate"


def test_no_alert_rule_scoped(record: RunRecord) -> None:
    record.sse.append(fired(40, M, KB, "truncation_share"))
    assert run(record, {"no_alert": {"agent": "kb-summarizer", "rule": "R1"}}).status == "pass"
    v = run(record, {"no_alert": {"agent": "kb-summarizer", "rule": "R7"}})
    assert v.status == "fail" and v.offending["rule"] == "truncation_share"


def test_quiet_tenant_and_severity_ceiling(record: RunRecord) -> None:
    assert run(record, {"quiet": {"tenant": N}}).status == "pass"
    record.sse.append(fired(50, N, CLAIMS, "error_rate", severity="info"))
    assert run(record, {"quiet": {"tenant": N, "max_severity": "info"}}).status == "pass"
    record.sse.append(fired(51, N, CLAIMS, "error_rate", severity="warning"))
    v = run(record, {"quiet": {"tenant": N}})
    assert v.status == "fail" and v.severity == "CRITICAL"
    record.sse.append(SseEvent(52, M, "provider_incident.opened", {"provider_id": str(OPENAI_M)}))
    assert run(record, {"quiet": {"tenant": M}}).status == "fail"


def test_isolated_catches_foreign_agents_events_and_reads(record: RunRecord) -> None:
    assert run(record, {"isolated": {"tenant": M}}).status == "pass"
    record.listed_agents[M].append({"id": "01a1-unclaimed", "slug": "unclaimed/f5550710"})
    v = run(record, {"isolated": {"tenant": M}})
    assert v.status == "fail" and v.offending["slug"] == "unclaimed/f5550710"
    assert v.severity == "CRITICAL"


def test_isolated_sse_naming_another_tenants_agent(record: RunRecord) -> None:
    record.sse.append(fired(10, M, CLAIMS, "error_rate"))
    v = run(record, {"isolated": {"tenant": M}})
    assert v.status == "fail" and "SSE" in v.detail


def test_isolated_cross_reads_must_be_404(record: RunRecord) -> None:
    record.cross_reads.append(CrossRead(N, "operator", KB, 404))
    assert run(record, {"isolated": {"tenant": N}}).status == "pass"
    record.cross_reads.append(CrossRead(N, "operator", BILL, 200))
    v = run(record, {"isolated": {"tenant": N}})
    assert v.status == "fail" and "200" in v.detail


def test_observed_requires_traffic_to_land_in_its_own_tenant(record: RunRecord) -> None:
    record.events[CLAIMS] = [{"event_type": "gen_ai.request", "call_id": "c1"}]
    assert run(record, {"observed": {"tenant": N}}).status == "pass"
    # health counters include replayed history; only events stored since t = 0 count
    record.events[CLAIMS] = [{"event_type": "agent.discovered", "call_id": None}]
    v = run(record, {"observed": {"tenant": N}})
    assert v.status == "fail" and "claims-coder" in v.detail and v.severity == "CRITICAL"
    record.actors[CLAIMS].requests = 0  # an idle agent proves nothing either way
    assert run(record, {"observed": {"tenant": N}}).status == "pass"


def test_explainable_checks_penalty_identity_and_explanations(record: RunRecord) -> None:
    good = health(60, KB, 60, "degraded", factor("error_rate", 40), {"rule": "_hysteresis"})
    record.health[KB] = [good]
    assert run(record, {"explainable": {}}).status == "pass"
    clamped = health(
        61,
        KB,
        0,
        "failed",
        factor("error_rate", 50),
        factor("consecutive_failures", 60),
        {"rule": "_clamp", "penalty": 10},
    )
    record.health[KB] = [clamped]
    assert run(record, {"explainable": {}}).status == "pass"
    # B-04: the API strips `_clamp`; the oracle derives it as max(0, Σ penalty - 100)
    wire = health(61, KB, 0, "failed", factor("error_rate", 50), factor("consecutive_failures", 60))
    record.health[KB] = [wire]
    assert run(record, {"explainable": {}}).status == "pass"
    unclamped = health(
        61, KB, 5, "failed", factor("error_rate", 50), factor("consecutive_failures", 60)
    )
    record.health[KB] = [unclamped]
    assert run(record, {"explainable": {}}).status == "fail"
    wrong = health(62, KB, 70, "watch", factor("error_rate", 40))
    record.health[KB] = [wrong]
    v = run(record, {"explainable": {}})
    assert v.status == "fail" and v.measured["completeness"] == 0.0
    blank = health(63, KB, 60, "degraded", factor("error_rate", 40, explanation=""))
    record.health[KB] = [blank]
    assert run(record, {"explainable": {}}).status == "fail"
    empty = health(64, KB, 60, "degraded")
    record.health[KB] = [empty]
    assert run(record, {"explainable": {}}).status == "fail"


def test_explainable_accepts_a_band_held_or_floored_with_a_stated_reason(
    record: RunRecord,
) -> None:
    # after a failover the agent serves clean (score 100) while the band recovers through its
    # hysteresis: a zero-penalty band factor naming that band explains it (ML.md §3.6)
    held = {
        "rule": "consecutive_failures",
        "penalty": 0,
        "value": "degraded",
        "threshold": "healthy",
        "direction": "equals",
        "explanation": "Band held at degraded while recovering (4 of 18 clean ticks to healthy)",
    }
    record.health[KB] = [health(70, KB, 100, "degraded", held)]
    assert run(record, {"explainable": {}}).status == "pass"
    # the stated band must be the band reported, and the reason must be there
    record.health[KB] = [health(71, KB, 100, "failed", held)]
    assert run(record, {"explainable": {}}).status == "fail"
    record.health[KB] = [health(72, KB, 100, "degraded", held | {"explanation": ""})]
    assert run(record, {"explainable": {}}).status == "fail"
    # a band factor never excuses a broken identity
    record.health[KB] = [health(73, KB, 90, "degraded", held)]
    assert run(record, {"explainable": {}}).status == "fail"


def test_health_band_at_end_or_ever(record: RunRecord) -> None:
    record.health[KB] = [health(30, KB, 40, "degraded"), health(110, KB, 95, "healthy")]
    assert (
        run(record, {"health": {"agent": "kb-summarizer", "status": ["healthy"]}}).status == "pass"
    )
    v = run(record, {"health": {"agent": "kb-summarizer", "status": ["degraded"], "when": "ever"}})
    assert v.status == "pass"
    assert run(record, {"health": {"agent": "kb-summarizer", "min_score": 96}}).status == "fail"


def test_band_episodes_counts_departures_from_healthy(record: RunRecord) -> None:
    record.sse += [
        transition(20, KB, "healthy", "watch"),
        transition(30, KB, "watch", "failed"),
    ]
    assert run(record, {"band_episodes": {"agent": "kb-summarizer", "exactly": 1}}).status == "pass"
    record.sse += [transition(80, KB, "failed", "healthy"), transition(90, KB, "healthy", "failed")]
    v = run(record, {"band_episodes": {"agent": "kb-summarizer", "exactly": 1}})
    assert v.status == "fail" and v.measured["episodes"] == 2


def test_provider_incident_counts_attached_members(record: RunRecord) -> None:
    record.sse += [
        SseEvent(
            40,
            M,
            "provider_incident.opened",
            {"provider_incident_id": "pi-1", "provider_id": str(OPENAI_M)},
        ),
        SseEvent(
            41, M, "alert.updated", {"agent_id": str(IDS[KB]), "provider_incident_id": "pi-1"}
        ),
        SseEvent(
            41, M, "alert.updated", {"agent_id": str(IDS[BILL]), "provider_incident_id": "pi-1"}
        ),
    ]
    ok = run(
        record, {"provider_incident": {"provider": "openai-stub", "min_agents": 2, "by_t": 60}}
    )
    assert ok.status == "pass" and ok.measured["agents"] == 2
    assert (
        run(record, {"provider_incident": {"provider": "openai-stub", "min_agents": 3}}).status
        == "fail"
    )


def test_recommended_action_and_failure_mode(record: RunRecord) -> None:
    record.sse.append(transition(50, KB, "healthy", "watch", action="trim_context"))
    assert (
        run(
            record, {"recommended_action": {"agent": "kb-summarizer", "action": "trim_context"}}
        ).status
        == "pass"
    )
    assert (
        run(
            record,
            {"recommended_action": {"agent": "kb-summarizer", "action": "reroute_to_fallback"}},
        ).status
        == "fail"
    )
    record.health[KB] = [
        health(60, KB, 70, "watch").__class__(
            60, KB, 70, "watch", predicted_failure_mode="quality_collapse"
        )
    ]
    assert (
        run(record, {"failure_mode": {"agent": "kb-summarizer", "mode": "quality_collapse"}}).status
        == "pass"
    )


def test_gateway_route_share(record: RunRecord) -> None:
    stats = record.actors[KB]
    stats.routes.update({"primary": 10, "inline_fallback": 10})
    assert (
        run(
            record,
            {
                "gateway_route": {
                    "agent": "kb-summarizer",
                    "route": "inline_fallback",
                    "min_share": 0.4,
                }
            },
        ).status
        == "pass"
    )
    assert (
        run(
            record,
            {
                "gateway_route": {
                    "agent": "kb-summarizer",
                    "route": "inline_fallback",
                    "min_share": 0.6,
                }
            },
        ).status
        == "fail"
    )


def test_event_seen_and_no_duplicates(record: RunRecord) -> None:
    record.events[KB] = [
        {"event_type": "gen_ai.request", "call_id": "c1"},
        {"event_type": "gen_ai.request", "call_id": "c2"},
        {"event_type": "observation.gap", "call_id": None},
    ]
    assert (
        run(
            record, {"event_seen": {"agent": "kb-summarizer", "event_type": "observation.gap"}}
        ).status
        == "pass"
    )
    assert run(record, {"no_duplicates": {"agent": "kb-summarizer"}}).status == "pass"
    record.events[KB].append({"event_type": "gen_ai.request", "call_id": "c2"})
    v = run(record, {"no_duplicates": {"agent": "kb-summarizer"}})
    assert v.status == "fail" and v.offending == "c2"


def test_scores_at_least_for_a_tenant(record: RunRecord) -> None:
    assert run(record, {"scores_at_least": {"tenant": N, "min": 90}}).status == "pass"
    record.health[CLAIMS] = [health(110, CLAIMS, 70, "watch")]
    v = run(record, {"scores_at_least": {"tenant": N, "min": 90}})
    assert v.status == "fail" and v.severity == "CRITICAL"


def test_missing_lanes_skip_with_an_allowlisted_reason(record: RunRecord) -> None:
    s = scenario({"action": {"agent": "kb-summarizer", "to_state": "failed_over"}})
    record.lanes = {"S": False, "P": False, "U": False}
    verdicts = evaluate_all(s, record)
    assert verdicts[0].status == "skip" and "requires S" in verdicts[0].detail


def test_lane_present_runs_the_predicate(record: RunRecord) -> None:
    s = scenario({"action": {"agent": "kb-summarizer", "to_state": "failed_over", "by_t": 90}})
    record.lanes = {"S": True}
    record.transitions[KB] = [
        {"to_state": "failed_over", "actor_kind": "rule", "t": 70.0},
    ]
    v = evaluate_all(s, record)[0]
    assert v.status == "pass"


def test_action_ignores_the_registration_before_the_run(record: RunRecord) -> None:
    """S-25: the seeded `-> active` registration (t < 0) is not the fail-back the run gates."""
    s = scenario({"action": {"agent": "kb-summarizer", "to_state": "active", "by_t": 1200}})
    record.lanes = {"S": True}
    record.transitions[KB] = [
        {"from_state": None, "to_state": "active", "actor_kind": "system", "t": -23.5},
        {"from_state": "active", "to_state": "failed_over", "actor_kind": "rule", "t": 69.4},
    ]
    v = evaluate_all(s, record)[0]
    assert v.status == "fail" and "never reached active" in v.detail
    record.transitions[KB].append(
        {"from_state": "failing_back", "to_state": "active", "actor_kind": "user", "t": 995.4}
    )
    v = evaluate_all(s, record)[0]
    assert v.status == "pass" and v.measured["t"] == 995.4


def test_single_failover_and_no_action(record: RunRecord) -> None:
    record.lanes = {"S": True}
    record.transitions[KB] = [
        {"to_state": "failed_over", "actor_kind": "rule", "t": 70.0},
        {"to_state": "active", "actor_kind": "rule", "t": 300.0},
        {"to_state": "failed_over", "actor_kind": "rule", "t": 310.0},
    ]
    s = scenario({"single_failover": {"agent": "kb-summarizer"}})
    assert evaluate_all(s, record)[0].status == "fail"
    s2 = scenario({"no_action": {"agent": "faq-bot"}})
    assert evaluate_all(s2, record)[0].status == "pass"


def test_unknown_agent_in_expectation_fails_loudly(record: RunRecord) -> None:
    v = run(record, {"detect": {"agent": "nope", "rule": "R1"}})
    assert v.status == "error" and "nope" in v.detail


def test_expectation_name_is_human_readable() -> None:
    assert Expectation("detect", {"agent": "kb-summarizer"}).name == "detect(kb-summarizer)"
    assert Expectation("explainable", {}).name == "explainable"


def test_detect_provider_scope(record: RunRecord) -> None:
    record.sse.append(
        SseEvent(
            130,
            M,
            "alert.fired",
            {
                "rule": "provider_status",
                "scope": "provider",
                "provider_id": str(OPENAI_M),
                "severity": "critical",
            },
        )
    )
    v = run(record, {"detect": {"provider": "openai-stub", "rule": "R4", "by_t": 200}})
    assert v.status == "pass" and v.measured["t"] == 130
    late = run(record, {"detect": {"provider": "openai-stub", "rule": "R4", "by_t": 100}})
    assert late.status == "fail"


def test_quiet_agent_scope_ignores_shared_provider_status(record: RunRecord) -> None:
    record.sse += [
        SseEvent(
            130,
            N,
            "alert.fired",
            {"rule": "provider_status", "scope": "provider", "severity": "critical"},
        ),
        SseEvent(
            131,
            N,
            "provider_incident.opened",
            {"provider_id": "x", "rule_codes": ["provider_status"]},
        ),
    ]
    assert run(record, {"quiet": {"tenant": N}}).status == "fail"
    assert run(record, {"quiet": {"tenant": N, "scope": "agent"}}).status == "pass"
    record.sse.append(fired(140, N, CLAIMS, "error_rate"))
    assert run(record, {"quiet": {"tenant": N, "scope": "agent"}}).status == "fail"


def test_contract_flags_schema_invalid_health_documents(record: RunRecord) -> None:
    assert run(record, {"contract": {}}).status == "pass"
    bad = health(60, KB, 60, "degraded").__class__(
        60, KB, 60, "degraded", schema_errors=("factors.0.rule: pattern mismatch",)
    )
    record.health[KB] = [bad]
    v = run(record, {"contract": {}})
    assert v.status == "fail" and v.severity == "HIGH" and "sibyl-health/1" in v.detail


def test_every_scenario_gets_an_implicit_contract_check() -> None:
    s = scenario({"explainable": {}})
    assert [e.predicate for e in s.expect] == ["explainable", "contract"]


def test_explainable_fails_on_a_dead_evidence_link(record: RunRecord) -> None:
    record.health[KB] = [health(60, KB, 60, "degraded", factor("error_rate", 40))]
    record.lane_reads["evidence"] = {"/api/v1/events?agent_id=x": 200}
    ok = run(record, {"explainable": {}})
    assert ok.status == "pass" and ok.measured["evidence_checked"] == 1
    record.lane_reads["evidence"]["/api/v1/providers/y/status"] = 404
    v = run(record, {"explainable": {}})
    assert v.status == "fail" and "404" in v.detail
