"""Per-tier gates (ML §8.3): TTD, detection precision/recall, isolation, worst seed."""

from __future__ import annotations

from typing import Any

from sibyl_sim.oracle.predicates import evaluate_all
from sibyl_sim.oracle.record import RunRecord
from sibyl_sim.reports.gates import (
    PRECISION,
    RECALL,
    TTD_GATES,
    RunOutcome,
    detection_counts,
    gate_run,
    severity_counts,
    worst_over_seeds,
)
from sibyl_sim.scenarios.model import parse_scenario

from .conftest import BILL, CLAIMS, FAQ, KB, OPENAI_M, M, N, fired, transition


def scenario(**extra: Any) -> Any:
    raw = {
        "id": "S-98",
        "title": "t",
        "duration_s": 300,
        "gate_class": "hard",
        "labels": [
            {"agent": "kb-summarizer", "kind": "onset", "t": 20},
            {"agent": "billing-agent", "kind": "onset", "t": 20},
            {"agent": "billing-agent", "kind": "recovery", "t": 200},
        ],
        "expect": [
            {"detect": {"agent": "kb-summarizer", "rule": "R3"}},
            {"detect": {"agent": "billing-agent", "rule": "R3"}},
            {"isolated": {"tenant": N}},
        ],
    } | extra
    return parse_scenario(raw)


def test_thresholds_match_ml_8_3() -> None:
    assert TTD_GATES["hard"] == {1: 60.0, 2: 90.0, 3: 120.0}
    assert TTD_GATES["silent"] == {1: 600.0, 2: 600.0, 3: 900.0}
    assert RECALL == {1: 0.95, 2: 0.95, 3: 0.90} and PRECISION == {1: 0.90, 2: 0.85, 3: 0.80}


def test_detection_counts_per_tier(record: RunRecord) -> None:
    s = scenario()
    record.sse += [
        fired(30, M, KB, "consecutive_failures"),
        fired(31, M, KB, "error_rate"),  # second alert on the same label: still one TP
        fired(15, M, FAQ, "error_rate"),  # unlabelled agent: FP (tier 3)
        fired(270, M, BILL, "error_rate"),  # after recovery + 60 s grace: FP (tier 1)
    ]
    counts = detection_counts(s, record)
    assert counts[3].tp == 1 and counts[3].fp == 1 and counts[3].fn == 0
    assert counts[1].tp == 0 and counts[1].fn == 1 and counts[1].fp == 1


def test_gate_run_flags_ttd_and_recall(record: RunRecord) -> None:
    s = scenario()
    record.sse += [
        fired(30, M, KB, "consecutive_failures"),
        fired(200, M, BILL, "consecutive_failures"),
    ]
    record.lanes = {}
    verdicts = evaluate_all(s, record)
    gates = gate_run(s, record, verdicts)
    by = {(g.gate, g.tier): g for g in gates}
    assert by[("ttd_hard", 3)].passed and by[("ttd_hard", 3)].value == 10
    assert by[("ttd_hard", 1)].passed is False and by[("ttd_hard", 1)].severity == "MEDIUM"
    assert by[("recall", 1)].passed and by[("precision", 3)].passed
    assert by[("isolation_leaks", None)].passed and by[("isolation_leaks", None)].value == 0


def _masked(**extra: Any) -> Any:
    """kb-summarizer's outage is fully masked by inline fallback (ruling B35)."""
    return scenario(
        labels=[{"agent": "kb-summarizer", "kind": "onset", "t": 20, "masked": True}],
        expect=[{"isolated": {"tenant": N}}],
        **extra,
    )


def test_a_masked_outage_is_detected_at_provider_scope_once_the_band_fails(
    record: RunRecord,
) -> None:
    """B35: no failed call of its own, so no R1/R3; it is attributed to the primary and reaches
    `failed` through R4 (provider scope). That pair is the detection."""
    s = _masked()
    record.sse.append(
        fired(90, M, None, "provider_status", scope="provider", provider_id=str(OPENAI_M))
    )
    assert detection_counts(s, record)[3].fn == 1  # R4 alone, the band never failed
    record.sse.append(transition(100, KB, "degraded", "failed", "reroute_to_fallback"))
    counts = detection_counts(s, record)[3]
    assert (counts.tp, counts.fn, counts.fp) == (1, 0, 0)


def test_r4_on_another_provider_does_not_detect_a_masked_outage(record: RunRecord) -> None:
    s = _masked()
    record.sse += [
        fired(90, M, None, "provider_status", scope="provider", provider_id="someone-else"),
        transition(100, KB, "degraded", "failed"),
    ]
    assert detection_counts(s, record)[3].fn == 1


def test_without_a_status_page_a_masked_outage_is_seen_by_fallback_pressure(
    record: RunRecord,
) -> None:
    """B35 with no R4: the leading L5 fallback-pressure alert is the only signal there is."""
    s = _masked()
    record.sse.append(fired(60, M, KB, "fallback_pressure"))
    assert detection_counts(s, record)[3].tp == 1
    # the same leading alert does not excuse an unmasked label
    plain = scenario(labels=[{"agent": "kb-summarizer", "kind": "onset", "t": 20}])
    assert detection_counts(plain, record)[3].fn == 1


def test_masked_is_a_boolean() -> None:
    import pytest
    from sibyl_sim.scenarios.model import ScenarioError

    with pytest.raises(ScenarioError, match="masked"):
        scenario(labels=[{"agent": "kb-summarizer", "kind": "onset", "t": 20, "masked": "yes"}])


def test_ttd_gate_limit_scales_with_measured_tick_lag(record: RunRecord) -> None:
    """B38: 80 s misses tier 1's 60 s at idle; with the product's eval ticks measured 1.4x
    slower the limit is 84 s, and the gate says so."""
    from sibyl_sim.oracle.timing import Timing

    s = scenario()
    record.sse.append(fired(100, M, BILL, "consecutive_failures"))
    record.lanes = {}

    def tier1(rec: RunRecord) -> Any:
        gates = gate_run(s, rec, evaluate_all(s, rec))
        return next(g for g in gates if (g.gate, g.tier) == ("ttd_hard", 1))

    assert not tier1(record).passed
    record.timing = Timing(dilation=1.4)
    gate = tier1(record)
    assert gate.passed and gate.threshold == 84.0 and gate.value == 80
    assert "x1.4" in gate.detail


def test_isolation_failure_is_a_critical_gate(record: RunRecord) -> None:
    s = scenario()
    record.listed_agents[N].append({"id": "x", "slug": "unclaimed/1"})
    gates = gate_run(s, record, evaluate_all(s, record))
    leak = next(g for g in gates if g.gate == "isolation_leaks")
    assert leak.passed is False and leak.severity == "CRITICAL" and leak.value == 1


def test_worst_seed_wins_and_severity_counts(record: RunRecord) -> None:
    s = scenario()
    good = RunOutcome("S-98", 1, "pass", [], [], 10.0)
    record.sse.append(fired(30, M, KB, "consecutive_failures"))
    verdicts = evaluate_all(s, record)
    bad = RunOutcome("S-98", 2, "fail", verdicts, gate_run(s, record, verdicts), 11.0)
    worst = worst_over_seeds([good, bad])
    assert worst.seed == 2 and worst.status == "fail"
    counts = severity_counts([good, bad])
    assert counts["MEDIUM"] >= 1 and counts["CRITICAL"] == 0


def test_skipped_runs_are_reported_not_failed() -> None:
    skipped = RunOutcome("S-26", 1, "skip", [], [], 0.0, reason="requires S")
    assert worst_over_seeds([skipped]).status == "skip"
    assert severity_counts([skipped]) == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_northstar_alerts_count_as_isolation_leaks(record: RunRecord) -> None:
    s = scenario(expect=[{"quiet": {"tenant": N}}])
    record.sse.append(fired(40, N, CLAIMS, "error_rate"))
    gates = gate_run(s, record, evaluate_all(s, record))
    leak = next(g for g in gates if g.gate == "isolation_leaks")
    assert leak.value == 1 and leak.passed is False


def test_precursor_is_tolerated_but_not_required(record: RunRecord) -> None:
    s = scenario(
        labels=[
            {"agent": "kb-summarizer", "kind": "precursor", "t": 60},
            {"agent": "kb-summarizer", "kind": "onset", "t": 120},
        ],
        expect=[],
    )
    record.sse += [fired(90, M, KB, "p95_latency"), fired(150, M, KB, "p95_latency")]
    counts = detection_counts(s, record)
    assert (counts[3].tp, counts[3].fp, counts[3].fn) == (1, 0, 0)
    record.sse.append(fired(30, M, KB, "p95_latency"))  # before the precursor: early is not free
    assert detection_counts(s, record)[3].fp == 1
