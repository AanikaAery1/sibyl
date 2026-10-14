"""Golden series (qa-expert §4.1): canonicalised to tick offsets, compared with tolerances."""

from __future__ import annotations

import json
from pathlib import Path

from sibyl_sim.golden.series import Tolerance, canonical, compare, load, save
from sibyl_sim.oracle.record import RunRecord, SseEvent
from sibyl_sim.scenarios.model import parse_scenario

from .conftest import KB, OPENAI_M, M, N, fired, health, transition

SCENARIO = parse_scenario(
    {
        "id": "S-97",
        "title": "g",
        "duration_s": 300,
        "labels": [{"agent": "kb-summarizer", "kind": "onset", "t": 20}],
        "expect": [{"detect": {"agent": "kb-summarizer", "rule": "R3"}}],
    }
)


def populated(record: RunRecord, shift: float = 0.0, score: int = 40) -> RunRecord:
    record.sse += [
        fired(31 + shift, M, KB, "consecutive_failures"),
        fired(52 + shift, M, KB, "error_rate"),
        transition(41 + shift, KB, "healthy", "failed"),
        SseEvent(60 + shift, M, "provider_incident.opened", {"provider_id": str(OPENAI_M)}),
    ]
    record.health[KB] = [health(290, KB, score, "failed")]
    return record


def test_canonical_uses_tick_offsets_and_tracked_agents(record: RunRecord) -> None:
    doc = canonical(SCENARIO, populated(record), tick_s=10)
    kb = doc["agents"]["meridian/kb-summarizer"]
    assert kb["alerts"] == [[3, "consecutive_failures"], [5, "error_rate"]]
    assert kb["transitions"] == [[4, "healthy", "failed"]]
    assert kb["final"] == {"status": "failed", "score": 40}
    assert doc["incidents"] == [[6, "openai-stub"]]
    assert doc["tenants"][N] == {"alerts": 0, "transitions": 0}


def test_compare_within_tolerance_is_clean(record: RunRecord) -> None:
    golden = canonical(SCENARIO, populated(record), tick_s=10)
    again = canonical(SCENARIO, populated(_fresh(record), shift=9, score=42), tick_s=10)
    assert compare(golden, again, Tolerance(ticks=1, score=2)) == []


def test_compare_reports_each_difference(record: RunRecord) -> None:
    golden = canonical(SCENARIO, populated(record), tick_s=10)
    shifted = canonical(SCENARIO, populated(_fresh(record), shift=40, score=60), tick_s=10)
    diffs = compare(golden, shifted, Tolerance(ticks=1, score=2))
    joined = "\n".join(diffs)
    assert "consecutive_failures" in joined and "tick 3 -> 7" in joined
    assert "score 40 -> 60" in joined


def test_new_rule_is_a_deliberate_update(record: RunRecord) -> None:
    golden = canonical(SCENARIO, populated(record), tick_s=10)
    extra = _fresh(record)
    populated(extra)
    extra.sse.append(fired(70, M, KB, "p95_latency"))
    diffs = compare(golden, canonical(SCENARIO, extra, tick_s=10), Tolerance())
    assert any("new alert p95_latency" in d for d in diffs)


def test_save_and_load_round_trip(tmp_path: Path, record: RunRecord) -> None:
    doc = canonical(SCENARIO, populated(record), tick_s=10)
    path = save(tmp_path, "S-97", 7, doc)
    assert path == tmp_path / "S-97" / "7.json"
    assert load(tmp_path, "S-97", 7) == doc
    assert json.loads(path.read_text())["scenario"] == "S-97"
    assert load(tmp_path, "S-97", 8) is None


def _fresh(record: RunRecord) -> RunRecord:
    return RunRecord(
        record.scenario, record.seed, record.started_at, record.duration_s, record.world
    )
