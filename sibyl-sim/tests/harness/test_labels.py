"""Ground truth goes to run-local JSONL, never Postgres, and is identical for the same seed."""

from __future__ import annotations

import json
from pathlib import Path

from sibyl_sim.actors.traffic import plan_arrivals
from sibyl_sim.harness.labels import ground_truth_rows, plan_rows, write_ground_truth
from sibyl_sim.scenarios.model import AgentRef, parse_scenario

RAW = {
    "id": "S-96",
    "title": "labels",
    "duration_s": 120,
    "tenants": {"meridian": {"agents": {"kb-summarizer": "busy"}}},
    "chaos": [
        {"at": 20, "double": "openai-stub", "set": {"outage": True}, "agents": ["kb-summarizer"]}
    ],
    "labels": [
        {"agent": "kb-summarizer", "kind": "onset", "t": 20, "failure_mode": "provider_outage"},
        {"agent": "kb-summarizer", "kind": "recovery", "t": 100},
    ],
    "expect": [{"detect": {"agent": "kb-summarizer", "rule": "R3", "by_t": 80}}],
}


def test_rows_carry_expectations_and_injection() -> None:
    s = parse_scenario(RAW)
    rows = ground_truth_rows(s, seed=5)
    onset = next(r for r in rows if r["kind"] == "onset")
    assert onset == {
        "row": "label",
        "scenario": "S-96",
        "seed": 5,
        "t_sim": 20.0,
        "tenant": "meridian",
        "agent": "kb-summarizer",
        "kind": "onset",
        "failure_mode": "provider_outage",
        "injected_by": ["chaos[0] double:openai-stub outage"],
        "expected": [{"predicate": "detect", "rule": "R3", "by_t": 80}],
    }
    chaos = [r for r in rows if r["row"] == "chaos"]
    assert chaos[0]["target"] == "double:openai-stub" and chaos[0]["agents"] == [
        "meridian/kb-summarizer"
    ]


def test_same_seed_same_bytes(tmp_path: Path) -> None:
    s = parse_scenario(RAW)
    plans = {
        AgentRef("meridian", "kb-summarizer"): plan_arrivals(
            5, s.id, AgentRef("meridian", "kb-summarizer"), s.profile("busy"), duration_s=120
        )
    }
    a = write_ground_truth(tmp_path / "a", s, 5, plans)
    b = write_ground_truth(tmp_path / "b", s, 5, plans)
    assert a.read_bytes() == b.read_bytes()
    rows = [json.loads(line) for line in a.read_text().splitlines()]
    assert {r["row"] for r in rows} == {"label", "chaos", "plan"}
    assert a.name == "labels-S-96-5.jsonl"


def test_plan_rows_summarise_each_agent() -> None:
    s = parse_scenario(RAW)
    ref = AgentRef("meridian", "kb-summarizer")
    plan = plan_arrivals(5, s.id, ref, s.profile("busy"), duration_s=120)
    rows = plan_rows(s, 5, {ref: plan})
    assert rows[0]["agent"] == "meridian/kb-summarizer" and rows[0]["calls"] == len(plan)
    assert rows[0]["first_request_id"] == plan[0].request_id
    assert len(rows[0]["digest"]) == 64
