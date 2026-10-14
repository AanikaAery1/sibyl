"""Markdown report + JSON summary (qa-expert §4.4)."""

from __future__ import annotations

import json
from pathlib import Path

from sibyl_sim.oracle.predicates import Verdict
from sibyl_sim.reports.gates import GateResult, RunOutcome
from sibyl_sim.reports.render import Suite, render_markdown, summary, write


def suite() -> Suite:
    ok = RunOutcome(
        "S-01",
        1,
        "pass",
        [
            Verdict(
                "detect(kb-summarizer)",
                "detect",
                "MEDIUM",
                "pass",
                "R3 at t=31",
                {"ttd_s": 11.0, "tier": 3},
            )
        ],
        [GateResult("ttd_hard", 3, 11.0, 120.0, "MEDIUM", True, "worst TTD 11.0s")],
        95.0,
    )
    leak = RunOutcome(
        "S-21",
        1,
        "fail",
        [Verdict("isolated(meridian)", "isolated", "CRITICAL", "fail", "lists unclaimed/1")],
        [
            GateResult(
                "isolation_leaks",
                None,
                1.0,
                0.0,
                "CRITICAL",
                False,
                "lists unclaimed/1",
                derived=True,
            )
        ],
        80.0,
    )
    skipped = RunOutcome("S-26", 1, "skip", [], [], 0.0, reason="requires S (lane not merged)")
    return Suite([ok, leak, skipped], build="abc1234", bridges=("B11 bridge: x",), wall_s=200.0)


def test_markdown_has_gate_line_tables_and_skips() -> None:
    md = render_markdown(suite())
    assert md.startswith("# sibyl-sim report")
    assert "CRITICAL 1 · HIGH 0 · MEDIUM 0" in md
    assert "| S-01 | pass |" in md and "| S-21 | fail |" in md
    assert "S-26" in md and "requires S" in md
    assert "B11 bridge" in md
    assert "isolated(meridian)" in md
    assert "| t3 | 11.0 |" in md  # TTD headline per tier


def test_summary_json_is_machine_readable() -> None:
    doc = summary(suite())
    assert doc["schema"] == "sibyl-sim-report/1"
    assert doc["severity"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    assert doc["verdict"] == "block"
    assert [s["id"] for s in doc["scenarios"]] == ["S-01", "S-21", "S-26"]
    assert doc["scenarios"][2]["status"] == "skip"
    assert doc["ttd_worst_s"] == {"hard": {"3": 11.0}}
    json.dumps(doc)  # serialisable


def test_write_creates_both_files(tmp_path: Path) -> None:
    md, js = write(suite(), tmp_path)
    assert md.read_text().startswith("# sibyl-sim report")
    assert json.loads(js.read_text())["verdict"] == "block"


def test_green_suite_verdict() -> None:
    s = suite()
    s.outcomes = [s.outcomes[0], s.outcomes[2]]
    assert summary(s)["verdict"] == "pass"
