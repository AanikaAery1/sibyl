"""`python -m sibyl_sim run`: parsing, selection, seeds and exit codes (no stack needed)."""

from __future__ import annotations

import pytest
from sibyl_sim.doubles.cli import main, parser
from sibyl_sim.harness.cli import exit_code, seeds_for, select
from sibyl_sim.oracle.predicates import Verdict
from sibyl_sim.reports.gates import RunOutcome
from sibyl_sim.reports.render import Suite
from sibyl_sim.scenarios.load import load


def test_run_subcommand_is_registered_beside_serve() -> None:
    args = parser().parse_args(["run", "--scenario", "S-01", "--seed", "7", "--report", "out"])
    assert args.command == "run" and args.scenario == ["S-01"] and args.seed == [7]
    assert args.report == "out" and args.parallel == 1 and args.eval_tick_s is None
    assert parser().parse_args(["serve"]).command == "serve"


def test_selection_and_seeds() -> None:
    p = parser()
    assert [s.id for s in select(p.parse_args(["run", "--smoke"]))] == [
        "S-01",
        "S-09",
        "S-21",
        "S-22",
    ]
    assert len(select(p.parse_args(["run", "--all"]))) == 33
    s01 = load("S-01")
    assert seeds_for(s01, p.parse_args(["run", "--scenario", "S-01", "--seeds", "3"])) == [
        s01.seed,
        s01.seed + 1,
        s01.seed + 2,
    ]
    assert seeds_for(s01, p.parse_args(["run", "--scenario", "S-01", "--seed", "5"])) == [5]


def test_scenario_and_all_are_exclusive() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(["run", "--scenario", "S-01", "--all"])


def _suite(*outcomes: RunOutcome) -> Suite:
    return Suite(list(outcomes))


def test_exit_codes() -> None:
    green = RunOutcome("S-09", 1, "pass")
    medium = RunOutcome("S-09", 1, "fail", [Verdict("d", "detect", "MEDIUM", "fail", "late")])
    high = RunOutcome("S-09", 1, "fail", [Verdict("c", "contract", "HIGH", "fail", "x")])
    critical = RunOutcome("S-21", 1, "fail", [Verdict("i", "isolated", "CRITICAL", "fail", "x")])
    broken = RunOutcome("S-01", 1, "error", reason="harness: boom")
    assert exit_code(_suite(green)) == 0
    assert exit_code(_suite(green, medium)) == 0  # MEDIUM is carried with a ticket
    assert exit_code(_suite(high)) == 1
    assert exit_code(_suite(high, critical)) == 2
    assert exit_code(_suite(green, broken)) == 3


def test_list_prints_the_catalogue(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--list"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 33 and out[0].startswith("S-01 smoke")
    assert any(line.startswith("S-26 requires=S") for line in out)
