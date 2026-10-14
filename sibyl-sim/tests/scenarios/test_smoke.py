"""PR smoke suite (ML §8.4, WAVE2 lane M): S-01, S-09, S-21, S-22 against fresh in-process
stacks on PG17, four at once, within 5 minutes of wall time.

Verdicts are checked against `KNOWN_PRODUCT_BUGS` with strict-xfail semantics: a listed bug
must still fail (so the suite stays green while it is open), and a listed bug that passes
fails the test so its entry is removed the day the fix lands. Anything else must pass or be
an allowlisted lane skip. Skipped when PG17 is unreachable on a developer machine, failed
under CI / SIBYL_REQUIRE_PG; `SIBYL_SIM_SMOKE=0` opts out locally.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sibyl_sim.harness.cli import run_suite
from sibyl_sim.harness.inprocess import database as pg
from sibyl_sim.harness.ports import free_base
from sibyl_sim.reports.gates import RunOutcome
from sibyl_sim.reports.render import Suite, write
from sibyl_sim.scenarios.load import load_catalog

SMOKE_BUDGET_S = 300.0
# Four stacks bind base..base+3; another worktree's CI may hold a base (each base has its own
# cached template, so the set stays small).
SMOKE_PORT_BASES = (18490, 18930, 19030, 19130)
# Open product bugs, strict-xfail: a listed bug must still fail; one that passes fails the test
# so its entry is removed the day the fix lands. Closed in wave 4 (HARDEN): B-03 (per-tenant
# ingest keys at the shared gateway), B-04 (health bookkeeping stripped, every snapshot carries
# a feature snapshot), B-07 (a band held worse than a live floor is explained), B-08 (ruling
# B35: masked outages are labelled `masked` and judged as the ruling states).
KNOWN_PRODUCT_BUGS: dict[tuple[str, str], str] = {}
# Gate misses with a ticket, same strict-xfail semantics: (scenario, gate, tier) -> bug.
KNOWN_GATE_MISSES: dict[tuple[str, str, int | None], str] = {
    # B-10 (open, wave 4 HARDEN): escalation-router is masked by inline fallback (ruling B35)
    # and calls about every 9 s; with no status page to flip there is no R4, and its 5-minute
    # window stays below L5 fallback_pressure's sample minimum, so nothing detects the outage.
    # A product coverage gap on low-traffic masked agents (chair ruling needed), not a timing
    # flake: the seed is fixed and it reproduces every run.
    ("S-22", "recall", 2): "B-10",
}
# Timing-dependent bugs, checked as "pass or this bug", never as strict-xfail.
FLAKY_PRODUCT_BUGS: dict[tuple[str, str], str] = {}


def _enabled() -> bool:
    return os.environ.get("SIBYL_SIM_SMOKE", "1") not in ("0", "false", "no")


def _required() -> bool:
    return any(
        os.environ.get(v, "").lower() in ("1", "true", "yes") for v in ("CI", "SIBYL_REQUIRE_PG")
    )


@pytest.fixture(scope="module")
def suite(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Suite]:
    if not _enabled():
        pytest.skip("SIBYL_SIM_SMOKE=0")
    if not asyncio.run(pg.available()):
        message = f"PostgreSQL 17 not reachable at {pg.admin_dsn()} (make db-up)"
        if _required():
            pytest.fail(message, pytrace=False)
        pytest.skip(message)
    base = free_base(SMOKE_PORT_BASES, width=4)
    if base is None:
        pytest.fail(f"no free doubles port base among {SMOKE_PORT_BASES}", pytrace=False)
    report = tmp_path_factory.mktemp("sim-smoke")
    args = argparse.Namespace(
        report=str(report),
        update_golden=False,
        golden_dir=str(report / "golden"),  # goldens are a nightly concern
        tolerance_ticks=2,
        parallel=4,
        keep_db=False,
        eval_tick_s=None,
        doubles_port=base,
        seed=None,
        seeds=1,
    )
    smoke = [s for s in load_catalog().values() if s.smoke]
    result = asyncio.run(run_suite(smoke, args))
    write(result, Path(report))
    yield result


def _outcome(suite: Suite, sid: str) -> RunOutcome:
    return next(o for o in suite.outcomes if o.scenario == sid)


def test_smoke_fits_the_pr_budget(suite: Suite) -> None:
    assert suite.wall_s <= SMOKE_BUDGET_S, f"smoke took {suite.wall_s:.0f} s"


@pytest.mark.parametrize("sid", ["S-01", "S-09", "S-21", "S-22"])
def test_smoke_scenario(suite: Suite, sid: str) -> None:
    outcome = _outcome(suite, sid)
    assert outcome.status != "error", outcome.reason
    unexpected, fixed = [], []
    for v in outcome.verdicts:
        bug = KNOWN_PRODUCT_BUGS.get((sid, v.name))
        if (sid, v.name) in FLAKY_PRODUCT_BUGS:
            continue
        if bug is None and v.status not in ("pass", "skip", "report"):
            unexpected.append(f"{v.severity} {v.name}: {v.detail}")
        if bug is not None and v.status == "pass":
            fixed.append(f"{bug} {v.name} now passes: remove it from KNOWN_PRODUCT_BUGS")
    for gate in outcome.gates:
        if gate.derived:
            continue
        gate_bug = KNOWN_GATE_MISSES.get((sid, gate.gate, gate.tier))
        if gate_bug is None and not gate.passed:
            unexpected.append(f"{gate.severity} gate {gate.gate} t{gate.tier}: {gate.detail}")
        if gate_bug is not None and gate.passed:
            fixed.append(f"{gate_bug} gate {gate.gate} t{gate.tier} now passes: remove it")
    assert not unexpected, "\n".join(unexpected)
    assert not fixed, "\n".join(fixed)


def test_skips_are_only_allowlisted_lane_gaps(suite: Suite) -> None:
    for outcome in suite.outcomes:
        for v in outcome.verdicts:
            if v.status == "skip":
                assert "lane not merged; allowlisted until G2" in v.detail, v
