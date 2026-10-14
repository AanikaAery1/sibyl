"""`python -m sibyl_sim run`: run scenarios against fresh in-process stacks and report.

    python -m sibyl_sim run --scenario S-01 [--seed N | --seeds 3] [--report out/]
    python -m sibyl_sim run --smoke                  # the PR smoke set (smoke: true)
    python -m sibyl_sim run --all --seeds 1          # the nightly catalogue
    python -m sibyl_sim run --list

Exit codes: 0 pass (MEDIUM misses are carried with a ticket), 1 a HIGH gate missed, 2 a
CRITICAL gate missed (automatic No-go), 3 the harness itself failed. Dev-only (R46).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..golden.series import DATA_DIR, Tolerance
from ..reports.gates import RunOutcome
from ..reports.render import Suite, summary, write
from ..scenarios.load import load, load_catalog
from ..scenarios.model import Scenario, ScenarioError
from .hostslots import host_slot
from .runner import RunOptions, run_scenario

log = logging.getLogger("sibyl_sim.harness")
EXIT = {"pass": 0, "warn": 1, "block": 2}
BASE_DOUBLES_PORT = 18390


def add_run_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    run = sub.add_parser("run", help="run evaluation scenarios against an in-process stack")
    pick = run.add_mutually_exclusive_group()
    pick.add_argument("--scenario", action="append", help="scenario id (repeatable)")
    pick.add_argument("--smoke", action="store_true", help="the PR smoke set")
    pick.add_argument("--all", action="store_true", help="the full catalogue (nightly)")
    pick.add_argument("--list", action="store_true", help="list scenarios and exit")
    run.add_argument("--seed", type=int, action="append", help="seed (repeatable)")
    run.add_argument("--seeds", type=int, default=1, help="N seeds from the scenario seed")
    run.add_argument("--report", default="sibyl-sim/reports/latest", help="report directory")
    run.add_argument("--parallel", type=int, default=1, help="concurrent stacks")
    run.add_argument("--update-golden", action="store_true")
    run.add_argument("--golden-dir", default=str(DATA_DIR))
    run.add_argument("--tolerance-ticks", type=int, default=Tolerance().ticks)
    run.add_argument("--keep-db", action="store_true", help="keep each run's database")
    run.add_argument(
        "--eval-tick-s",
        type=float,
        default=None,
        help="dev-only SIBYL_EVAL_TICK_S equivalent for rollup/scoring cadence (R45)",
    )
    run.add_argument("--doubles-port", type=int, default=BASE_DOUBLES_PORT)
    run.add_argument("-v", "--verbose", action="store_true")


@dataclass
class _Lanes:
    known: dict[str, bool] | None = None
    bridges: tuple[str, ...] = ()
    notes: list[str] = field(default_factory=list)


def _build_id() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except OSError:
        return "unknown"
    return out.stdout.strip() or "unknown"


def select(args: argparse.Namespace) -> list[Scenario]:
    if args.all:
        return list(load_catalog().values())
    if args.smoke:
        return [s for s in load_catalog().values() if s.smoke]
    if args.scenario:
        return [load(sid) for sid in args.scenario]
    raise ScenarioError("choose --scenario, --smoke, --all or --list")


def seeds_for(scenario: Scenario, args: argparse.Namespace) -> list[int]:
    if args.seed:
        return list(args.seed)
    return [scenario.seed + n for n in range(max(1, args.seeds))]


async def run_suite(
    scenarios: Sequence[Scenario],
    args: argparse.Namespace,
    *,
    stack_factory: object | None = None,
) -> Suite:
    from .inprocess.stack import (  # control plane imports here only
        InProcessStack,
        StackOptions,
        start_with_retry,
    )

    started = time.monotonic()
    report_dir = Path(args.report)
    opts = RunOptions(
        out_dir=report_dir / "runs",
        update_golden=args.update_golden,
        golden_root=Path(args.golden_dir),
        tolerance=Tolerance(ticks=args.tolerance_ticks),
    )
    lanes = _Lanes()
    slots: asyncio.Queue[int] = asyncio.Queue()
    for n in range(max(1, args.parallel)):
        slots.put_nowait(n)

    async def one(scenario: Scenario, seed: int) -> RunOutcome:
        if scenario.phase != "1":
            return RunOutcome(scenario.id, seed, "skip", reason="requires Phase 1.5 (ROADMAP §3.4)")
        if lanes.known is not None:
            missing = [lane for lane in scenario.requires if not lanes.known.get(lane)]
            if missing:
                reason = f"requires {', '.join(missing)} (lane not merged; allowlisted until G2)"
                return RunOutcome(scenario.id, seed, "skip", reason=reason)
        slot = await slots.get()
        async with host_slot():  # host-wide: every run on this machine shares the cluster
            return await boot_and_run(scenario, seed, slot)

    async def boot_and_run(scenario: Scenario, seed: int, slot: int) -> RunOutcome:
        stack = InProcessStack(
            StackOptions(
                doubles_port=args.doubles_port + slot,
                sim_seed=seed,
                eval_tick_s=args.eval_tick_s,
                keep_db=args.keep_db,
                drift=dict(scenario.drift) or None,
            )
        )
        try:
            await start_with_retry(stack)
            assert stack.world is not None
            lanes.bridges = stack.world.bridges
            outcome = await run_scenario(scenario, seed, stack, opts)
            if lanes.known is None and outcome.status != "skip":
                lanes.known = dict(outcome.summary.get("lanes") or {})
            log.warning(
                "%s seed %s: %s (%.0f s)", scenario.id, seed, outcome.status, outcome.wall_s
            )
            return outcome
        except Exception as exc:
            log.exception("%s seed %s: harness error", scenario.id, seed)
            return RunOutcome(
                scenario.id, seed, "error", reason=f"harness: {type(exc).__name__}: {exc}"
            )
        finally:
            await stack.stop()
            slots.put_nowait(slot)

    jobs = [one(s, seed) for s in scenarios for seed in seeds_for(s, args)]
    outcomes = list(await asyncio.gather(*jobs))
    return Suite(
        outcomes,
        build=_build_id(),
        bridges=lanes.bridges,
        wall_s=time.monotonic() - started,
        notes=lanes.notes,
    )


def exit_code(suite: Suite) -> int:
    doc = summary(suite)
    if any(o.status == "error" for o in suite.outcomes):
        return 3
    return EXIT[doc["verdict"]]


def main(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    if args.list:
        for scenario in load_catalog().values():
            flags = " smoke" if scenario.smoke else ""
            gated = sorted(scenario.requires)
            partial = sorted(scenario.lanes_needed() - set(gated))
            needs = f" requires={','.join(gated)}" if gated else ""
            needs += f" partial={','.join(partial)}" if partial else ""
            print(f"{scenario.id}{flags}{needs} phase={scenario.phase} {scenario.title}")
        return 0
    try:
        scenarios = select(args)
    except ScenarioError as exc:
        print(f"sibyl_sim run: {exc}")
        return 3
    suite = asyncio.run(run_suite(scenarios, args))
    md, js = write(suite, Path(args.report))
    doc = summary(suite)
    print(f"sibyl-sim: {doc['verdict']} {doc['severity']} -> {md} {js}")
    return exit_code(suite)
