"""Shell scripts parse; ci/run.sh exposes its steps, refuses a dead DB and guards skips."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted(
    [
        *REPO_ROOT.glob("ci/*.sh"),
        *REPO_ROOT.glob("ops/backup/*.sh"),
        *REPO_ROOT.glob("ops/demo/*.sh"),
        *REPO_ROOT.glob("deploy/compose/*.sh"),
    ]
)
# POSIX sh scripts run inside third-party/slim images (no bash there).
CONTAINER_SCRIPTS = sorted(REPO_ROOT.glob("deploy/compose/*/*.sh"))


def _bash(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_expected_scripts_exist() -> None:
    names = {p.relative_to(REPO_ROOT).as_posix() for p in SCRIPTS}
    assert {
        "ci/run.sh",
        "ci/worktree.sh",
        "ops/backup/backup.sh",
        "ops/backup/restore.sh",
        "ops/demo/up.sh",
        "ops/demo/down.sh",
        "deploy/compose/init-env.sh",
    } <= names


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_script_parses_and_is_strict(path: Path) -> None:
    assert _bash("-n", str(path)).returncode == 0
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text


@pytest.mark.parametrize(
    "path", CONTAINER_SCRIPTS, ids=lambda p: p.relative_to(REPO_ROOT).as_posix()
)
def test_container_script_is_posix_sh(path: Path) -> None:
    proc = subprocess.run(["sh", "-n", str(path)], capture_output=True, check=False)  # noqa: S603, S607
    assert proc.returncode == 0, proc.stderr
    assert path.read_text(encoding="utf-8").startswith("#!/bin/sh")


@pytest.mark.parametrize("script", ["up.sh", "down.sh"])
def test_demo_scripts_have_help(script: str) -> None:
    proc = _bash(str(REPO_ROOT / "ops" / "demo" / script), "--help")
    assert proc.returncode == 0, proc.stderr
    assert "usage" in proc.stdout.lower()


@pytest.mark.parametrize("script", ["up.sh", "down.sh"])
def test_demo_scripts_reject_unknown_arguments(script: str) -> None:
    proc = _bash(str(REPO_ROOT / "ops" / "demo" / script), "--nope")
    assert proc.returncode == 2
    assert "unknown argument" in proc.stderr


def test_run_sh_lists_the_pipeline_steps() -> None:
    proc = _bash(str(REPO_ROOT / "ci" / "run.sh"), "--list")
    assert proc.returncode == 0, proc.stderr
    steps = proc.stdout.split()
    assert steps == ["sync", "ruff", "format", "imports", "mypy", "pytest", "licences"]


def test_run_sh_rejects_unknown_step() -> None:
    proc = _bash(str(REPO_ROOT / "ci" / "run.sh"), "--only", "nope")
    assert proc.returncode != 0


def test_run_sh_licence_step_covers_the_console() -> None:
    text = (REPO_ROOT / "ci" / "run.sh").read_text(encoding="utf-8")
    assert "--npm-lock console/package-lock.json" in text


def test_run_sh_defaults_uv_system_certs() -> None:
    text = (REPO_ROOT / "ci" / "run.sh").read_text(encoding="utf-8")
    assert 'export UV_SYSTEM_CERTS="${UV_SYSTEM_CERTS:-1}"' in text


def test_run_sh_makes_db_fixtures_fail_instead_of_skip() -> None:
    text = (REPO_ROOT / "ci" / "run.sh").read_text(encoding="utf-8")
    assert 'export SIBYL_REQUIRE_PG="${SIBYL_REQUIRE_PG:-1}"' in text
    assert 'export CI="${CI:-1}"' in text
    assert "ci/skip_guard.py" in text


def test_run_sh_runs_the_scenario_smoke_beside_the_parallel_suite() -> None:
    """R71 (10-minute budget): the real-time smoke scenarios run in their own process while the
    rest runs on xdist workers; nothing is dropped: one coverage floor over both, both junit
    files guarded for skips, and a smoke failure fails the step."""
    text = (REPO_ROOT / "ci" / "run.sh").read_text(encoding="utf-8")
    assert 'SMOKE_TEST="sibyl-sim/tests/scenarios/test_smoke.py"' in text
    assert '--ignore="$SMOKE_TEST"' in text
    assert 'WORKERS="${SIBYL_CI_WORKERS:-6}"' in text and "--dist loadfile" in text
    assert "coverage combine" in text and '--fail-under="$COV_MIN"' in text
    assert 'skip_guard.py "$OUT/junit.xml"' in text
    assert 'skip_guard.py "$OUT/junit-smoke.xml"' in text
    assert 'wait "$smoke_pid"' in text
    # four in-process stacks hold ~80 connections: concurrent only when the cluster has room
    assert 'PG_SLOTS="${SIBYL_CI_PG_SLOTS:-150}"' in text and "free_pg_slots" in text
    # timing-budget tests never share the CPU with xdist workers: they run alone, afterwards
    assert '-m "not serial"' in text and "-m serial" in text
    assert 'skip_guard.py "$OUT/junit-serial.xml"' in text


def test_run_sh_refuses_to_test_against_a_dead_database() -> None:
    env = {**os.environ, "SIBYL_PG_ADMIN_DSN": "postgresql://postgres@127.0.0.1:1/postgres"}
    proc = _bash(str(REPO_ROOT / "ci" / "run.sh"), "--only", "pytest", env=env)
    assert proc.returncode != 0
    assert "not accepting connections" in proc.stderr
    assert "passed" not in proc.stdout, "pytest must not run (and skip) against a dead DB"


JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest">
<testcase classname="a" name="ok"/>
<testcase classname="a" name="xf"><skipped type="pytest.xfail" message="wall"/></testcase>
<testcase classname="a" name="ca">
<skipped type="pytest.skip" message="no SIBYL_EXTRA_CA_FILE: x"/></testcase>
{extra}
</testsuite></testsuites>
"""
DB_SKIP = (
    '<testcase classname="db" name="t">'
    '<skipped type="pytest.skip" message="PG17 dev cluster on :5433 not up"/></testcase>'
)


def test_skip_guard_allows_xfail_and_allow_listed_skips(
    tmp_path: Path, skip_guard: ModuleType
) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT.format(extra=""))
    assert skip_guard.main([str(junit)]) == 0


def test_skip_guard_fails_on_a_skipped_db_test(
    tmp_path: Path, skip_guard: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT.format(extra=DB_SKIP))
    assert skip_guard.main([str(junit)]) == 1
    assert "db::t: PG17 dev cluster" in capsys.readouterr().out


def test_skip_guard_extra_allowances_from_env(
    tmp_path: Path, skip_guard: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT.format(extra=DB_SKIP))
    monkeypatch.setenv("SIBYL_CI_ALLOW_SKIPS", "dev cluster on :5433")
    assert skip_guard.main([str(junit)]) == 0


def test_skip_guard_missing_junit_is_an_error(tmp_path: Path, skip_guard: ModuleType) -> None:
    assert skip_guard.main([str(tmp_path / "none.xml")]) == 2
