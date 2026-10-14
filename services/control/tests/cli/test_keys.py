"""``python -m sibyl_control.cli keys …`` against the lane's migrated PG17 database."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sibyl_control.cli import main

KEY_RE = re.compile(r"^sbl_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}$")


def _kit() -> Any:
    name = "sibyl_lane_a_kit"
    if name not in sys.modules:
        path = Path(__file__).resolve().parents[1] / "api" / "auth" / "kit.py"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


kit = _kit()


@pytest.fixture(scope="module")
def lane_db() -> Iterator[Any]:
    if not kit.available():
        pytest.skip("PostgreSQL 17 not reachable (make db-up)")
    db = kit.acquire()
    yield db
    kit.release()


@pytest.fixture
def world(lane_db: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    for key, value in {
        "SIBYL_PG_DSN": lane_db.dsn(),
        "SIBYL_KEK": kit.KEK_B64,
        "SIBYL_KEK_ID": kit.KEK_ID,
        "SIBYL_KEY_PEPPER": kit.PEPPER_HEX,
        "SIBYL_ENV": "live",
    }.items():
        monkeypatch.setenv(key, value)
    return kit.world(lane_db)


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_break_glass_key_without_capture_policy(world: Any, lane_db: Any) -> None:
    code, out, err = run(
        "--json",
        "keys",
        "create",
        world.slug,
        "--name",
        "break-glass",
        "--env",
        "live",
        "--scope",
        "killswitch:pull",
        "--reason",
        "IdP not wired yet",
    )
    assert code == 0, err
    doc = json.loads(out)
    assert KEY_RE.fullmatch(doc["secret"]) and doc["scopes"] == ["killswitch:pull"]
    row = kit.audit_rows(lane_db, world.tenant, "api_key.created")[-1]
    assert row["actor_type"] == "system" and row["detail"]["break_glass"] is True
    assert doc["secret"] not in json.dumps(row["detail"])
    mixed = run(
        "keys",
        "create",
        world.slug,
        "--name",
        "x",
        "--env",
        "live",
        "--scope",
        "killswitch:pull",
        "--scope",
        "routing:read",
    )
    assert mixed[0] == 2 and "break_glass_scope_exclusive" in mixed[2]


def test_rules_capture_policy_env_and_agents(world: Any, lane_db: Any) -> None:
    base = ("keys", "create", world.slug, "--name", "gw")
    assert "capture policy" in run(*base, "--env", "live", "--scope", "gateway:proxy")[2]
    kit.add_capture_policy(lane_db, world.tenant, world.users["owner"])
    assert "env_mismatch" in run(*base, "--env", "test", "--scope", "gateway:proxy")[2]
    assert (
        "no agent" in run(*base, "--env", "live", "--scope", "ingest:write", "--agent", "nope")[2]
    )
    code, out, err = run(
        "--json",
        *base,
        "--env",
        "live",
        "--scope",
        "ingest:write",
        "--agent",
        "agent-in-g1",
        "--expires-days",
        "30",
    )
    assert code == 0, err
    assert json.loads(out)["scopes"] == ["ingest:write"]
    assert (
        "expires_at_out_of_range"
        in run(*base, "--env", "live", "--scope", "ingest:write", "--expires-days", "500")[2]
    )


def test_list_and_revoke(world: Any, lane_db: Any) -> None:
    kit.add_capture_policy(lane_db, world.tenant, world.users["owner"])
    made = json.loads(
        run(
            "--json",
            "keys",
            "create",
            world.slug,
            "--name",
            "gw",
            "--env",
            "live",
            "--scope",
            "gateway:proxy",
        )[1]
    )
    listed = json.loads(run("--json", "keys", "list", world.slug)[1])
    assert [k["prefix"] for k in listed] == [made["prefix"]]
    assert all("secret" not in k for k in listed)
    assert (
        "at least 10" in run("keys", "revoke", world.slug, made["prefix"], "--reason", "short")[2]
    )
    code, out, err = run(
        "--json", "keys", "revoke", world.slug, made["prefix"], "--reason", "operator drill done"
    )
    assert code == 0 and json.loads(out)["status"] == "revoked", err
    assert run("keys", "revoke", world.slug, made["id"], "--reason", "operator drill done")[0] == 2
    assert json.loads(run("--json", "keys", "list", world.slug)[1]) == []
    assert len(json.loads(run("--json", "keys", "list", world.slug, "--all")[1])) == 1
    events = [
        e for e in kit.outbox_events(lane_db, world.tenant) if e["event_type"] == "policy_changed"
    ]
    assert len(events) >= 2  # create + revoke (plus the agent registrations)
