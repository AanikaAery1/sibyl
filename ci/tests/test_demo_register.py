"""ops/demo/register.py: the demo's snapshot + audit-anchor signing keys and the sim dev host.

Unit level, no Docker: asyncpg is replaced by a recording fake. test_demo_live.py runs the
script for real inside the migrate container.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

OPS_DIR = Path(__file__).resolve().parents[2] / "ops"


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _key(kid: str, raw: bytes) -> dict[str, str]:
    return {
        "kid": kid,
        "alg": "Ed25519",
        "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
    }


SNAP_RAW, ANCHOR_RAW = bytes(range(32)), bytes(range(32, 64))
SNAP = _key("snapshot-0123456789abcdef", SNAP_RAW)
ANCHOR = _key("audit-anchor-0123456789abcdef", ANCHOR_RAW)


class FakeConn:
    def __init__(self, active: dict[str, dict[str, Any]]) -> None:
        self.active = active  # purpose -> active row
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.closed = False

    @asynccontextmanager
    async def _tx(self) -> Any:
        yield

    def transaction(self) -> Any:
        return self._tx()

    async def execute(self, sql: str, *args: Any) -> None:
        self.executed.append((sql, args))

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        return self.active.get(args[0])

    async def close(self) -> None:
        self.closed = True

    def inserted(self) -> dict[str, tuple[Any, ...]]:
        """purpose -> (kid, public_key, private_key_ref, ...) of each signing_key insert."""
        return {a[1]: a for s, a in self.executed if "INSERT INTO sibyl.signing_key" in s}


@pytest.fixture
def register() -> ModuleType:
    return load_module("sibyl_ops_demo_register", OPS_DIR / "demo" / "register.py")


def _run(
    register: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    active: dict[str, dict[str, Any]] | None = None,
) -> tuple[int, FakeConn, dict[str, Any]]:
    conn = FakeConn(active or {})
    seen: dict[str, Any] = {}

    async def connect(**kwargs: Any) -> FakeConn:
        seen.update(kwargs)
        return conn

    monkeypatch.setattr(register.asyncpg, "connect", connect)
    for key, value in {
        "SIBYL_SNAPSHOT_PIN": json.dumps(SNAP),
        "SIBYL_ANCHOR_PIN": json.dumps(ANCHOR),
        "SIBYL_DB_HOST": "postgres",
        "SIBYL_DB_PORT": "5432",
        "SIBYL_DB_NAME": "sibyl",
        "SIBYL_DB_USER": "sibyl_migrate",
        "SIBYL_DB_PASSWORD": "pw",
    }.items():
        monkeypatch.setenv(key, value)
    code = asyncio.run(register.main())
    return code, conn, seen


def test_registers_both_keys_and_the_dev_host_as_the_migrate_role(
    register: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, conn, seen = _run(register, monkeypatch)
    assert code == 0 and conn.closed
    assert seen["user"] == "sibyl_migrate" and seen["host"] == "postgres"
    dev = [a for s, a in conn.executed if "base_url_dev_host" in s]
    assert dev == [("sim",)]
    inserted = conn.inserted()
    assert inserted["snapshot"][0] == SNAP["kid"]
    assert inserted["snapshot"][2:4] == (SNAP_RAW, "env:SIBYL_SNAPSHOT_SIGNING_KEY")
    assert inserted["audit_anchor"][0] == ANCHOR["kid"]
    assert inserted["audit_anchor"][2:4] == (ANCHOR_RAW, "env:SIBYL_ANCHOR_SIGNING_KEY")


def test_same_active_keys_are_left_alone(
    register: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = {
        "snapshot": {"kid": SNAP["kid"], "public_key": SNAP_RAW},
        "audit_anchor": {"kid": ANCHOR["kid"], "public_key": ANCHOR_RAW},
    }
    code, conn, _ = _run(register, monkeypatch, active)
    assert code == 0
    assert conn.inserted() == {}


def test_a_different_active_key_is_never_replaced_but_the_other_is_registered(
    register: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = {"snapshot": {"kid": "other", "public_key": b"x" * 32}}
    code, conn, _ = _run(register, monkeypatch, active)
    assert code == 3
    assert set(conn.inserted()) == {"audit_anchor"}


def test_a_malformed_key_is_refused(register: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIBYL_ANCHOR_PIN", json.dumps({**ANCHOR, "public_key": "AAAA"}))
    with pytest.raises(SystemExit, match="32 bytes"):
        register._public_key("SIBYL_ANCHOR_PIN")


def test_up_sh_feeds_both_public_keys_to_register_py() -> None:
    text = (OPS_DIR / "demo" / "up.sh").read_text(encoding="utf-8")
    assert 'migrate python - < "$here/register.py"' in text
    assert "SIBYL_SNAPSHOT_PIN=" in text and "SIBYL_ANCHOR_PIN=" in text
    assert "public/anchor_key.json" in text
