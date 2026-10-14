"""Unit tests for the tenant transaction against a fake pool (no Postgres needed)."""

from contextlib import asynccontextmanager
from uuid import UUID

import pytest
from sibyl_control.core.db import SET_TENANT_SQL, Database

TENANT = UUID("01927000-0000-7000-8000-000000000001")


class FakeTx:
    def __init__(self, log: list[str], kwargs: dict) -> None:
        self.log = log
        self.kwargs = kwargs

    async def __aenter__(self):
        self.log.append(f"BEGIN {sorted(self.kwargs.items())}")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.log.append("ROLLBACK" if exc_type else "COMMIT")
        return False


class FakeConn:
    def __init__(self, log: list[str]) -> None:
        self.log = log

    def transaction(self, **kwargs):
        return FakeTx(self.log, kwargs)

    async def execute(self, sql: str, *args):
        self.log.append(sql if not args else f"{sql} {args}")


class FakePool:
    def __init__(self) -> None:
        self.log: list[str] = []

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self.log)

    async def close(self) -> None:
        self.log.append("CLOSE")


async def test_set_tenant_is_the_first_statement_in_the_transaction() -> None:
    pool = FakePool()
    db = Database(pool)
    async with db.tenant_tx(TENANT) as conn:
        await conn.execute("SELECT 1")
    assert pool.log[0].startswith("BEGIN")
    assert pool.log[1] == f"{SET_TENANT_SQL} ({TENANT!r},)"
    assert pool.log[2:] == ["SELECT 1", "COMMIT"]
    assert "sibyl.set_tenant" in SET_TENANT_SQL


async def test_statement_timeout_is_local_and_after_set_tenant() -> None:
    pool = FakePool()
    async with Database(pool).tenant_tx(TENANT, statement_timeout_ms=1500):
        pass
    assert pool.log[1].startswith(SET_TENANT_SQL)
    assert pool.log[2] == "SET LOCAL statement_timeout = 1500"


async def test_errors_roll_back() -> None:
    pool = FakePool()
    with pytest.raises(RuntimeError):
        async with Database(pool).tenant_tx(TENANT):
            raise RuntimeError("boom")
    assert pool.log[-1] == "ROLLBACK"


async def test_readonly_flag_reaches_the_transaction() -> None:
    pool = FakePool()
    async with Database(pool).tenant_tx(TENANT, readonly=True):
        pass
    assert "('readonly', True)" in pool.log[0]


async def test_tenant_must_be_a_uuid() -> None:
    with pytest.raises(TypeError):
        async with Database(FakePool()).tenant_tx("not-a-uuid"):  # type: ignore[arg-type]
            pass


async def test_pre_tenant_runs_without_set_tenant_and_read_only() -> None:
    pool = FakePool()
    async with Database(pool).pre_tenant() as conn:
        await conn.execute("SELECT 1")
    assert not any("set_tenant" in line for line in pool.log)
    assert "('readonly', True)" in pool.log[0]
