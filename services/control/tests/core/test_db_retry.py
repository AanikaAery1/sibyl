"""H2: bounded, jittered retry of whole tenant transactions on 40P01 / 40001 (no Postgres)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import UUID

import pytest
from sibyl_control.core.db import (
    RETRYABLE_SQLSTATES,
    Database,
    is_retryable,
    retry_transient,
)

TENANT = UUID("01927000-0000-7000-8000-000000000001")


class PgError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


class Recorder:
    def __init__(self) -> None:
        self.sleeps: list[float] = []

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)


def failing(times: int, sqlstate: str = "40P01"):
    calls = {"n": 0}

    async def op() -> str:
        calls["n"] += 1
        if calls["n"] <= times:
            raise PgError(sqlstate)
        return "ok"

    return op, calls


def test_only_deadlock_and_serialization_failures_are_retryable() -> None:
    assert frozenset({"40P01", "40001"}) == RETRYABLE_SQLSTATES
    assert is_retryable(PgError("40P01")) and is_retryable(PgError("40001"))
    assert not is_retryable(PgError("23505"))
    assert not is_retryable(RuntimeError("no sqlstate"))


@pytest.mark.parametrize("sqlstate", ["40P01", "40001"])
async def test_transient_failures_are_retried_until_success(sqlstate: str) -> None:
    op, calls = failing(2, sqlstate)
    rec = Recorder()
    assert await retry_transient(op, attempts=3, sleep=rec.sleep, rand=lambda: 0.5) == "ok"
    assert calls["n"] == 3
    assert len(rec.sleeps) == 2


async def test_retries_are_bounded_and_the_last_error_propagates() -> None:
    op, calls = failing(10)
    rec = Recorder()
    with pytest.raises(PgError):
        await retry_transient(op, attempts=3, sleep=rec.sleep)
    assert calls["n"] == 3
    assert len(rec.sleeps) == 2


async def test_non_transient_errors_are_not_retried() -> None:
    op, calls = failing(1, "23505")
    with pytest.raises(PgError):
        await retry_transient(op, attempts=5, sleep=Recorder().sleep)
    assert calls["n"] == 1


async def test_backoff_is_exponential_capped_and_jittered() -> None:
    rec = Recorder()
    op, _ = failing(5)
    await retry_transient(
        op, attempts=6, base_delay_s=0.01, max_delay_s=0.04, sleep=rec.sleep, rand=lambda: 1.0
    )
    assert rec.sleeps == [0.01, 0.02, 0.04, 0.04, 0.04]
    low = Recorder()
    op, _ = failing(1)
    await retry_transient(op, attempts=2, base_delay_s=0.01, sleep=low.sleep, rand=lambda: 0.0)
    assert low.sleeps == [0.005]  # jitter keeps at least half the step


async def test_attempts_must_be_positive() -> None:
    op, _ = failing(0)
    with pytest.raises(ValueError):
        await retry_transient(op, attempts=0)


class FakeTx:
    def __init__(self, log: list[str]) -> None:
        self.log = log

    async def __aenter__(self):
        self.log.append("BEGIN")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.log.append("ROLLBACK" if exc_type else "COMMIT")
        return False


class FakeConn:
    def __init__(self, log: list[str]) -> None:
        self.log = log

    def transaction(self, **kwargs):
        return FakeTx(self.log)

    async def execute(self, sql: str, *args):
        self.log.append("SET_TENANT" if "set_tenant" in sql else sql)


class FakePool:
    def __init__(self) -> None:
        self.log: list[str] = []

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self.log)

    async def close(self) -> None:
        pass


async def test_run_in_tenant_tx_reruns_the_whole_transaction() -> None:
    pool = FakePool()
    db = Database(pool)
    attempts = {"n": 0}

    async def body(conn) -> int:
        attempts["n"] += 1
        await conn.execute("UPDATE x")
        if attempts["n"] == 1:
            raise PgError("40P01")
        return 7

    assert await db.run_in_tenant_tx(TENANT, body, sleep=Recorder().sleep) == 7
    assert pool.log == [
        "BEGIN",
        "SET_TENANT",
        "UPDATE x",
        "ROLLBACK",
        "BEGIN",
        "SET_TENANT",
        "UPDATE x",
        "COMMIT",
    ]
