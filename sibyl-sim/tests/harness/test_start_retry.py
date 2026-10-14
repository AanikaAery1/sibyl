"""A shared dev cluster can be out of connection slots for a moment (another worktree's CI);
a stack waits for slots at start instead of erroring the scenario, within a bound."""

from __future__ import annotations

import asyncpg
import pytest
from sibyl_sim.harness.inprocess.stack import start_with_retry


class Flaky:
    def __init__(self, failures: int) -> None:
        self.failures, self.starts = failures, 0

    async def start(self) -> Flaky:
        self.starts += 1
        if self.starts <= self.failures:
            raise asyncpg.TooManyConnectionsError("remaining connection slots are reserved")
        return self


async def test_a_full_cluster_is_waited_out() -> None:
    stack = Flaky(failures=2)
    assert await start_with_retry(stack, attempts=3, wait_s=0.0) is stack
    assert stack.starts == 3


async def test_the_wait_is_bounded() -> None:
    stack = Flaky(failures=5)
    with pytest.raises(asyncpg.TooManyConnectionsError):
        await start_with_retry(stack, attempts=3, wait_s=0.0)
    assert stack.starts == 3


async def test_a_full_cluster_is_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """No free slot is not "PostgreSQL down": the stack start waits for a slot instead of the
    run being reported as a harness error."""
    from sibyl_sim.harness.inprocess import database as pg

    async def full(*_: object, **__: object) -> None:
        raise asyncpg.TooManyConnectionsError("remaining connection slots are reserved")

    async def down(*_: object, **__: object) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(pg.asyncpg, "connect", full)
    assert await pg.available()
    monkeypatch.setattr(pg.asyncpg, "connect", down)
    assert not await pg.available()


async def test_other_errors_are_not_retried() -> None:
    class Broken:
        starts = 0

        async def start(self) -> None:
            self.starts += 1
            raise RuntimeError("cannot bind")

    stack = Broken()
    with pytest.raises(RuntimeError):
        await start_with_retry(stack, attempts=3, wait_s=0.0)
    assert stack.starts == 1
