"""Host-wide stack slots: every `sibyl_sim run` on the host (any worktree) shares a fixed number
of in-process stacks, so together they never exceed the shared Postgres's connections."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from sibyl_sim.harness.hostslots import host_slot


async def test_slots_bound_concurrency_and_are_released(tmp_path: Path) -> None:
    inside, peak = 0, 0

    async def job() -> None:
        nonlocal inside, peak
        async with host_slot(limit=2, directory=tmp_path, poll_s=0.01):
            inside += 1
            peak = max(peak, inside)
            await asyncio.sleep(0.05)
            inside -= 1

    await asyncio.gather(*(job() for _ in range(6)))
    assert peak == 2 and inside == 0


async def test_a_slot_held_elsewhere_is_waited_for(tmp_path: Path) -> None:
    """flock is per open file description: a holder in this process looks like another run."""
    async with host_slot(limit=1, directory=tmp_path, poll_s=0.01):
        started = time.monotonic()
        waiter = asyncio.create_task(_take(tmp_path))
        await asyncio.sleep(0.1)
        assert not waiter.done()
    waited = await waiter
    assert waited >= 0.09 and time.monotonic() - started < 2


async def _take(directory: Path) -> float:
    t0 = time.monotonic()
    async with host_slot(limit=1, directory=directory, poll_s=0.01):
        return time.monotonic() - t0


def test_zero_means_unlimited(tmp_path: Path) -> None:
    async def both() -> None:
        async with host_slot(limit=0, directory=tmp_path), host_slot(limit=0, directory=tmp_path):
            pass

    asyncio.run(both())
    assert not list(tmp_path.iterdir())
