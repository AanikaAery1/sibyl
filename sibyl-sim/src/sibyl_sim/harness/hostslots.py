"""Host-wide stack slots.

One in-process stack holds about 20 Postgres connections and the dev cluster has 100. Separate
`sibyl_sim run` processes (several worktrees, CI beside an investigation) cannot see each other,
so each stack takes one of ``SIBYL_SIM_HOST_SLOTS`` (default 4) slots before it boots: a slot is
an exclusive ``flock`` on ``<dir>/slot-<n>.lock`` (default ``$TMPDIR/sibyl-sim-slots``). The lock
dies with its process, so a crashed run never leaks a slot. ``0`` disables the limit.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import logging
import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

log = logging.getLogger("sibyl_sim.harness")
SLOTS_ENV = "SIBYL_SIM_HOST_SLOTS"
DIR_ENV = "SIBYL_SIM_SLOT_DIR"
DEFAULT_SLOTS = 4


def configured_slots() -> int:
    try:
        return max(0, int(os.environ.get(SLOTS_ENV, DEFAULT_SLOTS)))
    except ValueError:
        return DEFAULT_SLOTS


def slot_dir() -> Path:
    return Path(os.environ.get(DIR_ENV) or Path(tempfile.gettempdir()) / "sibyl-sim-slots")


def _try(directory: Path, limit: int) -> int | None:
    directory.mkdir(parents=True, exist_ok=True)
    for n in range(limit):
        fd = os.open(directory / f"slot-{n}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            continue
        return fd
    return None


@contextlib.asynccontextmanager
async def host_slot(
    *, limit: int | None = None, directory: Path | None = None, poll_s: float = 2.0
) -> AsyncIterator[None]:
    """Hold one host slot for the duration (waits, polling, while all are taken)."""
    limit = configured_slots() if limit is None else limit
    if limit <= 0:
        yield
        return
    where = directory or slot_dir()
    fd = _try(where, limit)
    if fd is None:
        log.warning("all %d host stack slots are taken; waiting (%s)", limit, where)
    while fd is None:
        await asyncio.sleep(poll_s)
        fd = _try(where, limit)
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


__all__ = ["DEFAULT_SLOTS", "configured_slots", "host_slot", "slot_dir"]
