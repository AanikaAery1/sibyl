"""Pick doubles ports that are free right now.

The doubles' port is part of the seeded world (provider base URLs), so each port has its own
cached template database: a run therefore picks from a *small fixed* set of bases rather than
any random port, and keeps reusing the same few templates. Concurrent CI runs from other
worktrees on the same host take the next free base instead of failing to bind.
"""

from __future__ import annotations

import socket
from collections.abc import Sequence

HOST = "127.0.0.1"


def port_free(port: int, host: str = HOST) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def free_base(candidates: Sequence[int], width: int = 1, host: str = HOST) -> int | None:
    """The first base whose ``width`` consecutive ports are all free, else ``None``."""
    for base in candidates:
        if all(port_free(base + n, host) for n in range(width)):
            return base
    return None


__all__ = ["free_base", "port_free"]
