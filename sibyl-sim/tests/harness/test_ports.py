"""Doubles ports: skip a base another run (another worktree's CI) is holding."""

from __future__ import annotations

import socket

from sibyl_sim.harness.ports import free_base, port_free


def _listen() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock, sock.getsockname()[1]


def test_a_held_port_is_not_free_and_its_base_is_skipped() -> None:
    held, port = _listen()
    try:
        assert not port_free(port)
        # a base whose second port is held is skipped for the next candidate
        base = free_base([port - 1, port + 10], width=2)
        assert base == port + 10 or (base is None and not port_free(port + 10))
    finally:
        held.close()
    assert port_free(port)


def test_no_free_base_is_none() -> None:
    held, port = _listen()
    try:
        assert free_base([port], width=1) is None
    finally:
        held.close()
