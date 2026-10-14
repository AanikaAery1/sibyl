"""Process-global client handle; every module-level helper is a no-op until `init()`."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sibyl._client import Client

log = logging.getLogger("sibyl")
_lock = threading.Lock()
_client: Client | None = None
_warned: set[str] = set()


def get() -> Client | None:
    return _client


def set_client(client: Client | None) -> Client | None:
    global _client
    with _lock:
        previous, _client = _client, client
    return previous


def warn_once(key: str, message: str) -> None:
    if key not in _warned:
        _warned.add(key)
        log.warning("sibyl: %s", message)
