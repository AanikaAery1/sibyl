"""Shared fixtures: a recording ingest transport, an advanceable clock, test keys."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sibyl.testing import Ingest, OffsetClock


@pytest.fixture
def ingest() -> Ingest:
    return Ingest()


@pytest.fixture
def clock() -> OffsetClock:
    return OffsetClock()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "SIBYL_API_KEY",
        "SIBYL_ENDPOINT",
        "SIBYL_AGENT_ID",
        "SIBYL_CAPTURE_MODE",
        "SIBYL_ENV",
        "SIBYL_API_URL",
        "SIBYL_SCRUB_SALT",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    import sibyl

    shutdown = getattr(sibyl, "shutdown", None)
    if shutdown is not None:
        shutdown(0.5)
