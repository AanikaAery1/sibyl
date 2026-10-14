from __future__ import annotations

from collections.abc import Iterator

import pytest

from ..fakes.servers import ServerThread
from ..fakes.upstream import FakeUpstream


@pytest.fixture(scope="module")
def upstream_server() -> Iterator[tuple[FakeUpstream, str]]:
    fake = FakeUpstream()
    with ServerThread(fake) as server:
        yield fake, server.url


@pytest.fixture
def upstream(upstream_server: tuple[FakeUpstream, str]) -> tuple[FakeUpstream, str]:
    fake, url = upstream_server
    fake.plan.clear()
    fake.seen.clear()
    return fake, url
