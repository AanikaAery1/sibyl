"""Doubles fixtures: a settable clock, a recording sleep, ASGI clients for both apps."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx
import pytest
from sibyl_sim.doubles import SimState, build_state, control_app, doubles_app

AUTH = {"Authorization": "Bearer sk-sim-meridian"}


@dataclass
class FakeClock:
    now: float = 1_790_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Sleeps:
    calls: list[float] = field(default_factory=list)

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def sleeps() -> Sleeps:
    return Sleeps()


@pytest.fixture
def state(clock: FakeClock, sleeps: Sleeps) -> SimState:
    return build_state(seed=7, clock=clock, sleep=sleeps, admin_token="")


@pytest.fixture
async def doubles(state: SimState) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=doubles_app(state))
    async with httpx.AsyncClient(
        transport=transport, base_url="https://sim.test", headers=AUTH
    ) as client:
        yield client


@pytest.fixture
async def control(state: SimState) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=control_app(state))
    async with httpx.AsyncClient(transport=transport, base_url="http://sim.test") as client:
        yield client
