"""GatewayActor wire shape: the headers a scripted agent sends to the gateway."""

from __future__ import annotations

import httpx
from sibyl_sim.actors.agents import GatewayActor
from sibyl_sim.actors.traffic import Arrival
from sibyl_sim.harness.clock import RunClock
from sibyl_sim.harness.world import Endpoints, World
from sibyl_sim.scenarios.model import Profile

from .conftest import KB, M


async def _sent_headers(world: World, profile: Profile) -> httpx.Headers:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": []}, headers={"x-sibyl-route": "primary"})

    endpoints = Endpoints("http://api", "http://ingest", "http://gw", "http://sim", "http://d")
    tenant = world.tenant(M)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        actor = GatewayActor(
            KB, tenant.agent(KB.slug), tenant, profile, [], endpoints, RunClock(), client=client
        )
        await actor.call(Arrival(0, 0.0, "req-1", "hello", 10))
    [request] = seen
    return request.headers


async def test_profile_fallback_is_sent_as_the_x_sibyl_fallback_header(world: World) -> None:
    headers = await _sent_headers(world, Profile("busy_no_inline", rps=0.5, fallback="none"))
    assert headers["x-sibyl-fallback"] == "none"


async def test_default_profile_sends_no_fallback_header(world: World) -> None:
    headers = await _sent_headers(world, Profile("busy", rps=0.5))
    assert "x-sibyl-fallback" not in headers
