"""Status-feed double: scripted incidents, truthful / late / lies, feed outage, admin API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from sibyl_sim.doubles import SimState, build_state, control_app, doubles_app
from sibyl_sim.status_feed import FeedError, ProviderFeed

SUMMARY = "/status/{}/api/v2/summary.json"


@dataclass
class FakeClock:
    now: float = 1_790_000_000.0

    def __call__(self) -> float:
        return self.now


async def _no_sleep(seconds: float) -> None:
    return None


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def state(clock: FakeClock) -> SimState:
    return build_state(seed=3, clock=clock, sleep=_no_sleep, admin_token="")


@pytest.fixture
async def control(state: SimState) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=control_app(state))
    async with httpx.AsyncClient(transport=transport, base_url="http://sim") as client:
        yield client


async def wire(control: httpx.AsyncClient, provider: str = "anthropic") -> str:
    response = await control.get(SUMMARY.format(provider))
    assert response.status_code == 200
    return str(response.json()["sibyl_sim"]["wire_status"])


async def test_default_feed_is_operational_statuspage_json(control: httpx.AsyncClient) -> None:
    doc = (await control.get(SUMMARY.format("openai"))).json()
    assert doc["status"] == {"indicator": "none", "description": "All Systems Operational"}
    assert doc["components"][0]["status"] == "operational" and doc["incidents"] == []
    small = (await control.get("/status/openai/api/v2/status.json")).json()
    assert set(small) == {"page", "status"}
    assert (await control.get(SUMMARY.format("nope"))).status_code == 404


async def test_scripted_incident_timeline(control: httpx.AsyncClient, clock: FakeClock) -> None:
    await control.put(
        "/_sim/status/anthropic",
        json={
            "incidents": [
                {
                    "name": "Elevated latency",
                    "status": "degraded_performance",
                    "start_s": 60,
                    "duration_s": 120,
                },
                {"status": "partial_outage", "start_s": 120, "duration_s": 30},
            ]
        },
    )
    assert await wire(control) == "operational"
    clock.now += 60
    assert await wire(control) == "degraded_performance"
    clock.now += 60
    doc = (await control.get(SUMMARY.format("anthropic"))).json()
    assert doc["sibyl_sim"]["wire_status"] == "partial_outage"
    assert doc["status"]["indicator"] == "major" and len(doc["incidents"]) == 2
    clock.now += 31
    assert await wire(control) == "degraded_performance"
    clock.now += 100
    assert await wire(control) == "operational"


async def test_truthful_mirrors_the_linked_double_outage(control: httpx.AsyncClient) -> None:
    await control.post("/_sim/doubles/anthropic-stub/outage", json={"on": True})
    doc = (await control.get(SUMMARY.format("anthropic"))).json()
    assert doc["status"]["indicator"] == "critical"
    assert doc["components"][0]["status"] == "major_outage"
    assert await wire(control, "openai") == "operational"  # other providers unaffected


async def test_late_feed_lags_reality(control: httpx.AsyncClient, clock: FakeClock) -> None:
    """S-17: the double is down but the status page keeps saying operational."""
    await control.patch("/_sim/status/anthropic", json={"mode": "late", "delay_s": 300})
    await control.post("/_sim/doubles/anthropic-stub/outage", json={"on": True})
    clock.now += 299
    assert await wire(control) == "operational"
    clock.now += 2
    assert await wire(control) == "major_outage"


async def test_lying_feed_ignores_healthy_traffic(
    control: httpx.AsyncClient, state: SimState
) -> None:
    """S-16: the page says major outage while the double serves 200s."""
    await control.patch("/_sim/status/openai", json={"mode": "lies", "lie_status": "major_outage"})
    doc = (await control.get(SUMMARY.format("openai"))).json()
    assert doc["status"]["indicator"] == "critical" and doc["incidents"]
    transport = httpx.ASGITransport(app=doubles_app(state))
    async with httpx.AsyncClient(transport=transport, base_url="https://sim") as doubles:
        ok = await doubles.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer k"},
            json={"model": "gpt-5-mini", "messages": []},
        )
        assert ok.status_code == 200
        served = await doubles.get(SUMMARY.format("openai"))
        assert served.json()["status"]["indicator"] == "critical"  # also on the https port
    await control.patch("/_sim/status/openai", json={"lie_status": "operational"})
    assert await wire(control, "openai") == "operational"


async def test_feed_down_returns_503(control: httpx.AsyncClient) -> None:
    await control.patch("/_sim/status/ollama", json={"feed_down": True})
    assert (await control.get(SUMMARY.format("ollama"))).status_code == 503
    assert (await control.get("/status/ollama/api/v2/status.json")).status_code == 503


async def test_maintenance_maps_to_statuspage_spelling(control: httpx.AsyncClient) -> None:
    await control.put(
        "/_sim/status/openai", json={"incidents": [{"status": "maintenance", "start_s": 0}]}
    )
    doc = (await control.get(SUMMARY.format("openai"))).json()
    assert doc["components"][0]["status"] == "under_maintenance"
    assert doc["status"]["indicator"] == "maintenance"


async def test_admin_incident_append_reset_and_validation(control: httpx.AsyncClient) -> None:
    created = await control.post(
        "/_sim/status/anthropic/incidents", json={"status": "major_outage", "start_s": 0}
    )
    assert created.status_code == 201 and created.json()["id"] == "sim-inc-0001"
    assert await wire(control) == "major_outage"
    listing = (await control.get("/_sim/status")).json()
    assert listing["anthropic"]["status"] == "major_outage"
    reset = (await control.post("/_sim/status/anthropic/reset")).json()
    assert reset["incidents"] == [] and reset["link_double"] == "anthropic-stub"
    bad: list[Any] = [
        {"mode": "sometimes"},
        {"delay_s": -1},
        {"lie_status": "fine"},
        {"what": 1},
        {"incidents": "x"},
        {"incidents": [{"status": "nope"}]},
        {"incidents": [{"start_s": "soon"}]},
        {"incidents": [{"duration_s": 0}]},
    ]
    for patch in bad:
        response = await control.patch("/_sim/status/anthropic", json=patch)
        assert response.status_code == 422, patch
    assert (await control.patch("/_sim/status/anthropic", json=[1])).status_code == 422
    assert (
        await control.post("/_sim/status/anthropic/incidents", json={"status": "x"})
    ).status_code == 422
    assert (await control.post("/_sim/status/anthropic/incidents", json=[])).status_code == 422
    assert (await control.get("/_sim/status/nope")).status_code == 404
    assert (await control.post("/_sim/status/nope/incidents", json={})).status_code == 404
    assert (await control.post("/_sim/status/nope/reset")).status_code == 404


def test_feed_is_deterministic_for_identical_scripts() -> None:
    clock = FakeClock()
    feeds = [
        ProviderFeed(provider="p", page_name="P", clock=clock, outage_at=lambda d, t: False)
        for _ in range(2)
    ]
    script = {"incidents": [{"status": "partial_outage", "start_s": 10, "duration_s": 5}]}
    timelines = []
    for feed in feeds:
        feed.configure(script)
        start = clock.now
        timeline = []
        for t in range(0, 20):
            clock.now = start + t
            timeline.append(feed.status()[0])
        clock.now = start
        timelines.append(timeline)
    assert timelines[0] == timelines[1]
    assert timelines[0].count("partial_outage") == 5
    with pytest.raises(FeedError):
        feeds[0].configure({"mode": "x"})
