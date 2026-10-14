"""Feed parsing and the fetch guard (no network: httpx.MockTransport and a fake resolver)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sibyl_control.worker.status_poller.feeds import parse_feed
from sibyl_control.worker.status_poller.fetch import FeedError, FetchPolicy, fetch_feed

PUBLIC = "93.184.216.34"


def statuspage(indicator: str, **extra: Any) -> dict[str, Any]:
    return {"page": {"id": "x"}, "status": {"indicator": indicator, "description": "d"}, **extra}


@pytest.mark.parametrize(
    ("indicator", "status"),
    [
        ("none", "operational"),
        ("minor", "degraded_performance"),
        ("major", "partial_outage"),
        ("critical", "major_outage"),
        ("maintenance", "maintenance"),
        ("weird", "unknown"),
    ],
)
def test_statuspage_indicator_mapping(indicator: str, status: str) -> None:
    assert parse_feed(statuspage(indicator)).status == status


def test_statuspage_incident_and_maintenance() -> None:
    doc = statuspage(
        "major",
        incidents=[
            {"id": "inc1", "name": "API errors", "status": "investigating", "body": "never stored"}
        ],
    )
    parsed = parse_feed(doc)
    assert parsed.incident_ref == "inc1"
    assert "body" not in str(parsed.raw), "only ids, names and states are kept"
    maint = statuspage("none", scheduled_maintenances=[{"id": "m1", "status": "in_progress"}])
    assert parse_feed(maint).status == "maintenance"


def test_native_feed_and_garbage() -> None:
    assert parse_feed({"status": "partial_outage", "incident_id": "z"}).status == "partial_outage"
    assert parse_feed({"status": "partial_outage"}).incident_ref is None
    assert parse_feed({"nope": 1}).status == "unknown"
    assert parse_feed([1, 2]).status == "unknown"  # type: ignore[arg-type]


async def _resolve_public(host: str) -> list[str]:
    return [PUBLIC]


async def _resolve_private(host: str) -> list[str]:
    return ["10.0.0.5"]


def client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_fetch_returns_json() -> None:
    async with client(lambda r: httpx.Response(200, json=statuspage("none"))) as c:
        doc = await fetch_feed(
            "https://status.example.com/api/v2/summary.json",
            c,
            FetchPolicy(resolve=_resolve_public),
        )
    assert doc["status"]["indicator"] == "none"


@pytest.mark.parametrize(
    ("url", "resolver", "match"),
    [
        ("http://status.example.com/x.json", _resolve_public, "https"),
        ("https://status.example.com/x.json", _resolve_private, "private"),
        ("https://127.0.0.1/x.json", _resolve_public, "private"),
        ("https://[::1]/x.json", _resolve_public, "private"),
        ("https://169.254.169.254/latest", _resolve_public, "private"),
        ("ftp://status.example.com/x", _resolve_public, "https"),
        ("https://user:pw@status.example.com/x", _resolve_public, "credentials"),
    ],
)
async def test_fetch_guard_refuses_unsafe_targets(url: str, resolver: Any, match: str) -> None:
    async with client(lambda r: httpx.Response(200, json={})) as c:
        with pytest.raises(FeedError, match=match):
            await fetch_feed(url, c, FetchPolicy(resolve=resolver))


async def test_dev_hosts_allow_the_local_double_over_http() -> None:
    async with client(lambda r: httpx.Response(200, json={"status": "operational"})) as c:
        doc = await fetch_feed(
            "http://sibyl-sim:8090/status.json",
            c,
            FetchPolicy(resolve=_resolve_private, dev_hosts=frozenset({"sibyl-sim"})),
        )
    assert doc == {"status": "operational"}


async def test_fetch_refuses_redirects_errors_and_oversize() -> None:
    policy = FetchPolicy(resolve=_resolve_public, max_bytes=100)
    url = "https://status.example.com/s.json"
    async with client(lambda r: httpx.Response(302, headers={"location": "http://10.0.0.1"})) as c:
        with pytest.raises(FeedError, match="302"):
            await fetch_feed(url, c, policy)
    async with client(lambda r: httpx.Response(200, content=b"x" * 500)) as c:
        with pytest.raises(FeedError, match="too large"):
            await fetch_feed(url, c, policy)
    async with client(lambda r: httpx.Response(200, content=b"not json")) as c:
        with pytest.raises(FeedError, match="JSON"):
            await fetch_feed(url, c, FetchPolicy(resolve=_resolve_public))
