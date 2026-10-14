"""sibyl.monitor.Client / AsyncClient against a recording httpx.MockTransport."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import ValidationError
from sibyl.monitor import (
    AsyncClient,
    Client,
    MonitorApiError,
    MonitorConfigError,
    apaginate,
    paginate,
)

KEY = "sbl_test_ABCDEFGHIJKL_" + "s" * 43
URL = "https://sibyl.example.com"
AGENT = "0190f1c2-0000-7000-8000-000000000001"
HOLD = "0190f1c2-0000-7000-8000-000000000002"


class Recorder:
    def __init__(self, respond: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._respond = respond

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._respond is not None:
            return self._respond(request)
        return httpx.Response(200, json={"data": [], "next_cursor": None, "has_more": False})

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


def _client(rec: Recorder) -> Client:
    return Client(URL, KEY, transport=httpx.MockTransport(rec))


def test_base_url_is_normalised_and_headers_sent() -> None:
    rec = Recorder()
    with _client(rec) as c:
        assert c.base_url == URL + "/api/v1"
        c.list_agents(limit=5, band="critical", tier=1)
    req = rec.last
    assert req.url.path == "/api/v1/agents"
    assert req.url.params["limit"] == "5" and req.url.params["band"] == "critical"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert req.headers["user-agent"].startswith("sibyl-monitor/")
    assert Client(URL + "/api/v1/", KEY).base_url == URL + "/api/v1"


@pytest.mark.parametrize(
    ("call", "path", "params"),
    [
        (lambda c: c.get_agent(AGENT), f"/api/v1/agents/{AGENT}", {}),
        (lambda c: c.whoami(), "/api/v1/monitors/self", {}),
        (
            lambda c: c.get_fleet_health(band="critical"),
            "/api/v1/fleet/health",
            {"band": "critical"},
        ),
        (
            lambda c: c.get_health(AGENT, verbose=True),
            f"/api/v1/agents/{AGENT}/health",
            {"verbose": "true"},
        ),
        (
            lambda c: c.list_runs(status="error", root_only=True),
            "/api/v1/runs",
            {"status": "error", "root_only": "true"},
        ),
        (lambda c: c.get_run(AGENT), f"/api/v1/runs/{AGENT}", {}),
        (lambda c: c.get_drift(AGENT, limit=3), f"/api/v1/agents/{AGENT}/drift", {"limit": "3"}),
        (lambda c: c.list_alerts(state="open"), "/api/v1/alerts", {"state": "open"}),
        (lambda c: c.get_alert(AGENT), f"/api/v1/alerts/{AGENT}", {}),
        (lambda c: c.list_incidents(open=True), "/api/v1/incidents", {"open": "true"}),
        (lambda c: c.get_incident(AGENT), f"/api/v1/incidents/{AGENT}", {}),
        (
            lambda c: c.list_held_actions(agent_id=UUID(AGENT)),
            "/api/v1/held-actions",
            {"agent_id": AGENT},
        ),
        (lambda c: c.get_held_action(HOLD), f"/api/v1/held-actions/{HOLD}", {}),
        (lambda c: c.list_findings(source="external"), "/api/v1/findings", {"source": "external"}),
        (lambda c: c.get_finding(HOLD), f"/api/v1/findings/{HOLD}", {}),
    ],
)
def test_read_routes(call: Callable[[Client], Any], path: str, params: dict[str, str]) -> None:
    rec = Recorder()
    with _client(rec) as c:
        call(c)
    assert rec.last.method == "GET"
    assert rec.last.url.path == path
    assert dict(rec.last.url.params) == params


def test_list_values_repeat_and_none_is_dropped() -> None:
    rec = Recorder()
    with _client(rec) as c:
        c.list_held_actions(state=["pending", "approved"], tool=None)
    assert rec.last.url.params.get_list("state") == ["pending", "approved"]
    assert "tool" not in rec.last.url.params


def test_path_ids_must_be_uuids() -> None:
    with _client(Recorder()) as c, pytest.raises(ValueError, match="not a UUID"):
        c.get_agent("../tenant")


def test_submit_finding_body_and_idempotency() -> None:
    rec = Recorder(lambda r: httpx.Response(201, json={"id": "x", "source": "external"}))
    with _client(rec) as c:
        out = c.submit_finding(
            kind="anomaly",
            subject_kind="agent",
            subject_id=AGENT,
            severity="critical",
            summary="error rate tripled",
            body={"evidence": [1, 2]},
            model="claude-fable-5-1",
            provider="anthropic",
        )
        c.submit_finding(
            kind="fleet_summary",
            subject_kind="fleet",
            severity="info",
            summary="ok",
            idempotency_key="fixed-key",
        )
    assert out["source"] == "external"
    first, second = rec.requests
    assert first.method == "POST" and first.url.path == "/api/v1/findings"
    assert UUID(first.headers["idempotency-key"])
    body = json.loads(first.content)
    assert body == {
        "kind": "anomaly",
        "subject_kind": "agent",
        "subject_id": AGENT,
        "severity": "critical",
        "summary": "error rate tripled",
        "body": {"evidence": [1, 2]},
        "model": "claude-fable-5-1",
        "provider": "anthropic",
    }
    assert second.headers["idempotency-key"] == "fixed-key"
    assert "body" not in json.loads(second.content)


def test_submit_finding_is_validated_client_side() -> None:
    rec = Recorder()
    with _client(rec) as c, pytest.raises(ValidationError):
        c.submit_finding(
            kind="fleet_summary",
            subject_kind="agent",
            severity="info",
            summary="x",
            subject_id=AGENT,
        )
    assert rec.requests == []


def test_recommend_on_held_action() -> None:
    rec = Recorder(lambda r: httpx.Response(201, json={"id": "f"}))
    with _client(rec) as c:
        c.recommend_on_held_action(HOLD, "deny", "Amount is 40x the median.", confidence="high")
    body = json.loads(rec.last.content)
    assert body["kind"] == "held_action_review" and body["subject_kind"] == "held_action"
    assert body["subject_id"] == HOLD and body["advice"] == "deny"
    assert body["severity"] == "warning" and body["confidence"] == "high"
    assert body["summary"] == "Monitor advice on held action: deny"


def _problem(status: int, code: str, **headers: str) -> Callable[[httpx.Request], httpx.Response]:
    doc = {
        "type": f"https://sibyl.dev/problems/{code}",
        "title": "T",
        "status": status,
        "detail": "nope",
        "permission": "x",
    }
    return lambda r: httpx.Response(
        status, json=doc, headers={"content-type": "application/problem+json", **headers}
    )


def test_problem_parsing_and_retry_after() -> None:
    with _client(Recorder(_problem(429, "rate_limited", **{"Retry-After": "7"}))) as c:
        with pytest.raises(MonitorApiError) as info:
            c.list_alerts()
    err = info.value
    assert (err.status, err.code, err.detail, err.retry_after) == (429, "rate_limited", "nope", 7.0)
    assert err.extensions == {"permission": "x"}
    assert KEY not in str(err) and KEY not in repr(err)
    with _client(Recorder(_problem(404, "not_found"))) as c:
        with pytest.raises(MonitorApiError) as info:
            c.get_agent(AGENT)
    assert info.value.code == "not_found" and info.value.retry_after is None
    with _client(Recorder(lambda r: httpx.Response(502, text="bad gateway"))) as c:
        with pytest.raises(MonitorApiError) as info:
            c.get_agent(AGENT)
    assert info.value.code == "http_502"


def test_key_never_in_repr() -> None:
    c = Client(URL, KEY)
    assert KEY not in repr(c) and "sbl_test_ABCDEFGHIJKL_" in repr(c)
    assert KEY not in repr(c._key) and KEY not in repr(vars(c))
    c.close()


def test_config_errors_and_from_env() -> None:
    with pytest.raises(MonitorConfigError, match="SIBYL_API_URL"):
        Client.from_env({})
    with pytest.raises(MonitorConfigError, match="SIBYL_MONITOR_KEY"):
        Client.from_env({"SIBYL_API_URL": URL})
    with pytest.raises(MonitorConfigError, match="sbl_"):
        Client.from_env({"SIBYL_API_URL": URL, "SIBYL_MONITOR_KEY": "not-a-key"})
    with pytest.raises(MonitorConfigError, match="http"):
        Client("ftp://x", KEY)
    c = Client.from_env({"SIBYL_API_URL": URL, "SIBYL_MONITOR_KEY": KEY}, timeout=3)
    assert c.base_url.endswith("/api/v1")
    c.close()


def test_ca_file_keeps_verification(tmp_path: Any) -> None:
    import ssl

    from sibyl.monitor._http import tls_verify

    assert tls_verify(None) is True
    certifi = pytest.importorskip("certifi")
    ctx = tls_verify(certifi.where())
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_mode is ssl.CERT_REQUIRED


def test_paginate_follows_cursor_bounded() -> None:
    pages = iter(
        [
            {"data": [{"id": 1}], "next_cursor": "c1", "has_more": True},
            {"data": [{"id": 2}], "next_cursor": None, "has_more": False},
        ]
    )
    rec = Recorder(lambda r: httpx.Response(200, json=next(pages)))
    with _client(rec) as c:
        items = list(paginate(c.list_alerts, state="open"))
    assert items == [{"id": 1}, {"id": 2}]
    assert rec.requests[1].url.params["cursor"] == "c1"
    loop = Recorder(
        lambda r: httpx.Response(200, json={"data": [{}], "next_cursor": "c", "has_more": True})
    )
    with _client(loop) as c:
        assert len(list(paginate(c.list_alerts, max_pages=3))) == 3


def test_no_content_response() -> None:
    with _client(Recorder(lambda r: httpx.Response(204))) as c:
        assert c.get_agent(AGENT) is None


async def test_async_client_mirrors_sync() -> None:
    rec = Recorder(
        lambda r: httpx.Response(
            200, json={"data": [{"id": 9}], "next_cursor": None, "has_more": False}
        )
    )
    async with AsyncClient(URL, KEY, transport=httpx.MockTransport(rec)) as c:
        await c.list_agents(q="quote")
        await c.get_agent(AGENT)
        await c.get_fleet_health()
        await c.get_health(AGENT)
        await c.list_runs()
        await c.get_run(AGENT)
        await c.get_drift(AGENT, since="2026-10-01T00:00:00Z")
        await c.list_alerts()
        await c.get_alert(AGENT)
        await c.list_incidents()
        await c.get_incident(AGENT)
        await c.list_held_actions(state="pending")
        await c.get_held_action(HOLD)
        await c.list_findings()
        await c.get_finding(HOLD)
        await c.whoami()
        await c.submit_finding(
            kind="other", subject_kind="run", subject_id=uuid4(), severity="info", summary="s"
        )
        await c.recommend_on_held_action(HOLD, "approve", "fine", severity="info")
        items = [i async for i in apaginate(c.list_findings)]
    assert items == [{"id": 9}]
    paths = [q.url.path for q in rec.requests]
    assert paths[0] == "/api/v1/agents" and paths[6] == f"/api/v1/agents/{AGENT}/drift"
    assert [q.method for q in rec.requests].count("POST") == 2
    assert all(q.headers["authorization"] == f"Bearer {KEY}" for q in rec.requests)
    assert "AsyncClient" in repr(c) and KEY not in repr(c)
    c2 = AsyncClient.from_env({"SIBYL_API_URL": URL, "SIBYL_MONITOR_KEY": KEY})
    await c2.aclose()
