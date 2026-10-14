"""Unit tests of the webhook delivery path (no database): egress policy (deployment allowlist,
https only, connect-time refusal of private addresses), signing, backoff and event mapping."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
from sibyl_control.core.llm.egress import EgressPolicy
from sibyl_control.core.llm.types import EgressRefused
from sibyl_control.worker.webhooks.deliver import (
    BASE_BACKOFF_S,
    MAX_BACKOFF_S,
    DeliveryResult,
    backoff_s,
    deployment_allows,
    envelope,
    render_body,
    send,
    signed_headers,
    webhook_policy,
)
from sibyl_control.worker.webhooks.enqueue import Target, agent_refs, outbox_events
from sibyl_control.worker.webhooks.secrets import new_secret
from sibyl_schemas.webhook_signature import SignatureError, verify

URL = "https://hooks.example.com/sibyl"


def _settings(allowed: str = "") -> SimpleNamespace:
    return SimpleNamespace(webhook_allowed_hosts=allowed, upstream_ca_file=None)


@pytest.mark.parametrize(
    ("host", "allowlist", "expected"),
    [
        ("hooks.example.com", "", True),
        ("hooks.example.com", "hooks.example.com", True),
        ("hooks.example.com", ".example.com", True),
        ("hooks.example.com", "*.example.com", True),
        ("example.com", ".example.com", False),
        ("evil-example.com", ".example.com", False),
        ("hooks.example.com", "other.example.org, .example.net", False),
        ("HOOKS.EXAMPLE.COM.", "hooks.example.com", True),
    ],
)
def test_deployment_allowlist(host: str, allowlist: str, expected: bool) -> None:
    assert deployment_allows(host, allowlist) is expected


def test_policy_allows_only_the_webhooks_own_host() -> None:
    policy = webhook_policy(URL, _settings())
    assert policy.allowed_hosts == frozenset({"hooks.example.com"})
    with pytest.raises(EgressRefused):
        policy.check("https://other.example.com/x")
    with pytest.raises(EgressRefused):
        webhook_policy(URL, _settings(".example.org"))
    with pytest.raises(EgressRefused):
        webhook_policy("http://hooks.example.com/sibyl", _settings())  # https only
    with pytest.raises(EgressRefused):
        webhook_policy("https://user:pw@hooks.example.com/", _settings())
    dev = webhook_policy("http://sibyl-sim:8400/hook", _settings(), ["sibyl-sim"])
    dev.check("http://sibyl-sim:8400/hook")  # development doubles may use http


async def _private(host: str, port: int) -> list[str]:
    return ["10.0.0.7"]


def test_connect_time_refusal_of_private_addresses() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"hooks.example.com"}), resolver=_private)
    result = asyncio.run(send(URL, b"{}", {}, policy))
    assert result == DeliveryResult(False, 0, "egress_refused", result.latency_ms)
    assert not result.retryable


def _transport(status: int = 200, error: Exception | None = None) -> object:
    def handler(request: httpx.Request) -> httpx.Response:
        if error is not None:
            raise error
        return httpx.Response(status, content=b"x" * 100_000)

    return lambda policy: httpx.MockTransport(handler)


@pytest.mark.parametrize(
    ("status", "error", "expected"),
    [
        (204, None, (True, 204, None)),
        (302, None, (False, 302, "http_error")),  # redirects are never followed
        (500, None, (False, 500, "http_error")),
        (0, httpx.ConnectTimeout("slow"), (False, 0, "timeout")),
        (0, httpx.ConnectError("refused"), (False, 0, "transport")),
    ],
)
def test_send_outcomes(status: int, error: Exception | None, expected: tuple[object, ...]) -> None:
    policy = webhook_policy(URL, _settings())
    result = asyncio.run(send(URL, b"{}", {}, policy, transport_factory=_transport(status, error)))
    assert (result.ok, result.http_status, result.error) == expected
    assert result.retryable is (not result.ok)


def test_send_refuses_a_url_outside_the_policy() -> None:
    policy = webhook_policy(URL, _settings())
    other = asyncio.run(
        send("https://elsewhere.example.com/", b"{}", {}, policy, transport_factory=_transport())
    )
    assert other.error == "egress_refused"


def test_signed_headers_and_body() -> None:
    secret = new_secret()
    assert secret.startswith("whsec_") and len(secret) == 49 and secret != new_secret()
    doc = envelope(
        event_id=uuid4(),
        event_type="alert.fired",
        created_at=datetime(2026, 10, 14, 12, 0, tzinfo=UTC),
        tenant_id=uuid4(),
        monitor_id=uuid4(),
        data={"alert_id": "a", "agent_id": "b"},
    )
    body = render_body(doc)
    assert json.loads(body)["created_at"] == "2026-10-14T12:00:00Z"
    headers = signed_headers(
        secret, body, event_id=doc["id"], event_type="alert.fired", delivery_id=uuid4()
    )
    assert verify(secret, headers["Sibyl-Signature"], body) > 0
    with pytest.raises(SignatureError):
        verify(secret, headers["Sibyl-Signature"], body + b" ")
    assert secret not in json.dumps(headers)


def test_backoff_doubles_and_caps() -> None:
    assert backoff_s(1, jitter=0) == BASE_BACKOFF_S
    assert backoff_s(2, jitter=0) == BASE_BACKOFF_S * 2
    assert backoff_s(30, jitter=0) == MAX_BACKOFF_S
    assert BASE_BACKOFF_S <= backoff_s(1) <= BASE_BACKOFF_S * 1.2


def _row(event_type: str, payload: dict[str, object], kind: str = "alert") -> dict[str, object]:
    return {
        "id": uuid4(),
        "event_type": event_type,
        "aggregate_kind": kind,
        "aggregate_id": uuid4(),
        "payload": json.dumps(payload),
        "created_at": datetime.now(UTC),
    }


def test_outbox_mapping() -> None:
    agent = uuid4()
    drift = outbox_events(_row("alert.fired", {"rule": "model_change", "agent_id": str(agent)}))
    assert [e.event_type for e in drift] == ["alert.fired", "drift.detected"]
    assert drift[0].agents == (agent,) and drift[1].event_id != drift[0].event_id
    assert outbox_events(_row("alert.resolved", {"rule": "silent_drift"}))[0].event_type == (
        "alert.resolved"
    )
    assert outbox_events(_row("job.requested", {})) == []
    assert outbox_events(_row("policy_changed", {})) == []
    refs = agent_refs(
        _row(
            "incident.updated",
            {"affected_agent_ids": [str(agent), "nonsense"], "scope_kind": "agent"},
            kind="agent",
        )
    )
    assert agent in refs


def test_target_visibility() -> None:
    now = datetime.now(UTC)
    group = uuid4()
    wide = Target(uuid4(), uuid4(), frozenset({"alert.fired"}), now, None)
    narrow = Target(uuid4(), uuid4(), frozenset({"alert.fired"}), now, frozenset({group}))
    later = datetime.now(UTC)
    assert wide.wants("alert.fired", later, []) and wide.wants("alert.fired", later, [None])
    assert not wide.wants("alert.updated", later, [])
    assert not wide.wants("alert.fired", datetime(2020, 1, 1, tzinfo=UTC), [])
    assert narrow.wants("alert.fired", later, [group])
    assert not narrow.wants("alert.fired", later, [])
    assert not narrow.wants("alert.fired", later, [None, UUID(int=1)])
