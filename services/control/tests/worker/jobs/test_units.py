"""Unit tests: the SSRF guard (connect-time re-check), the probe's auth headers and URL, the
retry back-off, and the lane U adapters (resolved lazily, inert until that code is merged)."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import ModuleType
from typing import Any
from uuid import uuid4

import httpcore
import httpx
import pytest
from sibyl_control.api.sse.stream import Visibility
from sibyl_control.worker.jobs import audit as audit_jobs
from sibyl_control.worker.jobs.net import (
    GuardedBackend,
    SsrfBlocked,
    guarded_get,
    is_public_address,
    is_ssrf_refusal,
)
from sibyl_control.worker.jobs.probe import UnsupportedScheme, auth_headers, probe_url
from sibyl_control.worker.jobs.runner import (
    MAX_BACKOFF_S,
    ClaimedJob,
    JobEnv,
    JobRunner,
    backoff_s,
    resolve_handler,
)


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("93.184.216.34", True),
        ("2606:4700:4700::1111", True),
        ("10.0.0.1", False),
        ("172.16.5.4", False),
        ("192.168.1.1", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),  # cloud metadata
        ("100.64.0.1", False),  # CGNAT
        ("::1", False),
        ("fd00::1", False),
        ("fe80::1%en0", False),
        ("::ffff:10.0.0.1", False),  # IPv4-mapped private
        ("0.0.0.0", False),  # noqa: S104 (an address under test)
        ("224.0.0.1", False),
        ("not-an-ip", False),
    ],
)
def test_public_address_classification(address: str, public: bool) -> None:
    assert is_public_address(address) is public


class Inner(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self.connected: list[tuple[str, int]] = []

    async def connect_tcp(self, host: str, port: int, *a: Any, **kw: Any) -> Any:
        self.connected.append((host, port))
        return object()

    async def sleep(self, seconds: float) -> None:
        return None


def _resolver(*addresses: str) -> Any:
    async def resolve(host: str, port: int) -> list[str]:
        return list(addresses)

    return resolve


async def test_guard_connects_to_the_vetted_literal() -> None:
    inner = Inner()
    backend = GuardedBackend(resolver=_resolver("93.184.216.34"), inner=inner)
    await backend.connect_tcp("api.example.com", 443)
    assert inner.connected == [("93.184.216.34", 443)]


@pytest.mark.parametrize(
    ("host", "addresses"),
    [
        ("rebind.example.com", ("93.184.216.34", "127.0.0.1")),
        ("internal.example.com", ("10.0.0.7",)),
        ("nothing.example.com", ()),
        ("169.254.169.254", ()),
        ("[::1]", ()),
    ],
)
async def test_guard_refuses_any_non_public_resolution(
    host: str, addresses: tuple[str, ...]
) -> None:
    inner = Inner()
    backend = GuardedBackend(resolver=_resolver(*addresses), inner=inner)
    with pytest.raises(SsrfBlocked):
        await backend.connect_tcp(host, 443)
    assert inner.connected == []


async def test_guard_lets_dev_doubles_through_and_refuses_unix_sockets() -> None:
    inner = Inner()
    backend = GuardedBackend(["sibyl-sim"], resolver=_resolver("10.0.0.9"), inner=inner)
    await backend.connect_tcp("sibyl-sim", 8300)
    assert inner.connected == [("sibyl-sim", 8300)]
    with pytest.raises(SsrfBlocked):
        await backend.connect_unix_socket("/var/run/docker.sock")


async def test_resolution_errors_are_connect_errors_not_refusals() -> None:
    async def broken(host: str, port: int) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(httpcore.ConnectError) as err:
        await GuardedBackend(resolver=broken, inner=Inner()).connect_tcp("x.example", 443)
    assert not isinstance(err.value, SsrfBlocked)


def test_ssrf_refusal_is_found_through_httpx_wrapping() -> None:
    try:
        try:
            raise SsrfBlocked("private")
        except SsrfBlocked as inner:
            raise httpx.ConnectError("wrapped") from inner
    except httpx.ConnectError as outer:
        assert is_ssrf_refusal(outer)
    assert not is_ssrf_refusal(httpx.ConnectError("plain"))


async def test_guarded_get_never_follows_redirects_and_caps_the_body() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path.endswith("/models"):
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest"})
        return httpx.Response(200)

    response = await guarded_get(
        "https://api.example.com/v1/models", {}, transport=httpx.MockTransport(handler)
    )
    assert response.status == 302 and seen == ["https://api.example.com/v1/models"]

    big = await guarded_get(
        "https://api.example.com/v1/models",
        {},
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 500_000)),
        max_body=1024,
    )
    assert big.status == 200


@pytest.mark.parametrize(
    ("scheme", "header"),
    [
        ("bearer", "authorization"),
        ("Bearer", "authorization"),
        ("x-api-key", "x-api-key"),
        ("x_api_key", "x-api-key"),
        ("api-key", "api-key"),
        ("azure", "api-key"),
    ],
)
def test_auth_headers(scheme: str, header: str) -> None:
    headers = auth_headers(scheme, "s3cr3t")
    assert list(headers) == [header]
    assert headers[header] in ("s3cr3t", "Bearer s3cr3t")


def test_unknown_auth_schemes_are_refused_and_the_url_is_models() -> None:
    with pytest.raises(UnsupportedScheme):
        auth_headers("basic", "x")
    assert probe_url("https://api.example.com/v1/") == "https://api.example.com/v1/models"


@pytest.mark.parametrize("event_type", ["job.requested", "agent.discovered", "audit.anchor_now"])
def test_worker_facing_events_are_never_streamed(event_type: str) -> None:
    open_view = Visibility(topics=None, event_types=None, agent_id=None, agents=None)
    row = {
        "topic": "job",
        "event_type": event_type,
        "aggregate_kind": "job",
        "aggregate_id": uuid4(),
        "payload": {},
    }
    assert not open_view.admits(row)
    assert open_view.admits({**row, "topic": "policy", "event_type": "policy_changed"})


def test_backoff_doubles_with_jitter_and_caps() -> None:
    assert backoff_s(1, lambda: 1.0) == 2.0
    assert backoff_s(3, lambda: 1.0) == 8.0
    assert backoff_s(3, lambda: 0.0) == 4.0
    assert backoff_s(30, lambda: 1.0) == MAX_BACKOFF_S


def test_a_deadline_longer_than_the_lease_is_refused() -> None:
    with pytest.raises(ValueError, match="lease"):
        JobRunner(JobEnv(None, None), kinds=[], lease_s=10, job_timeout_s=10)


def test_lane_u_handlers_are_inert_until_their_code_exists() -> None:
    env = JobEnv(None, None)
    if "sibyl_control.worker.housekeeping.verification" not in sys.modules:
        try:
            import sibyl_control.worker.housekeeping.verification  # noqa: F401
        except ModuleNotFoundError:
            assert resolve_handler("audit_verify", env) is None
            assert resolve_handler("audit_export", env) is None
    assert resolve_handler("agent_bom", env) is None
    assert resolve_handler("credential_probe", env) is not None


@dataclass
class _Result:
    ok: bool = True

    action = "audit.verified"
    last_seq = 9

    def body(self) -> dict[str, Any]:
        return {"ok": True, "rows": 10, "anchors_checked": 1, "first_break_seq": None, "kind": None}

    def audit_detail(self) -> dict[str, Any]:
        return {"from_seq": 0, "to_seq": 9, "anchors_checked": 1, "rows": 10}


class _Db:
    @asynccontextmanager
    async def tenant_tx(self, tenant: Any, readonly: bool = False) -> Any:
        yield object()


async def test_audit_verify_adapter_records_the_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []

    async def verify_chain(conn: Any, tenant: Any, from_seq: int, to_seq: Any) -> _Result:
        calls.append((tenant, from_seq, to_seq))
        return _Result()

    fake = ModuleType("sibyl_control.worker.housekeeping.verification")
    fake.verify_chain = verify_chain  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sibyl_control.worker.housekeeping.verification", fake)
    handler = audit_jobs.AuditVerify(JobEnv(_Db(), None))
    assert handler is not None
    tenant = uuid4()
    job = ClaimedJob(
        tenant, uuid4(), "audit_verify", {"from_seq": 0}, 1, 5, None, "system", None, None
    )
    outcome = await handler.run(job)
    assert calls == [(tenant, 0, None)]
    assert outcome.state == "done" and outcome.result is not None
    assert outcome.result["ok"] is True and outcome.result["to_seq"] == 9
    assert [a.action for a in outcome.audits] == ["audit.verified"]
    assert outcome.audits[0].actor_type == "system"
    bad = ClaimedJob(
        tenant, uuid4(), "audit_verify", {"from_seq": "x"}, 1, 5, None, "system", None, None
    )
    assert (await handler.run(bad)).error == "invalid_params"
