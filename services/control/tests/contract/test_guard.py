"""The contract-driven guard and API-key resolution, exercised on a real FastAPI app."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sibyl_control.api._stubs import stub_router
from sibyl_control.api.app import create_app
from sibyl_control.api.contract import API_PREFIX
from sibyl_control.api.deps import (
    ApiKeyResolver,
    AuthContext,
    ChainResolver,
    Services,
    StaticTokenResolver,
    guard,
)
from sibyl_control.core.apikeys import KeyRecord, generate_api_key
from sibyl_control.core.audit import InMemoryAuditWriter
from sibyl_control.core.ratelimit import InMemoryRateLimiter

from .conftest import TENANT_A

PEPPER = b"k" * 32


def _app_with_real_routes(services: Services):
    router = APIRouter()

    @router.get(API_PREFIX + "/tenant")
    async def get_tenant(ctx: AuthContext = Depends(guard("getTenant"))) -> dict:  # noqa: B008
        return {"tenant": str(ctx.tenant_id)}

    @router.patch(API_PREFIX + "/tenant")
    async def patch_tenant(ctx: AuthContext = Depends(guard("updateTenant"))) -> dict:  # noqa: B008
        return {"ok": True}

    @router.get(API_PREFIX + "/agents")
    async def list_agents(ctx: AuthContext = Depends(guard("listAgents"))) -> dict:  # noqa: B008
        ctx.group_filter()
        ctx.agent_filter()
        return {"data": [], "next_cursor": None, "has_more": False}

    @router.get(API_PREFIX + "/sessions")
    async def sessions(ctx: AuthContext = Depends(guard("listSessions"))) -> dict:  # noqa: B008
        ctx.self_filter()
        return {"self_only": ctx.self_only}

    @router.get(API_PREFIX + "/policy/keys")
    async def keys(ctx: AuthContext = Depends(guard("getPolicyKeys"))) -> dict:  # noqa: B008
        return {"keys": [], "next_key": None}

    return create_app(
        services, include=lambda app: app.include_router(stub_router("tenancy", router))
    )


@pytest.fixture
def audit() -> InMemoryAuditWriter:
    return InMemoryAuditWriter()


@pytest.fixture
def client(audit, tokens, now) -> TestClient:
    services = Services(principals=StaticTokenResolver(tokens), audit=audit, clock=lambda: now)
    return TestClient(_app_with_real_routes(services), raise_server_exceptions=False)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_guarded_route_allows_the_right_scope(client) -> None:
    resp = client.get("/api/v1/tenant", headers=auth("owner-a"))
    assert resp.status_code == 200
    assert resp.json() == {"tenant": str(TENANT_A)}
    assert resp.headers["RateLimit-Policy"] == '"read";q=600;w=60'


def test_guard_denies_and_audits(client, audit) -> None:
    resp = client.get("/api/v1/tenant", headers=auth("nobody-a"))
    assert resp.status_code == 403
    assert audit.actions(TENANT_A) == ["access.denied"]


def test_guard_requires_a_principal(client) -> None:
    assert client.get("/api/v1/tenant").status_code == 401
    assert client.get("/api/v1/tenant", headers=auth("unknown")).status_code == 401


def test_guard_enforces_step_up_from_the_contract(client) -> None:
    assert client.patch("/api/v1/tenant", headers=auth("owner-a")).status_code == 200
    resp = client.patch("/api/v1/tenant", headers=auth("owner-a-stale"))
    assert resp.status_code == 403
    assert resp.json()["step_up_url"] == "/api/v1/auth/step-up"


def test_guard_refuses_keys_on_session_routes_and_break_glass_everywhere(client) -> None:
    assert client.get("/api/v1/tenant", headers=auth("keys-a")).status_code == 403
    assert client.get("/api/v1/agents", headers=auth("keys-a")).status_code == 200
    resp = client.get("/api/v1/agents", headers=auth("breakglass-a"))
    assert resp.json()["type"].endswith("/break_glass_key_misuse")


def test_self_rule_lets_the_handler_scope_to_own_rows(client) -> None:
    assert client.get("/api/v1/sessions", headers=auth("nobody-a")).json() == {"self_only": True}
    assert client.get("/api/v1/sessions", headers=auth("owner-a")).json() == {"self_only": False}


def test_public_routes_need_no_principal(client) -> None:
    assert client.get("/api/v1/policy/keys").status_code == 200


def test_unimplemented_operations_of_a_module_stay_stubbed(client) -> None:
    resp = client.get("/api/v1/users", headers=auth("owner-a"))
    assert resp.status_code == 501


def test_rate_limit_is_enforced_per_principal(audit, tokens, now) -> None:
    services = Services(
        principals=StaticTokenResolver(tokens),
        audit=audit,
        rate_limiter=InMemoryRateLimiter(),
        clock=lambda: now,
    )
    client = TestClient(_app_with_real_routes(services), raise_server_exceptions=False)
    statuses = {
        client.patch("/api/v1/tenant", headers=auth("owner-a")).status_code for _ in range(61)
    }
    assert statuses == {200, 429}


def _key_resolver_client(record_overrides: dict | None = None):
    generated = generate_api_key("live", PEPPER)
    record = KeyRecord(
        tenant_id=TENANT_A,
        id=uuid4(),
        env="live",
        secret_hash=generated.secret_hash,
        scopes=frozenset({"agents:read"}),
        expires_at=datetime.now(UTC) + timedelta(days=1),
        **(record_overrides or {}),
    )

    async def lookup(prefix: str):
        return record if prefix == generated.prefix else None

    resolver = ChainResolver(ApiKeyResolver(lookup, PEPPER, expected_env="live"))
    services = Services(principals=resolver, audit=InMemoryAuditWriter())
    return TestClient(_app_with_real_routes(services), raise_server_exceptions=False), generated


def test_api_key_resolver_end_to_end() -> None:
    client, generated = _key_resolver_client()
    assert client.get("/api/v1/agents", headers=auth(generated.plaintext)).status_code == 200
    forged = generated.plaintext[:-1] + ("A" if generated.plaintext[-1] != "A" else "B")
    resp = client.get("/api/v1/agents", headers=auth(forged))
    assert resp.status_code == 401
    assert generated.plaintext not in resp.text


def test_revoked_and_browser_keys_are_refused() -> None:
    client, generated = _key_resolver_client({"status": "revoked"})
    assert client.get("/api/v1/agents", headers=auth(generated.plaintext)).status_code == 401
    client, generated = _key_resolver_client()
    resp = client.get(
        "/api/v1/agents", headers={**auth(generated.plaintext), "Origin": "https://evil"}
    )
    assert resp.json()["type"].endswith("/key_from_browser")
