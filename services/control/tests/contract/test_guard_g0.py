# ruff: noqa: B008  (FastAPI dependencies are declared as argument defaults)
"""G0 guard fixes: object rules fail closed (security M3), conditional step-up is enforced,
the client IP comes from trusted proxies only (M4), and invalid credentials are throttled per
client IP before any key lookup (security LOW)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import APIRouter, Depends, Request
from fastapi.testclient import TestClient
from sibyl_control.api.app import create_app
from sibyl_control.api.contract import API_PREFIX
from sibyl_control.api.deps import (
    KEY_FAILURE_POLICY,
    ApiKeyResolver,
    AuthContext,
    ChainResolver,
    Services,
    StaticTokenResolver,
    client_ip,
    guard,
)
from sibyl_control.core.apikeys import KeyRecord, generate_api_key
from sibyl_control.core.audit import InMemoryAuditWriter
from sibyl_control.core.ratelimit import InMemoryRateLimiter, RateDecision, RatePolicy
from sibyl_control.core.settings import Settings

from .conftest import BOUND_AGENT_A, GROUP_A, TENANT_A

OTHER_GROUP = uuid4()
OTHER_AGENT = uuid4()
D = Depends


def _routes() -> APIRouter:
    router = APIRouter()

    @router.get(API_PREFIX + "/agents/{agent_id}")
    async def get_agent(
        agent_id: UUID, mode: str = "checked", ctx: AuthContext = D(guard("getAgent"))
    ) -> dict:
        if mode == "checked":
            group = GROUP_A if agent_id != OTHER_AGENT else OTHER_GROUP
            ctx.check(resource_group_id=group, resource_agent_id=agent_id)
        elif mode == "group_only":
            ctx.check(resource_group_id=GROUP_A)
        return {"id": str(agent_id)}

    @router.get(API_PREFIX + "/agents")
    async def list_agents(
        mode: str = "filtered", ctx: AuthContext = D(guard("listAgents"))
    ) -> dict:
        if mode == "filtered":
            groups, agent = ctx.group_filter(), ctx.agent_filter()
            return {"groups": sorted(map(str, groups or ())), "agent": str(agent)}
        return {"data": []}

    @router.get(API_PREFIX + "/sessions")
    async def sessions(mode: str = "filtered", ctx: AuthContext = D(guard("listSessions"))) -> dict:
        if mode == "filtered":
            owner = ctx.self_filter()
            return {"owner": str(owner) if owner else None}
        return {"data": []}

    @router.post(API_PREFIX + "/api-keys", status_code=201)
    async def create_key(body: dict, ctx: AuthContext = D(guard("createApiKey"))) -> dict:
        if body.get("skip") == "step_up":
            ctx.check(resource_group_id=None)
            ctx.object_rule_checked("break_glass_create")
            return {"created": True}
        ctx.step_up_if("killswitch:pull" in body.get("scopes", []))
        ctx.check(resource_group_id=None)
        ctx.object_rule_checked("break_glass_create")
        return {"created": True}

    @router.get(API_PREFIX + "/policy/keys")
    async def policy_keys(ctx: AuthContext = D(guard("getPolicyKeys"))) -> dict:
        return {"keys": [], "next_key": None}

    return router


def _app(services: Services, settings: Settings | None = None):
    router = _routes()
    return create_app(services, settings=settings, include=lambda app: app.include_router(router))


@pytest.fixture
def client(tokens, now) -> TestClient:
    services = Services(
        principals=StaticTokenResolver(tokens), audit=InMemoryAuditWriter(), clock=lambda: now
    )
    return TestClient(_app(services), raise_server_exceptions=False)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- object rules fail closed --------------------------------------------------------------------


def test_a_handler_that_resolves_the_resource_through_the_guard_succeeds(client) -> None:
    resp = client.get(f"/api/v1/agents/{uuid4()}", headers=auth("owner-a"))
    assert resp.status_code == 200


def test_a_handler_that_skips_the_object_rules_fails_closed(client) -> None:
    resp = client.get(f"/api/v1/agents/{uuid4()}?mode=skip", headers=auth("owner-a"))
    assert resp.status_code == 500
    assert resp.headers["content-type"] == "application/problem+json"
    assert resp.json()["type"].endswith("/internal_error")
    assert "id" not in resp.json()


def test_checking_only_some_declared_rules_still_fails_closed(client) -> None:
    resp = client.get(f"/api/v1/agents/{uuid4()}?mode=group_only", headers=auth("owner-a"))
    assert resp.status_code == 500


def test_list_routes_mark_rules_through_the_filters(client) -> None:
    resp = client.get("/api/v1/agents", headers=auth("bound-key-a"))
    assert resp.status_code == 200
    assert resp.json()["agent"] == str(BOUND_AGENT_A)
    assert client.get("/api/v1/agents?mode=raw", headers=auth("owner-a")).status_code == 500


def test_bound_key_on_another_agent_is_404(client) -> None:
    resp = client.get(f"/api/v1/agents/{uuid4()}", headers=auth("bound-key-a"))
    assert resp.status_code == 404
    assert (
        client.get(f"/api/v1/agents/{BOUND_AGENT_A}", headers=auth("bound-key-a")).status_code
        == 200
    )


def test_self_rule_must_be_applied_when_the_scope_is_missing(client) -> None:
    resp = client.get("/api/v1/sessions", headers=auth("nobody-a"))
    assert resp.status_code == 200 and resp.json()["owner"] is not None
    assert client.get("/api/v1/sessions?mode=raw", headers=auth("nobody-a")).status_code == 500
    # a principal holding the scope needs no self filter
    assert client.get("/api/v1/sessions?mode=raw", headers=auth("owner-a")).status_code == 200


def test_unknown_rule_names_are_programming_errors(tokens, now) -> None:
    from sibyl_control.api.contract import operation

    ctx = AuthContext(operation("getAgent"), tokens["owner-a"], None, now)
    with pytest.raises(ValueError, match="not an object rule"):
        ctx.object_rule_checked("job_owner")


# --- conditional step-up -------------------------------------------------------------------------

BREAK_GLASS_BODY = {"name": "bg", "env": "live", "scopes": ["killswitch:pull"]}
PLAIN_BODY = {"name": "ci", "env": "live", "scopes": ["agents:read"]}


def test_conditional_step_up_applies_when_its_condition_holds(client) -> None:
    resp = client.post("/api/v1/api-keys", json=BREAK_GLASS_BODY, headers=auth("owner-a-stale"))
    assert resp.status_code == 403
    body = resp.json()
    assert body["type"].endswith("/step_up_required") and body["step_up_url"]
    ok = client.post("/api/v1/api-keys", json=BREAK_GLASS_BODY, headers=auth("owner-a"))
    assert ok.status_code == 201


def test_conditional_step_up_is_skipped_when_its_condition_does_not_hold(client) -> None:
    resp = client.post("/api/v1/api-keys", json=PLAIN_BODY, headers=auth("owner-a-stale"))
    assert resp.status_code == 201


def test_a_handler_that_never_decides_the_conditional_step_up_fails_closed(client) -> None:
    body = {**BREAK_GLASS_BODY, "skip": "step_up"}
    resp = client.post("/api/v1/api-keys", json=body, headers=auth("owner-a"))
    assert resp.status_code == 500


def test_conditional_step_up_actions_require_a_decision(tokens, now) -> None:
    from sibyl_control.api.contract import operation

    op = operation("actOnIncident")
    stale = AuthContext(op, tokens["owner-a-stale"], None, now)
    with pytest.raises(TypeError, match="step_up_required"):
        stale.action("release")
    with pytest.raises(Exception) as err:
        stale.action("release", step_up_required=True)
    assert getattr(err.value, "code", None) == "step_up_required"
    stale.action("release", step_up_required=False)


# --- trusted proxies (M4) ------------------------------------------------------------------------


class RecordingLimiter(InMemoryRateLimiter):
    def __init__(self) -> None:
        super().__init__()
        self.keys: list[str] = []

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        self.keys.append(f"{policy.name}|{key}")
        return await super().hit(key, policy, cost)


def _proxy_client(tokens, now, peer: str) -> tuple[TestClient, RecordingLimiter]:
    limiter = RecordingLimiter()
    services = Services(
        principals=StaticTokenResolver(tokens),
        audit=InMemoryAuditWriter(),
        rate_limiter=limiter,
        clock=lambda: now,
    )
    settings = Settings(trusted_proxies="172.30.0.0/16")
    return TestClient(_app(services, settings), client=(peer, 4000)), limiter


def test_requests_through_the_proxy_get_per_client_buckets(tokens, now) -> None:
    client, limiter = _proxy_client(tokens, now, "172.30.0.5")
    client.get("/api/v1/policy/keys", headers={"X-Forwarded-For": "198.51.100.1"})
    client.get("/api/v1/policy/keys", headers={"X-Forwarded-For": "198.51.100.2"})
    assert [k.split("|")[1] for k in limiter.keys] == ["ip:198.51.100.1", "ip:198.51.100.2"]


def test_xff_from_an_untrusted_peer_is_ignored(tokens, now) -> None:
    client, limiter = _proxy_client(tokens, now, "203.0.113.50")
    client.get("/api/v1/policy/keys", headers={"X-Forwarded-For": "198.51.100.1"})
    assert limiter.keys[-1].endswith("|ip:203.0.113.50")


def test_client_ip_helper_reads_the_resolved_address(tokens, now) -> None:
    seen: list[str] = []
    router = APIRouter()

    @router.get(API_PREFIX + "/policy/keys")
    async def keys(ctx: AuthContext = D(guard("getPolicyKeys"))) -> dict:
        assert ctx.request is not None
        seen.append(client_ip(ctx.request))
        return {"keys": [], "next_key": None}

    services = Services(principals=StaticTokenResolver(tokens), clock=lambda: now)
    app = create_app(
        services,
        settings=Settings(trusted_proxies="172.30.0.0/16"),
        include=lambda a: a.include_router(router),
    )
    TestClient(app, client=("172.30.0.9", 1)).get(
        "/api/v1/policy/keys", headers={"X-Forwarded-For": "6.6.6.6, 198.51.100.3"}
    )
    assert seen == ["198.51.100.3"]


# --- invalid credentials are throttled per client IP before the key lookup -----------------------

PEPPER = b"k" * 32


def test_invalid_keys_are_throttled_per_ip_before_any_lookup() -> None:
    generated = generate_api_key("live", PEPPER)
    record = KeyRecord(
        tenant_id=TENANT_A,
        id=uuid4(),
        env="live",
        secret_hash=generated.secret_hash,
        scopes=frozenset({"agents:read"}),
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    lookups: list[str] = []

    async def lookup(prefix: str):
        lookups.append(prefix)
        return record if prefix == generated.prefix else None

    services = Services(
        principals=ChainResolver(ApiKeyResolver(lookup, PEPPER, expected_env="live")),
        audit=InMemoryAuditWriter(),
    )
    attacker = TestClient(_app(services), client=("203.0.113.66", 1), raise_server_exceptions=False)
    victim = TestClient(_app(services), client=("198.51.100.77", 1), raise_server_exceptions=False)
    bad = "sbl_live_" + "A" * 12 + "_" + "b" * 43
    statuses = [
        attacker.get("/api/v1/agents", headers=auth(bad)).status_code
        for _ in range(KEY_FAILURE_POLICY.capacity + 5)
    ]
    assert statuses[: KEY_FAILURE_POLICY.capacity] == [401] * KEY_FAILURE_POLICY.capacity
    assert set(statuses[KEY_FAILURE_POLICY.capacity :]) == {429}
    assert len(lookups) == KEY_FAILURE_POLICY.capacity  # throttled requests never hit the DB
    throttled = attacker.get("/api/v1/agents", headers=auth(bad))
    assert throttled.headers["Retry-After"]
    # the attacker's IP is throttled even with a valid key; other clients are unaffected
    assert attacker.get("/api/v1/agents", headers=auth(generated.plaintext)).status_code == 429
    assert victim.get("/api/v1/agents", headers=auth(generated.plaintext)).status_code == 200


# --- idempotency helpers and G0-5 ----------------------------------------------------------------


def test_idempotency_helpers_bind_the_request_line(tokens, now) -> None:
    from sibyl_control.api.deps import idempotency_fingerprint, idempotency_principal_kind

    seen: list[bytes] = []
    router = APIRouter()

    @router.post(API_PREFIX + "/x")
    async def x(request: Request) -> dict:
        seen.append(idempotency_fingerprint(request, await request.body()))
        return {}

    client = TestClient(create_app(Services(), include=lambda a: a.include_router(router)))
    client.post("/api/v1/x", json={"a": 1})
    client.post("/api/v1/x?dry_run=true", json={"a": 1})
    client.post("/api/v1/x", content=b'{ "a" : 1 }', headers={"content-type": "application/json"})
    assert seen[0] != seen[1] and seen[0] == seen[2]
    assert idempotency_principal_kind(tokens["owner-a"]) == "user"
    assert idempotency_principal_kind(tokens["keys-a"]) == "api_key"


def test_forbidden_is_the_only_plain_403_code() -> None:
    """Chair ruling G0-5: ``access_denied`` is gone from the contract and the kernel."""
    from sibyl_control.api.contract import load_document, operations
    from sibyl_control.core.problems import PROBLEM_CODES

    assert "access_denied" not in PROBLEM_CODES
    assert "access_denied" not in str(load_document())
    for op in operations():
        if 403 in op.problems:
            assert "forbidden" in op.problems[403] or op.scope == "public", op.operation_id
