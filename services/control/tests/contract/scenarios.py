"""One valid request per implemented operation, on real tenant-A objects (``contract_world``).

A scenario builds whatever it needs through the api (or direct SQL as the superuser, like a
fixture loader) and returns a ``Req``: path, body, query, If-Match, the agent the request is
about (object-rule cases), the token that must make it (when not the default) and extra headers.
The registry/policy/credentials scenarios were lifted from lane R's ``test_contract_pg.py``. This
module holds the registry, tenancy and reads scenarios, the exemption tables and ``SCENARIOS``;
lane S's live in ``scenarios_lane_s``, lanes P and U's in ``scenarios_governance``, and the
shared ``Req`` and object helpers in ``_world_kit``.

``EXEMPT`` lists the implemented operations that cannot answer 2xx in-process, with the reason;
``CUT_BY_RULING`` are guarded 501s (authorised, then ``not_implemented``): exempt from a scenario,
their 2xx world cases are strict xfails (``_cases``) and their guard-level wall stays strict;
``KNOWN_GAPS`` are findings (route or contract bugs) tracked as strict xfails until fixed. A
module is pending while any of its operations is still a 501 stub (``_cases``); once its last
stub is replaced it is strict, so its lane must add a scenario per operation here first (the
completeness test names any that are missing).
"""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl_control.api.auth.principals import session_token_hash
from sibyl_control.core.crypto.signing import b64url

from ._world_kit import (
    REASON,
    Req,
    Scenario,
    _api,
    _etag,
    _with_agent,
    agent,
    model,
    provider,
    unique,
)
from .pg_world import SIM_HOST, ContractWorld, kit
from .scenarios_action_gate import ACTION_GATE
from .scenarios_drift import DRIFT
from .scenarios_governance import ALERTS, GOVERNANCE
from .scenarios_int3 import INT3
from .scenarios_lane_s import LANE_S
from .scenarios_monitors import MONITORS
from .scenarios_sentinel import SENTINEL

KNOWN_GAPS: dict[tuple[str, str], str] = {}
CUT_BY_RULING: dict[str, str] = {
    "createDataExport": "guarded 501 by ruling: data export is cut to Phase 1.5 (ROADMAP A8)",
}
EXEMPT: dict[str, str] = {
    "authLogin": "public redirect to the IdP; no principal (covered by tests/api/auth)",
    "authCallback": "needs an IdP authorization-code round trip (covered by tests/api/auth)",
    "authStepUp": "re-authentication redirect through the IdP (covered by tests/api/auth)",
    "generateAgentBom": "501 by ruling B14: AI-BOM generation is cut to Phase 1.5 (Tier A1)",
    **CUT_BY_RULING,
}
BASELINE = (
    "sibyl_key openai_key anthropic_key aws_access_key aws_secret_key gcp_sa_key azure_conn_string"
    " github_token slack_token stripe_key jwt bearer_header basic_auth_url dsn pem_block ssh_key"
    " generic_secret_kv high_entropy"
).split()


def _secrets_only(w: ContractWorld) -> str:
    rows = _api(w, "GET", "/redaction-profiles?limit=200").json()["data"]
    return str(next(r["id"] for r in rows if r["name"] == "secrets_only"))


def _chain(w: ContractWorld, agent_id: str, steps: list[dict[str, Any]] | None = None) -> Any:
    return _api(
        w,
        "POST",
        f"/agents/{agent_id}/fallback-chains",
        {"steps": steps or [{"kind": "human_queue", "risk": "low"}], "note": "contract"},
    )


def _plan_body() -> dict[str, Any]:
    return {
        "degraded_mode": "safe_no_tools",
        "approval_timeout_policy": "hold",
        "reason": "contract scenario plan",
    }


def credential(w: ContractWorld, provider_id: UUID | None = None, secret: str = "") -> str:
    resp = _api(
        w,
        "POST",
        "/provider-credentials",
        {
            "provider_id": str(provider_id or provider(w)),
            "name": unique("cred"),
            "base_url": f"http://{SIM_HOST}:8300/v1",
            "auth_scheme": "bearer",
            "secret": secret or "sk-test-" + uuid4().hex,
        },
    )
    return str(resp.json()["id"])


def _catalog(w: ContractWorld, path: str, body: dict[str, Any]) -> Any:
    return _api(w, "POST", path, {"slug": unique("c"), "name": "Thing", **body})


def _seed_rule(w: ContractWorld) -> dict[str, Any]:
    rows = _api(w, "GET", "/alert-rules?limit=200").json()["data"]
    return dict(next(r for r in rows if r["origin"] == "seed" and not r.get("overridden")))


def _bom(w: ContractWorld, created: dict[str, Any]) -> Req:
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.ai_bom (tenant_id, agent_version_id, content, content_sha256,"
        " generator_version) VALUES ($1, $2, '{}'::jsonb, $3, 'contract')",
        w.a.id,
        UUID(created["current_version"]["id"]),
        b"\x02" * 32,
    )
    return Req(f"/agents/{created['id']}/versions/1/bom", agent_id=created["id"])


def _provisional(w: ContractWorld) -> Req:
    agent_id = uuid4()
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, is_provisional)"
        " VALUES ($1, $2, $3, 'provisional', 'chatbot', true)",
        w.a.id,
        agent_id,
        "unclaimed/" + uuid4().hex[:8],
    )
    return Req(f"/agents/{agent_id}/claim", agent_id=str(agent_id))


def _versioned(w: ContractWorld) -> dict[str, Any]:
    return agent(w, version={"primary_model_id": str(model(w))})


def _edge(w: ContractWorld, created: dict[str, Any]) -> str:
    resp = _api(
        w,
        "POST",
        "/dependency-edges",
        {
            "src_kind": "agent",
            "src_id": created["id"],
            "dst_kind": "model",
            "dst_id": str(model(w)),
            "edge_type": "uses_model",
        },
    )
    return str(resp.json()["id"])


def _tenant_policy(w: ContractWorld) -> None:
    current = w.client.get(
        "/api/v1/capture-policies?scope_kind=tenant", headers=w.headers("owner")
    ).json()["data"]
    if current:
        return
    _api(
        w,
        "POST",
        "/capture-policies",
        {
            "scope_kind": "tenant",
            "capture_mode": "redacted",
            "redaction_profile_id": _secrets_only(w),
            "payload_retention_days": 30,
            "consequences_version": "2026-10",
            "acknowledged": True,
        },
        **{"If-Match": "*"},
    )


def _provider_via_api(w: ContractWorld) -> Any:
    return _api(
        w,
        "POST",
        "/providers",
        {
            "slug": unique("p"),
            "name": "P",
            "provider_kind": "openai",
            "dialect": "openai_compatible",
            "base_url": "https://api.openai.com/v1",
        },
    )


# --- registry, policy, credentials (lifted from lane R) ---------------------------------------

REGISTRY: dict[str, Scenario] = {
    "listAgents": lambda w: Req("/agents"),
    "registerAgent": lambda w: Req(
        "/agents", {"slug": unique("reg"), "name": "R", "kind": "chatbot", "fail_mode": "open"}
    ),
    "getAgent": _with_agent(lambda w, a: Req(f"/agents/{a['id']}")),
    "updateAgent": _with_agent(
        lambda w, a: Req(
            f"/agents/{a['id']}", {"name": "Renamed"}, if_match=_etag(w, f"/agents/{a['id']}")
        )
    ),
    "claimAgent": _provisional,
    "getAgentLifecycle": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/lifecycle")),
    "changeAgentLifecycle": _with_agent(
        lambda w, a: Req(
            f"/agents/{a['id']}/lifecycle", {"to_stage": "approved", "reason": "approved in review"}
        )
    ),
    "getAgentIdentity": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/identity")),
    "putAgentIdentity": _with_agent(
        lambda w, a: Req(
            f"/agents/{a['id']}/identity",
            {
                "allowed_tools": ["t"],
                "allowed_models": [],
                "allowed_providers": [],
                "enforcement": "observe",
            },
            if_match='"1"',
        )
    ),
    "listAgentVersions": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/versions")),
    "createAgentVersion": _with_agent(
        lambda w, a: Req(f"/agents/{a['id']}/versions", {"primary_model_id": str(model(w))})
    ),
    "getAgentBom": lambda w: _bom(w, _versioned(w)),
    "listAgentDependencies": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/dependencies")),
    "getAgentBlastRadius": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/blast-radius")),
    "getBlastRadius": _with_agent(lambda w, a: Req(f"/blast-radius/agent/{a['id']}")),
    "createDependencyEdge": _with_agent(
        lambda w, a: Req(
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": a["id"],
                "dst_kind": "model",
                "dst_id": str(model(w)),
                "edge_type": "uses_model",
            },
        )
    ),
    "closeDependencyEdge": _with_agent(
        lambda w, a: Req(
            f"/dependency-edges/{_edge(w, a)}", params={"reason": "contract scenario close"}
        )
    ),
    "listTools": lambda w: Req("/tools"),
    "createTool": lambda w: Req("/tools", {"slug": unique("t"), "name": "T", "kind": "function"}),
    "getTool": lambda w: Req(f"/tools/{_catalog(w, '/tools', {'kind': 'function'}).json()['id']}"),
    "updateTool": lambda w: (
        lambda r: Req(f"/tools/{r.json()['id']}", {"name": "T2"}, if_match=r.headers["etag"])
    )(_catalog(w, "/tools", {"kind": "function"})),
    "listDataSources": lambda w: Req("/data-sources"),
    "createDataSource": lambda w: Req(
        "/data-sources", {"slug": unique("d"), "name": "D", "kind": "database"}
    ),
    "getDataSource": lambda w: Req(
        f"/data-sources/{_catalog(w, '/data-sources', {'kind': 'api'}).json()['id']}"
    ),
    "updateDataSource": lambda w: (
        lambda r: Req(f"/data-sources/{r.json()['id']}", {"name": "D2"}, if_match=r.headers["etag"])
    )(_catalog(w, "/data-sources", {"kind": "api"})),
    "listBusinessProcesses": lambda w: Req("/business-processes"),
    "createBusinessProcess": lambda w: Req(
        "/business-processes", {"slug": unique("b"), "name": "B"}
    ),
    "getBusinessProcess": lambda w: Req(
        f"/business-processes/{_catalog(w, '/business-processes', {}).json()['id']}"
    ),
    "updateBusinessProcess": lambda w: (
        lambda r: Req(
            f"/business-processes/{r.json()['id']}", {"name": "B2"}, if_match=r.headers["etag"]
        )
    )(_catalog(w, "/business-processes", {})),
    "listProviders": lambda w: Req("/providers"),
    "createProvider": lambda w: Req(
        "/providers",
        {
            "slug": unique("p"),
            "name": "P",
            "provider_kind": "openai",
            "dialect": "openai_compatible",
            "base_url": "https://api.openai.com/v1",
        },
    ),
    "getProvider": lambda w: Req(f"/providers/{provider(w)}"),
    "getProviderStatusHistory": lambda w: Req(f"/providers/{provider(w)}/status"),
    "updateProvider": lambda w: (
        lambda r: Req(f"/providers/{r.json()['id']}", {"name": "P2"}, if_match=r.headers["etag"])
    )(_provider_via_api(w)),
    "listModels": lambda w: Req("/models"),
    "createModel": lambda w: Req(
        "/models", {"provider_id": str(provider(w)), "model_name": unique("m")}
    ),
    "listModelCatalog": lambda w: Req("/model-catalog"),
    "updateModel": lambda w: (
        lambda r: Req(
            f"/models/{r.json()['id']}", {"is_allowed": False}, if_match=r.headers["etag"]
        )
    )(_api(w, "POST", "/models", {"provider_id": str(provider(w)), "model_name": unique("m")})),
    "listCapturePolicies": lambda w: Req("/capture-policies"),
    "setCapturePolicy": lambda w: (
        _tenant_policy(w),
        Req(
            "/capture-policies",
            {
                "scope_kind": "agent",
                "agent_id": agent(w)["id"],
                "capture_mode": "metadata",
                "redaction_profile_id": _secrets_only(w),
                "payload_retention_days": 7,
                "consequences_version": "2026-10",
                "acknowledged": True,
            },
            if_match="*",
        ),
    )[1],
    "getEffectiveCapturePolicy": lambda w: (
        _tenant_policy(w),
        Req("/capture-policies/effective", params={"agent_id": agent(w)["id"]}),
    )[1],
    "listRedactionProfiles": lambda w: Req("/redaction-profiles"),
    "createRedactionProfile": lambda w: Req(
        "/redaction-profiles", {"name": unique("rp"), "detectors": [*BASELINE, "email"]}
    ),
    "getContinuityPlan": _with_agent(
        lambda w, a: (
            _api(w, "PUT", f"/agents/{a['id']}/continuity-plan", _plan_body(), **{"If-Match": "*"}),
            Req(f"/agents/{a['id']}/continuity-plan"),
        )[1]
    ),
    "putContinuityPlan": _with_agent(
        lambda w, a: Req(f"/agents/{a['id']}/continuity-plan", _plan_body(), if_match="*")
    ),
    "listFallbackChains": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/fallback-chains")),
    "createFallbackChain": _with_agent(
        lambda w, a: Req(
            f"/agents/{a['id']}/fallback-chains",
            {"steps": [{"kind": "human_queue", "risk": "low"}]},
        )
    ),
    "putFallbackChain": _with_agent(
        lambda w, a: (
            lambda r: Req(
                f"/fallback-chains/{r.json()['id']}",
                {
                    "steps": [
                        {"kind": "degraded_safe_mode", "risk": "low"},
                        {"kind": "human_queue", "risk": "low"},
                    ]
                },
                if_match=r.headers["etag"],
            )
        )(_chain(w, a["id"]))
    ),
    "actOnFallbackChain": _with_agent(
        lambda w, a: Req(
            f"/fallback-chains/{_chain(w, a['id']).json()['id']}/actions",
            {"action": "approve", "reason": "approved in contract scenario"},
        )
    ),
    "listAlertRules": lambda w: Req("/alert-rules"),
    "createAlertRule": lambda w: Req(
        "/alert-rules",
        {
            "code": unique("cr").replace("-", "_"),
            "scope": "agent",
            "severity": "warning",
            "window_s": 60,
        },
    ),
    "getAlertRule": lambda w: Req(f"/alert-rules/{_seed_rule(w)['id']}"),
    "updateAlertRule": lambda w: (
        lambda r: Req(
            f"/alert-rules/{r['id']}", {"penalty": 7}, if_match=_etag(w, f"/alert-rules/{r['id']}")
        )
    )(_seed_rule(w)),
    "resetAlertRule": lambda w: Req(f"/alert-rules/{_seed_rule(w)['id']}/reset"),
    "listProviderCredentials": lambda w: Req("/provider-credentials"),
    "createProviderCredential": lambda w: Req(
        "/provider-credentials",
        {
            "provider_id": str(provider(w)),
            "name": unique("cred"),
            "base_url": f"http://{SIM_HOST}:8300/v1",
            "auth_scheme": "bearer",
            "secret": "sk-test-" + uuid4().hex,
        },
    ),
    "rotateProviderCredential": lambda w: Req(
        f"/provider-credentials/{credential(w)}/rotate", {"secret": "sk-new-" + uuid4().hex}
    ),
    "revokeProviderCredential": lambda w: Req(
        f"/provider-credentials/{credential(w)}/revoke", {"reason": "rotated out in drill"}
    ),
    "verifyProviderCredential": lambda w: Req(f"/provider-credentials/{credential(w)}/verify"),
}


# --- tenancy and keys --------------------------------------------------------------------------


def _fresh_user(w: ContractWorld, *roles: str) -> UUID:
    user: UUID = kit.add_user(w.db, w.a.id, w.a.issuer_id, roles=roles)
    return user


def _fresh_session(w: ContractWorld, user: UUID | None = None) -> tuple[str, UUID]:
    """A new console session (token, session id) for ``user`` (a fresh viewer by default)."""
    user = user or _fresh_user(w, "viewer")
    token: str = kit.add_session(w.db, w.a.id, user)
    with w.admin.tx(w.a.id):
        sid = w.admin.fetchval(
            "SELECT id FROM sibyl.session WHERE token_hash = $1",
            session_token_hash(token.removeprefix("sibyl_sess_")),
        )
    return token, sid


def _issuer(w: ContractWorld) -> Any:
    return _api(
        w,
        "POST",
        "/oidc-issuers",
        {
            "issuer_url": f"https://{unique('idp')}.example.com/dex",
            "client_id": "sibyl-console",
            "client_secret": "contract-client-secret-0123",
            "allowed_email_domains": ["example.com"],
        },
    )


def _group(w: ContractWorld) -> Any:
    return _api(w, "POST", "/agent-groups", {"slug": unique("grp"), "name": "Group"})


def _membership(w: ContractWorld) -> str:
    resp = _api(
        w,
        "POST",
        "/memberships",
        {
            "user_id": str(_fresh_user(w)),
            "role_name": "viewer",
            "scope_kind": "tenant",
            "reason": REASON,
        },
    )
    return str(resp.json()["id"])


def _key(w: ContractWorld) -> str:
    resp = _api(
        w, "POST", "/api-keys", {"name": unique("k"), "env": "test", "scopes": ["routing:read"]}
    )
    body = resp.json()
    return str(body["id"] if "id" in body else body["key"]["id"])


def _logout(w: ContractWorld) -> Req:
    token, _ = _fresh_session(w, _fresh_user(w, "owner"))
    w.tokens["logout"] = token
    return Req("/auth/logout", who="logout")


TENANCY: dict[str, Scenario] = {
    "authMe": lambda w: Req("/auth/me"),
    "authLogout": _logout,
    "getTenant": lambda w: Req("/tenant"),
    "updateTenant": lambda w: Req(
        "/tenant", {"name": unique("Acme"), "reason": REASON}, if_match=_etag(w, "/tenant")
    ),
    "listTenantKeys": lambda w: Req("/tenant-keys"),
    "rotateTenantKey": lambda w: Req("/tenant-keys/config/rotate", {"reason": REASON}),
    "listSessions": lambda w: Req("/sessions"),
    "revokeSession": lambda w: Req(f"/sessions/{_fresh_session(w)[1]}"),
    "listUsers": lambda w: Req("/users"),
    "getUser": lambda w: Req(f"/users/{w.a.users['viewer']}"),
    "updateUser": lambda w: (
        lambda uid: Req(
            f"/users/{uid}", {"display_name": "Renamed"}, if_match=_etag(w, f"/users/{uid}")
        )
    )(_fresh_user(w, "viewer")),
    "inviteUser": lambda w: Req(
        "/users/invitations",
        {
            "email": f"{unique('invitee')}@example.com",
            "oidc_issuer_id": str(w.a.issuer_id),
            "role_name": "viewer",
            "scope_kind": "tenant",
        },
    ),
    "grantMembership": lambda w: Req(
        "/memberships",
        {
            "user_id": str(_fresh_user(w)),
            "role_name": "viewer",
            "scope_kind": "tenant",
            "reason": REASON,
        },
    ),
    "revokeMembership": lambda w: Req(f"/memberships/{_membership(w)}", params={"reason": REASON}),
    "listOidcIssuers": lambda w: Req("/oidc-issuers"),
    "createOidcIssuer": lambda w: Req(
        "/oidc-issuers",
        {
            "issuer_url": f"https://{unique('idp')}.example.com/dex",
            "client_id": "sibyl-console",
            "client_secret": "contract-client-secret-0123",
            "allowed_email_domains": ["example.com"],
        },
    ),
    "getOidcIssuer": lambda w: Req(f"/oidc-issuers/{w.a.issuer_id}"),
    "updateOidcIssuer": lambda w: (
        lambda r: Req(
            f"/oidc-issuers/{r.json()['id']}",
            {"allowed_email_domains": ["example.org"]},
            if_match=r.headers["etag"],
        )
    )(_issuer(w)),
    "listAgentGroups": lambda w: Req("/agent-groups"),
    "createAgentGroup": lambda w: Req("/agent-groups", {"slug": unique("grp"), "name": "G"}),
    "getAgentGroup": lambda w: Req(f"/agent-groups/{w.a.groups['g1']}"),
    "updateAgentGroup": lambda w: (
        lambda r: Req(f"/agent-groups/{r.json()['id']}", {"name": "G2"}, if_match=r.headers["etag"])
    )(_group(w)),
    "listApiKeys": lambda w: Req("/api-keys"),
    "createApiKey": lambda w: Req(
        "/api-keys", {"name": unique("k"), "env": "test", "scopes": ["routing:read"]}
    ),
    "getApiKey": lambda w: Req(f"/api-keys/{_key(w)}"),
    "rotateApiKey": lambda w: Req(f"/api-keys/{_key(w)}/rotate", {"grace_s": 60}),
    "revokeApiKey": lambda w: Req(f"/api-keys/{_key(w)}/revoke", {"reason": REASON}),
}


# --- reads, sse, snapshot ----------------------------------------------------------------------


def _event(w: ContractWorld, agent_id: str, *, trace: UUID | None = None) -> UUID:
    event = uuid4()
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, call_id,"
        " trace_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash,"
        " normaliser_version, status, attrs) VALUES ($1, $2, now() - interval '5 seconds',"
        " 'gen_ai.request', 'gateway', $3, $4, $5, 'gw', 1, 'fresh', 'full', $6,"
        " 'normaliser/1.0', 'ok', '{\"gen_ai.system\": \"openai\"}')",
        w.a.id,
        event,
        UUID(agent_id),
        uuid4(),
        trace or uuid4(),
        b"\x07" * 32,
    )
    return event


def _run(w: ContractWorld, agent_id: str) -> UUID:
    """A finished root run: one ``agent.invoke`` end event (run id = its task id)."""
    run = uuid4()
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, task_id,"
        " trace_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash,"
        " normaliser_version, status, attrs) VALUES ($1, $2, now() - interval '5 seconds',"
        " 'agent.invoke', 'sdk', $3, $4, $5, 'sdk', 1, 'fresh', 'full', $6, 'normaliser/1.0',"
        ' \'ok\', \'{"phase": "end", "agent_name": "contract", "status": "ok"}\')',
        w.a.id,
        uuid4(),
        UUID(agent_id),
        run,
        uuid4(),
        b"\x07" * 32,
    )
    return run


def _snapshot(w: ContractWorld, agent_id: str) -> None:
    """A health snapshot so health and risk reads have something to show."""
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, agent_id, score, band,"
        " provisional, events_seen, observation_coverage, factors, horizons,"
        " predicted_failure_mode, scoring_config_id, policy_version, routing_state_at,"
        " window_start, window_end, grain_s)"
        " SELECT $1, now() - interval '1 minute', $2, 92, 'healthy', false, 120, 0.950,"
        " '[]'::jsonb, '{}'::jsonb, NULL, c.id, 3, 'active', now() - interval '10 minutes',"
        " now(), 60 FROM sibyl.scoring_config c WHERE c.tenant_id = $1 LIMIT 1",
        w.a.id,
        UUID(agent_id),
    )


def _with_snapshot(path: str) -> Scenario:
    def build(w: ContractWorld, a: dict[str, Any]) -> Req:
        _snapshot(w, a["id"])
        return Req(path.format(agent=a["id"]))

    return _with_agent(build)


def _payload(w: ContractWorld, agent_id: str) -> UUID:
    from sibyl_control.core.crypto.deks import dek_wrap_aad
    from sibyl_control.core.crypto.envelope import EncryptedBlob, build_aad, seal
    from sibyl_control.core.crypto.sealed import pack, payload_context

    ref = uuid4()
    body = b'{"messages":[]}'
    with w.admin.tx(w.a.id):
        key = w.admin.fetchrow(
            "SELECT id, version, wrapped_dek FROM sibyl.tenant_key WHERE tenant_id = $1"
            " AND purpose = 'payload' AND state = 'active'",
            w.a.id,
        )
        dek = kit.TEST_KEK.unwrap(
            bytes(key["wrapped_dek"]), dek_wrap_aad(w.a.id, "payload", key["version"])
        )
        sealed = seal(
            dek, body, build_aad(w.a.id, "payload", key["version"]) + payload_context(ref)
        )
        packed = pack(EncryptedBlob(key["version"], sealed.nonce, sealed.ciphertext))
        uri = f"tenant/{w.a.id}/2026-10-11/span_content/{ref}.bin"
        w.blob.objects[uri] = packed
        w.admin.execute(
            "INSERT INTO sibyl.payload_refs (tenant_id, id, kind, uri, content_type, sha256,"
            " size_bytes, stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
            " redaction_profile_hash, agent_id, source_kind, expires_at)"
            " VALUES ($1, $2, 'span_content', $3, 'application/json', $4, $5, $6, $7, $8, $9,"
            " 'full', $10, $11, 'event', now() + interval '30 days')",
            w.a.id,
            ref,
            uri,
            hashlib.sha256(body).digest(),
            len(body),
            len(packed),
            key["id"],
            key["version"],
            sealed.nonce,
            b"\x00" * 32,
            UUID(agent_id),
        )
    return ref


def _job(w: ContractWorld) -> str:
    resp = _api(w, "POST", f"/provider-credentials/{credential(w)}/verify")
    return str(resp.json()["job_id"])


def seal_keypair() -> tuple[X25519PrivateKey, str]:
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, b64url(public)


def vaulted_chain(w: ContractWorld, secret: str) -> tuple[str, str]:
    """An agent whose approved chain falls back to a vaulted credential → (agent, credential)."""
    pid = provider(w)
    mid = model(w, pid)
    cred = credential(w, pid, secret)
    created = agent(w, version={"primary_model_id": str(model(w))})
    chain = _chain(
        w,
        created["id"],
        [
            {
                "kind": "alt_provider",
                "provider_id": str(pid),
                "model_id": str(mid),
                "credential_id": cred,
                "risk": "low",
            },
            {"kind": "human_queue", "risk": "low"},
        ],
    )
    _api(
        w,
        "POST",
        f"/fallback-chains/{chain.json()['id']}/actions",
        {"action": "approve", "reason": "approved in contract scenario"},
    )
    return created["id"], cred


def _credentials_bundle(w: ContractWorld) -> Req:
    _, cred = vaulted_chain(w, "sk-bundle-" + uuid4().hex)
    _, public = seal_keypair()
    return Req("/policy/credentials", params={"ids": cred}, headers={"X-Sibyl-Seal-Key": public})


READS: dict[str, Scenario] = {
    "getRoutingState": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/routing")),
    "listRoutingTransitions": _with_agent(
        lambda w, a: Req(f"/agents/{a['id']}/routing/transitions")
    ),
    "getFleetHealth": lambda w: Req("/fleet/health"),
    "getAgentHealth": _with_snapshot("/agents/{agent}/health"),
    "getAgentHealthHistory": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/health/history")),
    "getAgentRisk": _with_snapshot("/agents/{agent}/risk"),
    "getAgentMetrics": _with_agent(
        lambda w, a: Req(f"/agents/{a['id']}/metrics", params={"grain": "5m"})
    ),
    "listAgentCheckpoints": _with_agent(lambda w, a: Req(f"/agents/{a['id']}/checkpoints")),
    "listEvents": lambda w: Req("/events"),
    "getEvent": _with_agent(lambda w, a: Req(f"/events/{_event(w, a['id'])}")),
    "getTrace": _with_agent(
        lambda w, a: (lambda t: (_event(w, a["id"], trace=t), Req(f"/traces/{t.hex}"))[1])(uuid4())
    ),
    "listRuns": _with_agent(lambda w, a: (_run(w, a["id"]), Req("/runs"))[1]),
    "getRun": _with_agent(lambda w, a: Req(f"/runs/{_run(w, a['id'])}")),
    "getPayload": _with_agent(lambda w, a: Req(f"/payloads/{_payload(w, a['id'])}")),
    "getJob": lambda w: Req(f"/jobs/{_job(w)}"),
    "streamEvents": lambda w: Req("/events/stream"),
    "getPolicySnapshot": lambda w: Req("/policy/snapshot"),
    "getPolicyCredentials": _credentials_bundle,
}


SCENARIOS: dict[str, Scenario] = {
    **REGISTRY,
    **TENANCY,
    **READS,
    **LANE_S,
    **ALERTS,
    **GOVERNANCE,
    **ACTION_GATE,
    **DRIFT,
    **SENTINEL,
    **INT3,
    **MONITORS,
}
