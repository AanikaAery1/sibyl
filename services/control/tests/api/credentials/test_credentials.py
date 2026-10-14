# ruff: noqa: S105, S106, S107  (synthetic secrets and bearer token names)
"""Provider credentials: envelope encryption, metadata-only reads, rotate/revoke, SSRF, R55.

Runs against a migrated PG17 (lane R harness). The plaintext secret must never appear in any
response, audit row or outbox payload; only ``vault.open_secret`` (the snapshot bundle path)
can recover it, and only for the row whose id it was sealed to.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.api.credentials.vault import open_secret
from sibyl_control.api.registry import ssrf
from sibyl_control.core.audit import RECEIPT_HEADER
from sibyl_control.core.crypto.envelope import DecryptionError, EncryptedBlob
from sibyl_lane_r_harness import Tenant, World, kek

BASE = "/api/v1/provider-credentials"
SIM_URL = "http://sibyl-sim:8300/openai/v1"
OPENAI_URL = "https://api.openai.com/v1"
SECRET = "sk-test-0123456789abcdefSECRETtail"


def _provider(world: World, tenant: Tenant, base_url: str = OPENAI_URL) -> UUID:
    pid: UUID = world.admin.fetchval(
        "INSERT INTO sibyl.provider (tenant_id, slug, name, provider_kind, dialect, base_url)"
        " VALUES ($1, $2, $2, 'openai', 'openai_compatible', $3) RETURNING id",
        tenant.id,
        f"p-{uuid4().hex[:10]}",
        base_url,
    )
    return pid


def _body(provider_id: UUID, base_url: str = SIM_URL, secret: str = SECRET) -> dict[str, Any]:
    return {
        "provider_id": str(provider_id),
        "name": "fallback key",
        "base_url": base_url,
        "auth_scheme": "bearer",
        "secret": secret,
    }


def _create(world: World, token: str = "owner", **kw: Any) -> Any:
    provider = kw.pop("provider_id", None) or _provider(world, world.a)
    return world.client.post(BASE, json=_body(provider, **kw), headers=world.idem(token))


@pytest.fixture
def no_dns() -> Iterator[None]:
    async def refuse(host: str, port: int) -> list[str]:
        raise AssertionError(f"unexpected DNS lookup of {host}")

    ssrf.set_resolver(refuse)
    yield
    ssrf.set_resolver(None)


@pytest.fixture
def dns() -> Iterator[dict[str, list[str]]]:
    table: dict[str, list[str]] = {}

    async def fake(host: str, port: int) -> list[str]:
        if host not in table:
            raise OSError("NXDOMAIN")
        return table[host]

    ssrf.set_resolver(fake)
    yield table
    ssrf.set_resolver(None)


def _row(world: World, credential_id: str) -> Any:
    return world.admin.fetchrow(
        "SELECT * FROM sibyl.provider_credential WHERE id = $1", UUID(credential_id)
    )


def _no_secret_anywhere(world: World, *texts: str) -> None:
    for text in texts:
        assert SECRET not in text
    rows = world.admin.fetch(
        "SELECT detail::text AS d FROM sibyl.audit_events WHERE tenant_id = $1", world.a.id
    )
    outbox = world.admin.fetch(
        "SELECT payload::text AS d FROM sibyl.outbox WHERE tenant_id = $1", world.a.id
    )
    for row in [*rows, *outbox]:
        assert SECRET not in row["d"]
        assert SECRET[-8:] not in row["d"]


# --- create -----------------------------------------------------------------------------------


def test_create_seals_the_secret_and_returns_metadata_only(world: World, no_dns: None) -> None:
    resp = _create(world)
    assert resp.status_code == 201, resp.text
    meta = resp.json()
    assert meta["status"] == "active"
    assert meta["base_url"] == SIM_URL
    assert meta["allowlist_basis"] == "resolver_checked"
    assert meta["secret_hint"] == SECRET[-4:]
    assert meta["key_version"] == 1
    for forbidden in ("ciphertext", "nonce", "secret_sha256", "secret"):
        assert forbidden not in meta
    assert resp.headers[RECEIPT_HEADER].startswith(f"{world.a.id}:")
    row = _row(world, meta["id"])
    assert row["ciphertext"] is not None and SECRET.encode() not in bytes(row["ciphertext"])
    assert len(bytes(row["nonce"])) == 12
    action = world.admin.fetchrow(
        "SELECT action, actor_type, reason, detail FROM sibyl.audit_events"
        " WHERE tenant_id = $1 AND resource_id = $2",
        world.a.id,
        UUID(meta["id"]),
    )
    assert action["action"] == "credential.created"
    assert action["actor_type"] == "human"
    assert action["reason"]
    detail = json.loads(action["detail"]) if isinstance(action["detail"], str) else action["detail"]
    assert detail["credential_id"] == meta["id"]
    assert detail["allowlist_basis"] == "resolver_checked"
    policy = world.admin.fetchval(
        "SELECT count(*) FROM sibyl.outbox WHERE tenant_id = $1 AND event_type = 'policy_changed'"
        " AND aggregate_id = $2",
        world.a.id,
        UUID(meta["id"]),
    )
    assert policy == 1
    _no_secret_anywhere(world, resp.text)


def test_sealed_secret_opens_only_for_its_own_row(world: World, no_dns: None) -> None:
    first = _create(world).json()
    second = _create(world, secret="sk-other-secret-value-0000").json()
    row = _row(world, first["id"])
    blob = EncryptedBlob(int(row["key_version"]), bytes(row["nonce"]), bytes(row["ciphertext"]))
    plain = world.admin.run(open_secret(world.admin.raw, kek(), world.a.id, row["id"], blob))
    assert plain == SECRET.encode()
    with pytest.raises(DecryptionError):
        world.admin.run(open_secret(world.admin.raw, kek(), world.a.id, UUID(second["id"]), blob))
    with pytest.raises(DecryptionError):
        world.admin.run(open_secret(world.admin.raw, kek(), world.b.id, row["id"], blob))


def test_short_secret_gets_a_masked_hint(world: World, no_dns: None) -> None:
    resp = _create(world, secret="abc12345")
    assert resp.status_code == 201
    assert resp.json()["secret_hint"] == "****"


def test_known_provider_host_skips_dns(world: World, no_dns: None) -> None:
    resp = _create(world, base_url=OPENAI_URL)
    assert resp.status_code == 201, resp.text
    assert resp.json()["allowlist_basis"] == "known_provider"


def test_public_resolving_host_is_resolver_checked(world: World, dns: dict[str, list[str]]) -> None:
    dns["llm.example.com"] = ["93.184.216.34"]
    resp = _create(world, base_url="https://llm.example.com/v1")
    assert resp.status_code == 201, resp.text
    assert resp.json()["allowlist_basis"] == "resolver_checked"


@pytest.mark.parametrize(
    "addresses", [["10.1.2.3"], ["93.184.216.34", "127.0.0.1"], ["169.254.169.254"]]
)
def test_host_resolving_to_a_private_address_is_refused(
    world: World, dns: dict[str, list[str]], addresses: list[str]
) -> None:
    dns["rebind.example.com"] = addresses
    resp = _create(world, base_url="https://rebind.example.com/v1")
    assert resp.status_code == 422
    assert resp.json()["type"].endswith("/base_url_not_allowlisted")
    assert "rebind.example.com" not in resp.text


@pytest.mark.parametrize(
    "url",
    [
        "http://api.openai.com/v1",
        "https://127.0.0.1/v1",
        "https://user:pw@api.openai.com/v1",
        "https://localhost/v1",
        "ftp://sibyl-sim/v1",
    ],
)
def test_non_allowlisted_base_url_is_422(world: World, no_dns: None, url: str) -> None:
    resp = _create(world, base_url=url)
    assert resp.status_code == 422
    assert resp.json()["type"].endswith("/base_url_not_allowlisted")


def test_unknown_or_foreign_provider_is_422(world: World, no_dns: None) -> None:
    foreign = _provider(world, world.b)
    for provider in (uuid4(), foreign):
        resp = _create(world, provider_id=provider)
        assert resp.status_code == 422
        assert resp.json()["type"].endswith("/validation_failed")


def test_demo_mode_allows_only_sim_doubles(world: World, no_dns: None) -> None:
    world.settings.demo = True
    try:
        refused = _create(world, base_url=OPENAI_URL)
        assert refused.status_code == 409
        assert refused.json()["type"].endswith("/demo_mode")
        assert _create(world, base_url=SIM_URL).status_code == 201
    finally:
        world.settings.demo = False


def test_missing_kek_is_503_and_writes_nothing(world: World, no_dns: None) -> None:
    saved = world.settings.kek
    world.settings.kek = None
    try:
        before = world.admin.fetchval("SELECT count(*) FROM sibyl.provider_credential")
        resp = _create(world)
        assert resp.status_code == 503
        assert world.admin.fetchval("SELECT count(*) FROM sibyl.provider_credential") == before
    finally:
        world.settings.kek = saved


def test_validation_errors_never_echo_the_secret(world: World, no_dns: None) -> None:
    body = _body(_provider(world, world.a))
    body["extra"] = "x"
    resp = world.client.post(BASE, json=body, headers=world.idem())
    assert resp.status_code == 422
    assert SECRET not in resp.text
    body = _body(_provider(world, world.a), secret="")
    resp = world.client.post(BASE, json=body, headers=world.idem())
    assert resp.status_code == 422


def test_stale_step_up_is_refused(world: World, no_dns: None) -> None:
    resp = _create(world, token="owner-stale")
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("/step_up_required")
    assert resp.json()["step_up_url"]


@pytest.mark.parametrize("token", ["auditor", "engineer", "operator", "viewer"])
def test_roles_without_manage_cannot_create(world: World, no_dns: None, token: str) -> None:
    resp = _create(world, token=token)
    assert resp.status_code == 403


@pytest.mark.parametrize("token", ["owner", "admin", "security_admin"])
def test_manage_roles_can_create(world: World, no_dns: None, token: str) -> None:
    assert _create(world, token=token).status_code == 201


def test_replay_returns_the_stored_response(world: World, no_dns: None) -> None:
    headers = world.idem()
    body = _body(_provider(world, world.a))
    first = world.client.post(BASE, json=body, headers=headers)
    second = world.client.post(BASE, json=body, headers=headers)
    assert first.status_code == second.status_code == 201
    assert second.headers["Idempotency-Replayed"] == "true"
    assert second.json()["id"] == first.json()["id"]
    assert second.headers[RECEIPT_HEADER] == first.headers[RECEIPT_HEADER]
    count = world.admin.fetchval(
        "SELECT count(*) FROM sibyl.provider_credential WHERE provider_id = $1",
        UUID(body["provider_id"]),
    )
    assert count == 1
    other = world.client.post(BASE, json={**body, "name": "changed"}, headers=headers)
    assert other.status_code == 422


def test_missing_idempotency_key_is_428(world: World, no_dns: None) -> None:
    resp = world.client.post(
        BASE, json=_body(_provider(world, world.a)), headers=world.headers("owner")
    )
    assert resp.status_code == 428


# --- list -------------------------------------------------------------------------------------


def test_list_is_metadata_only_and_filters(world: World, no_dns: None) -> None:
    provider = _provider(world, world.a)
    created = _create(world, provider_id=provider).json()
    resp = world.client.get(
        BASE, params={"provider_id": str(provider)}, headers=world.headers("auditor")
    )
    assert resp.status_code == 200, resp.text
    page = resp.json()
    assert [c["id"] for c in page["data"]] == [created["id"]]
    for item in page["data"]:
        assert set(item) == {
            "id",
            "name",
            "provider_id",
            "purpose",
            "base_url",
            "allowlist_basis",
            "auth_scheme",
            "secret_hint",
            "status",
            "key_version",
            "expires_at",
            "last_used_at",
            "last_verified_at",
        }
    assert "ciphertext" not in resp.text and SECRET not in resp.text
    revoked = world.client.get(
        BASE,
        params={"status": "revoked", "provider_id": str(provider)},
        headers=world.headers("owner"),
    )
    assert revoked.json()["data"] == []


def test_list_pages_with_a_cursor(world: World, no_dns: None) -> None:
    provider = _provider(world, world.a)
    ids = [_create(world, provider_id=provider).json()["id"] for _ in range(3)]
    seen: list[str] = []
    params: dict[str, Any] = {"provider_id": str(provider), "limit": 2}
    while True:
        page = world.client.get(BASE, params=params, headers=world.headers("owner")).json()
        seen += [c["id"] for c in page["data"]]
        if not page["has_more"]:
            break
        params["cursor"] = page["next_cursor"]
    assert seen == ids
    bad = world.client.get(
        BASE, params={"cursor": params["cursor"], "limit": 2}, headers=world.headers("owner")
    )
    assert bad.status_code == 400


def test_list_never_crosses_tenants(world: World, no_dns: None) -> None:
    created = _create(world).json()
    resp = world.client.get(BASE, headers=world.headers("owner-b"))
    assert resp.status_code == 200
    assert created["id"] not in [c["id"] for c in resp.json()["data"]]


def test_viewer_cannot_list(world: World) -> None:
    assert world.client.get(BASE, headers=world.headers("viewer")).status_code == 403


def test_group_limited_reader_sees_only_credentials_its_agents_use(
    world: World, no_dns: None
) -> None:
    a = world.a
    provider = _provider(world, a)
    used = _create(world, provider_id=provider).json()["id"]
    unused = _create(world, provider_id=provider).json()["id"]
    elsewhere = _create(world, provider_id=provider).json()["id"]
    for group, credential in ((a.group_id, used), (a.other_group_id, elsewhere)):
        agent = world.admin.fetchval(
            "INSERT INTO sibyl.agent (tenant_id, slug, name, kind, fail_mode, agent_group_id)"
            " VALUES ($1, $2, $2, 'chatbot', 'open', $3) RETURNING id",
            a.id,
            f"agent-{uuid4().hex[:8]}",
            group,
        )
        chain = world.admin.fetchval(
            "INSERT INTO sibyl.fallback_chain (tenant_id, agent_id, version_no,"
            " requested_by_user_id) VALUES ($1, $2, 1, $3) RETURNING id",
            a.id,
            agent,
            a.users["owner"],
        )
        world.admin.execute(
            "INSERT INTO sibyl.fallback_step (tenant_id, chain_id, position, kind, provider_id,"
            " credential_id) VALUES ($1, $2, 0, 'alt_provider', $3, $4)",
            a.id,
            chain,
            provider,
            UUID(credential),
        )
    resp = world.client.get(
        BASE, params={"provider_id": str(provider)}, headers=world.headers("engineer")
    )
    assert resp.status_code == 200, resp.text
    assert [c["id"] for c in resp.json()["data"]] == [used]
    owner_view = world.client.get(
        BASE, params={"provider_id": str(provider)}, headers=world.headers("owner")
    ).json()
    assert {c["id"] for c in owner_view["data"]} == {used, unused, elsewhere}


# --- rotate -----------------------------------------------------------------------------------


def _rotate(world: World, credential_id: str, token: str = "owner", **body: Any) -> Any:
    payload = {"secret": "sk-rotated-secret-value-9876", **body}
    return world.client.post(
        f"{BASE}/{credential_id}/rotate", json=payload, headers=world.idem(token)
    )


def test_rotate_creates_a_new_row_and_puts_the_old_in_grace(world: World, no_dns: None) -> None:
    old = _create(world).json()
    resp = _rotate(world, old["id"], grace_s=600)
    assert resp.status_code == 201, resp.text
    new = resp.json()
    assert new["id"] != old["id"]
    assert new["status"] == "active"
    assert new["secret_hint"] == "9876"
    assert new["base_url"] == old["base_url"]
    old_row = _row(world, old["id"])
    new_row = _row(world, new["id"])
    assert old_row["status"] == "rotating"
    assert old_row["ciphertext"] is not None  # still usable during the grace window
    grace = (old_row["rotation_grace_until"] - new_row["created_at"]).total_seconds()
    assert 590 <= grace <= 610
    assert new_row["rotated_from_id"] == old_row["id"]
    actions = world.admin.fetch(
        "SELECT action FROM sibyl.audit_events WHERE tenant_id = $1 AND resource_id = $2",
        world.a.id,
        new_row["id"],
    )
    assert [r["action"] for r in actions] == ["credential.rotated"]
    assert resp.headers[RECEIPT_HEADER]
    _no_secret_anywhere(world, resp.text)


def test_rotate_twice_is_409_not_active(world: World, no_dns: None) -> None:
    old = _create(world).json()
    assert _rotate(world, old["id"]).status_code == 201
    again = _rotate(world, old["id"])
    assert again.status_code == 409
    assert again.json()["type"].endswith("/not_active")


def test_rotate_grace_is_bounded(world: World, no_dns: None) -> None:
    old = _create(world).json()
    assert _rotate(world, old["id"], grace_s=86401).status_code == 422


def test_rotate_unknown_or_foreign_is_404(world: World, no_dns: None) -> None:
    created = _create(world).json()
    assert _rotate(world, str(uuid4())).status_code == 404
    assert _rotate(world, created["id"], token="owner-b").status_code == 404


def test_rotate_needs_fresh_step_up(world: World, no_dns: None) -> None:
    created = _create(world).json()
    resp = _rotate(world, created["id"], token="owner-stale")
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("/step_up_required")


# --- revoke -----------------------------------------------------------------------------------


def _revoke(world: World, credential_id: str, token: str = "owner") -> Any:
    return world.client.post(
        f"{BASE}/{credential_id}/revoke",
        json={"reason": "leaked in a ticket attachment"},
        headers=world.idem(token),
    )


def test_revoke_drops_the_ciphertext(world: World, no_dns: None) -> None:
    created = _create(world).json()
    resp = _revoke(world, created["id"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "revoked"
    row = _row(world, created["id"])
    assert row["ciphertext"] is None and row["nonce"] is None
    assert row["revoke_reason"] == "leaked in a ticket attachment"
    audit = world.admin.fetchrow(
        "SELECT action, reason FROM sibyl.audit_events WHERE tenant_id = $1 AND resource_id = $2"
        " AND action = 'credential.revoked'",
        world.a.id,
        row["id"],
    )
    assert audit["reason"] == "leaked in a ticket attachment"
    assert resp.headers[RECEIPT_HEADER]


def test_revoke_twice_is_409(world: World, no_dns: None) -> None:
    created = _create(world).json()
    assert _revoke(world, created["id"]).status_code == 200
    again = _revoke(world, created["id"])
    assert again.status_code == 409
    assert again.json()["type"].endswith("/already_revoked")


def test_revoke_a_rotating_credential_and_rotation_after_revoke(world: World, no_dns: None) -> None:
    old = _create(world).json()
    assert _rotate(world, old["id"]).status_code == 201
    assert _revoke(world, old["id"]).status_code == 200
    assert _rotate(world, old["id"]).status_code == 409


def test_revoke_requires_a_reason(world: World, no_dns: None) -> None:
    created = _create(world).json()
    resp = world.client.post(
        f"{BASE}/{created['id']}/revoke", json={"reason": "short"}, headers=world.idem()
    )
    assert resp.status_code == 422


def test_revoke_foreign_is_404(world: World, no_dns: None) -> None:
    created = _create(world).json()
    assert _revoke(world, created["id"], token="owner-b").status_code == 404


# --- verify -----------------------------------------------------------------------------------


def test_verify_is_not_run_inline(world: World, no_dns: None) -> None:
    """B14: verify only enqueues a ``credential_probe`` job (202 + job id); the probe, and its
    ``credential.verified`` / ``credential.probe_failed`` rows, belong to the worker."""
    created = _create(world).json()
    before = world.admin.fetchval(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1", world.a.id
    )
    resp = world.client.post(f"{BASE}/{created['id']}/verify", headers=world.idem())
    assert resp.status_code == 202, resp.text
    job = world.admin.fetchrow(
        "SELECT kind, state, subject_id FROM sibyl.job WHERE id = $1", UUID(resp.json()["job_id"])
    )
    assert (job["kind"], job["state"], str(job["subject_id"])) == (
        "credential_probe",
        "queued",
        created["id"],
    )
    after = world.admin.fetchval(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1", world.a.id
    )
    assert after == before


def test_list_writes_no_audit_row_and_no_receipt(world: World, no_dns: None) -> None:
    _create(world)
    before = world.admin.fetchval(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1", world.a.id
    )
    resp = world.client.get(BASE, headers=world.headers("owner"))
    assert resp.status_code == 200
    assert RECEIPT_HEADER not in resp.headers
    after = world.admin.fetchval(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1", world.a.id
    )
    assert after == before
