"""Lane G control routes against a migrated PG17: snapshot, key set, sealed credentials.

The gateway's own verifier and unsealer are the oracle (control and gateway must agree byte for
byte), and every body is validated against ``sibyl.policy_snapshot/1``.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sibyl_control.api.snapshot.service import SnapshotService
from sibyl_gateway.credentials.sealing import b64url, open_sealed, public_bytes, seal_aad
from sibyl_gateway.policy.keychain import KeyChain
from sibyl_gateway.policy.verify import SnapshotRejected, verify_snapshot
from sibyl_schemas import jsonschema as sj

from .conftest import SNAP_KID, VAULTED_SECRET, Api

SNAP = "/api/v1/policy/snapshot"


def block_of(raw: bytes) -> dict[str, Any]:
    body = json.loads(raw)
    (block,) = body["tenants"].values()
    return block


async def fetch(api: Api, key: str = "gateway", **params: str) -> Any:
    resp = await api.client.get(SNAP, headers=api.auth(key), params=params)
    assert resp.status_code == 200, resp.text
    return resp


async def key_chain(api: Api) -> KeyChain:
    resp = await api.client.get("/api/v1/policy/keys")
    assert resp.status_code == 200, resp.text
    pin = json.loads(resp.content)["body"]["keys"][0]
    chain = KeyChain.from_pin_json(json.dumps(pin))
    chain.accept(resp.content, now=datetime.now(UTC), persist=False)
    return chain


async def test_snapshot_is_schema_valid_signed_over_the_raw_bytes(api: Api) -> None:
    resp = await fetch(api)
    body = json.loads(resp.content)
    issues = list(sj.iter_errors("sibyl.policy_snapshot/1", body))
    assert not issues, issues[:3]
    assert list(body["tenants"]) == [str(api.world.tenant)]
    assert resp.headers["etag"] == f'"{body["version"]}"'
    assert resp.headers["x-sibyl-snapshot-kid"] == SNAP_KID
    assert resp.headers["cache-control"] == "max-age=60"
    chain = await key_chain(api)
    snap = verify_snapshot(
        resp.content,
        kid=resp.headers["x-sibyl-snapshot-kid"],
        signature=resp.headers["x-sibyl-snapshot-signature"],
        keys=chain.verification_keys(datetime.now(UTC)),
        held_version=None,
        now=datetime.now(UTC),
    )
    assert snap.version == body["version"]
    with pytest.raises(SnapshotRejected):
        verify_snapshot(
            resp.content.replace(b"closed", b"open!!"),
            kid=SNAP_KID,
            signature=resp.headers["x-sibyl-snapshot-signature"],
            keys=chain.verification_keys(datetime.now(UTC)),
            held_version=None,
            now=datetime.now(UTC),
        )


async def test_projection_content(api: Api) -> None:
    w = api.world
    block = block_of((await fetch(api)).content)
    agents = block["agents"]
    assert set(agents) == {str(w.agent_a), str(w.agent_b)}  # retired agent excluded
    a = agents[str(w.agent_a)]
    assert a["fail_mode"] == "closed" and a["inline_fallback"] is False
    assert a["limits"] == {
        "max_inflight": 10,
        "rps": 5.5,
        "budget_usd_month": "1500.0000",
        "spent_usd_month": "0",
    }
    assert a["identity"]["enforcement"] == "block"
    assert a["identity"]["allowed_models"] == ["alt-1", "large-1"]
    steps = a["fallback_chain"]["steps"]
    assert [s["position"] for s in steps] == [1, 2, 3]
    assert steps[1]["credential_id"] == str(w.credential) and steps[1]["viable"] is True
    assert '"secret"' not in json.dumps(block) and VAULTED_SECRET.decode() not in json.dumps(block)
    assert a["capture"] == {"mode": "full", "profile": "secrets_only"}
    assert block["capture_profiles"]["secrets_only"]["detectors_ref"] == "detectors/v1"
    assert agents[str(w.agent_b)]["route"]["state"] == "active"
    assert block["kill_switches"][0]["scope_id"] == str(w.agent_b)
    prefixes = {k["key_id"] for k in block["api_keys"].values()}
    assert len(prefixes) == 3  # gateway, sdk, bound_gw; revoked and lapsed rotation excluded
    assert all(p["base_url"].startswith("https://") for p in block["providers"].values())


async def test_key_visibility_and_agent_filtering(api: Api) -> None:
    w = api.world
    sdk = block_of((await fetch(api, "sdk")).content)
    assert sdk["api_keys"] == {}  # routing:read only: no key hashes
    assert set(sdk["agents"]) == {str(w.agent_a)}  # bound key sees its agent only
    assert sdk["kill_switches"] == []  # the other agent's kill is not visible
    bound = block_of((await fetch(api, "bound_gw")).content)
    assert {k["agent_id"] for k in bound["api_keys"].values()} == {str(w.agent_a)}
    one = block_of((await fetch(api, agent_id=str(w.agent_b))).content)
    assert set(one["agents"]) == {str(w.agent_b)}
    for key, agent in (
        ("sdk", w.agent_b),
        ("gateway", w.agent_retired),
        ("gateway", w.other_agent),
    ):
        resp = await api.client.get(SNAP, headers=api.auth(key), params={"agent_id": str(agent)})
        assert resp.status_code == 404, (key, resp.text)


async def test_tenant_isolation(api: Api) -> None:
    other = json.loads((await fetch(api, "other_gw")).content)
    assert list(other["tenants"]) == [str(api.world.other)]
    text = json.dumps(other)
    assert str(api.world.agent_a) not in text and str(api.world.tenant) not in text


async def test_etag_304_cache_reuse_and_version_bump(api: Api) -> None:
    first = await fetch(api)
    again = await fetch(api)
    assert again.headers["etag"] == first.headers["etag"]  # unchanged block: cached issue
    not_modified = await api.client.get(
        SNAP, headers=api.auth("gateway", **{"If-None-Match": first.headers["etag"]})
    )
    assert not_modified.status_code == 304 and not not_modified.content
    async with api.db.tenant_tx(api.world.tenant) as conn:
        await conn.execute(
            "UPDATE sibyl.continuity_plan SET max_inflight = 11 WHERE agent_id = $1",
            api.world.agent_a,
        )
    changed = await fetch(api)
    assert int(changed.headers["x-sibyl-snapshot-version"]) > int(
        first.headers["x-sibyl-snapshot-version"]
    )
    async with api.db.pre_tenant() as conn:
        issued = await conn.fetchval(
            "SELECT count(*) FROM sibyl.policy_snapshot_issue WHERE signer_kid = $1", SNAP_KID
        )
    assert issued >= 2


async def test_gzip_transfer_keeps_the_signature_over_raw(api: Api) -> None:
    plain = await fetch(api)
    resp = await api.client.get(SNAP, headers=api.auth("gateway", **{"Accept-Encoding": "gzip"}))
    assert resp.headers["content-encoding"] == "gzip"
    assert resp.content == plain.content  # httpx decoded; same canonical bytes
    assert gzip.compress(resp.content)  # sanity


async def test_size_budget_is_enforced(api: Api) -> None:
    api.service.max_raw = 100
    api.service._cache.clear()
    resp = await api.client.get(SNAP, headers=api.auth("gateway"))
    assert resp.status_code == 503 and resp.json()["type"].endswith("/snapshot_unavailable")


async def test_no_signer_or_no_db_is_503(api: Api) -> None:
    api.service.resolver = type(api.service.resolver)({})  # private key ref unresolvable
    api.service._cache.clear()
    resp = await api.client.get(SNAP, headers=api.auth("gateway"))
    assert resp.status_code == 503
    api.client._transport.app.state.snapshot_service = SnapshotService(None)  # type: ignore[attr-defined]
    resp = await api.client.get(SNAP, headers=api.auth("gateway"))
    assert resp.status_code == 503


async def test_key_set_routes_publish_the_signed_genesis(api: Api) -> None:
    resp = await api.client.get("/api/v1/policy/keys")
    well_known = await api.client.get("/.well-known/sibyl-keys.json")
    assert resp.content == well_known.content
    assert resp.headers["cache-control"] == "max-age=300"
    doc = json.loads(resp.content)
    assert doc["kid"] == SNAP_KID and doc["body"]["sequence"] == 1
    assert [k["kid"] for k in doc["body"]["keys"]] == [SNAP_KID]
    if "key_set_body" in sj.load_schema("sibyl.policy_snapshot/1")["$defs"]:
        assert sj.is_valid("sibyl.policy_snapshot/1", doc, pointer="/$defs/key_set")
    assert (await key_chain(api)).sequence == 1


async def test_credentials_are_sealed_to_the_gateway_key(api: Api) -> None:
    w = api.world
    gateway_key = X25519PrivateKey.generate()
    resp = await api.client.get(
        "/api/v1/policy/credentials",
        params={"ids": str(w.credential)},
        headers=api.auth("gateway", **{"X-Sibyl-Seal-Key": b64url(public_bytes(gateway_key))}),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["cache-control"] == "no-store"
    bundle = resp.json()
    assert bundle["expires_in_s"] == 300
    item = bundle["items"][str(w.credential)]
    assert VAULTED_SECRET.decode() not in resp.text
    plain = open_sealed(
        gateway_key, item["secret"], seal_aad(w.tenant, w.credential, item["key_version"])
    )
    assert plain == VAULTED_SECRET and item["base_url"] == "https://api.alt.example/v1"


async def test_credential_refusals(api: Api) -> None:
    w = api.world
    seal_header = {"X-Sibyl-Seal-Key": b64url(public_bytes(X25519PrivateKey.generate()))}
    url = "/api/v1/policy/credentials"
    for key, ids in (
        ("gateway", "0192f0b2-0000-7000-8000-0000000000aa"),
        ("other_gw", str(w.credential)),
    ):
        resp = await api.client.get(url, params={"ids": ids}, headers=api.auth(key, **seal_header))
        assert resp.status_code == 403 and resp.json()["type"].endswith(
            "/credential_not_in_snapshot"
        )
    resp = await api.client.get(url, params={"ids": str(w.credential)}, headers=api.auth("gateway"))
    assert resp.status_code == 422  # no seal key (validation_failed)
    resp = await api.client.get(
        url, params={"ids": "nope"}, headers=api.auth("gateway", **seal_header)
    )
    assert resp.status_code == 422
    api.service.demo = True
    resp = await api.client.get(
        url, params={"ids": str(w.credential)}, headers=api.auth("gateway", **seal_header)
    )
    assert resp.status_code == 409 and resp.json()["type"].endswith("/demo_mode")
    resp = await api.client.get(
        url, params={"ids": str(w.credential)}, headers=api.auth("sdk", **seal_header)
    )
    assert resp.status_code == 403  # routing:read key may not take credentials


async def test_unauthenticated_and_wrong_scope(api: Api) -> None:
    assert (await api.client.get(SNAP)).status_code == 401
    bad = api.world.keys["gateway"][:-2] + "xx"
    assert (
        await api.client.get(SNAP, headers={"Authorization": f"Bearer {bad}"})
    ).status_code == 401
    revoked = await api.client.get(SNAP, headers=api.auth("revoked"))
    assert revoked.status_code == 401


async def test_snapshot_route_is_rate_limited_per_key(api: Api) -> None:
    from sibyl_control.core.ratelimit import InMemoryRateLimiter

    api.services.rate_limiter = InMemoryRateLimiter()
    codes = [
        (await api.client.get(SNAP, headers=api.auth("gateway"))).status_code for _ in range(6)
    ]
    assert codes[0] == 200 and 429 in codes
