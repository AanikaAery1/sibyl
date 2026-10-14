"""SnapshotFetcher against a fake control plane (httpx MockTransport)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sibyl_gateway.credentials.sealing import b64url_decode, seal, seal_aad
from sibyl_gateway.credentials.vault import CredentialVault
from sibyl_gateway.policy.fetcher import SnapshotFetcher
from sibyl_gateway.policy.keychain import KeyChain
from sibyl_gateway.policy.store import SnapshotStore
from sibyl_gateway.policy.verify import PinnedKeySet
from sibyl_gateway.policy.view import CredentialRef

from ..support import CRED, GATEWAY_KEY, GATEWAY_PREFIX, TENANT, TestSigner, body, tenant_block
from .test_keychain import _Key


class FakeControl:
    def __init__(self, signer: TestSigner, vault: CredentialVault) -> None:
        self.signer = signer
        self.vault = vault
        self.version = 1
        self.tamper = False
        self.requests: list[httpx.Request] = []
        block = tenant_block()
        block["kill_switches"] = [
            {
                "kill_switch_id": "0192f0d1-0000-7000-8000-000000000001",
                "scope_kind": "agent",
                "scope_id": "0192767f-0000-7000-8000-00000000c012",
                "pulled_at": "2026-10-10T11:40:00.000Z",
            }
        ]
        self.block = block

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["authorization"] == f"Bearer {GATEWAY_KEY}"
        if request.url.path == "/api/v1/policy/snapshot":
            if request.headers.get("if-none-match") == f'"{self.version}"':
                return httpx.Response(304, headers={"etag": f'"{self.version}"'})
            raw, kid, sig = self.signer.deliver(
                body(self.version, tenants={str(TENANT): self.block})
            )
            if self.tamper:
                raw = raw.replace(b'"killed"', b'"active"')
            return httpx.Response(
                200,
                content=raw,
                headers={
                    "etag": f'"{self.version}"',
                    "x-sibyl-snapshot-kid": kid,
                    "x-sibyl-snapshot-signature": sig,
                },
            )
        if request.url.path == "/api/v1/policy/credentials":
            pub = b64url_decode(request.headers["x-sibyl-seal-key"])
            assert request.url.params["ids"] == str(CRED)
            item = {
                "auth_scheme": "bearer",
                "base_url": "https://x.example/v1",
                "key_version": 4,
                "secret": seal(pub, b"sk-vault", seal_aad(TENANT, CRED, 4)),
            }
            return httpx.Response(200, json={"expires_in_s": 300, "items": {str(CRED): item}})
        if request.url.path.endswith("/acks"):
            return httpx.Response(201, json={})
        return httpx.Response(404)


def setup() -> tuple[SnapshotFetcher, FakeControl, SnapshotStore, CredentialVault, list[Any]]:
    signer = TestSigner()
    store = SnapshotStore(PinnedKeySet.from_document(signer.key_set()))
    vault = CredentialVault()
    control = FakeControl(signer, vault)
    rejected: list[Any] = []
    fetcher = SnapshotFetcher(
        store,
        vault,
        control_url="http://api:8000",
        streams={GATEWAY_PREFIX: GATEWAY_KEY},
        client=httpx.AsyncClient(transport=httpx.MockTransport(control.handler)),
        gateway_id="gw-1",
        on_rejected=lambda *a: rejected.append(a),
    )
    return fetcher, control, store, vault, rejected


async def test_install_then_not_modified_then_credentials_and_acks() -> None:
    fetcher, control, store, vault, _ = setup()
    assert await fetcher.refresh(GATEWAY_PREFIX) == "installed"
    assert store.held_version(GATEWAY_PREFIX) == 1
    handle = vault.get(CredentialRef(CRED, 4))
    assert handle is not None and handle.reveal() == b"sk-vault"
    acks = [r for r in control.requests if r.url.path.endswith("/acks")]
    assert len(acks) == 1
    assert json.loads(acks[0].content) == {"gateway_id": "gw-1", "snapshot_version": 1}
    assert await fetcher.refresh(GATEWAY_PREFIX) == "not_modified"
    control.version = 2
    assert await fetcher.refresh(GATEWAY_PREFIX) == "installed"
    assert len([r for r in control.requests if r.url.path.endswith("/acks")]) == 1  # acked once
    assert fetcher.stats.installed == 2 and fetcher.stats.not_modified == 1


async def test_tampered_delivery_is_rejected_and_the_held_snapshot_stays() -> None:
    fetcher, control, store, _, rejected = setup()
    await fetcher.refresh(GATEWAY_PREFIX)
    control.version, control.tamper = 2, True
    assert await fetcher.refresh(GATEWAY_PREFIX) == "rejected:bad_signature"
    assert store.held_version(GATEWAY_PREFIX) == 1
    assert rejected == [(GATEWAY_PREFIX, "bad_signature", 1)]
    assert fetcher.stats.rejected == {"bad_signature": 1}


async def test_control_plane_errors_never_touch_the_held_snapshot() -> None:
    signer = TestSigner()
    store = SnapshotStore(PinnedKeySet.from_document(signer.key_set()))

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    fetcher = SnapshotFetcher(
        store,
        CredentialVault(),
        control_url="http://api",
        streams={GATEWAY_PREFIX: GATEWAY_KEY},
        client=httpx.AsyncClient(transport=httpx.MockTransport(down)),
        gateway_id="gw",
    )
    assert await fetcher.refresh(GATEWAY_PREFIX) == "error"
    await fetcher.refresh_all()
    assert not store.ever_loaded and fetcher.stats.errors == 2


async def test_rotation_is_followed_and_snapshots_by_the_new_key_verify() -> None:
    k1, k2 = _Key("k1"), _Key("k2")
    t0 = datetime.now(UTC) - timedelta(days=2)
    sets = [k1.sign_set(1, [k1.entry()], k2.entry(None), t0)]
    chain = KeyChain.from_pin_json(json.dumps(k1.entry()))
    store = SnapshotStore(chain.verification_keys(datetime.now(UTC)))
    new_signer = TestSigner("k2")
    new_signer._key = k2.private

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/policy/keys":
            assert "authorization" not in request.headers  # public route, no key sent
            since = int(request.url.params["since"])
            docs = [json.loads(s) for s in sets if json.loads(s)["body"]["sequence"] > since]
            latest = json.loads(sets[-1])["body"]["sequence"]
            return httpx.Response(200, json={"data": docs, "latest_sequence": latest})
        raw, kid, sig = new_signer.deliver(body(5, tenants={str(TENANT): tenant_block()}))
        return httpx.Response(
            200,
            content=raw,
            headers={"x-sibyl-snapshot-kid": kid, "x-sibyl-snapshot-signature": sig},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    fetcher = SnapshotFetcher(
        store,
        CredentialVault(),
        control_url="http://api",
        streams={GATEWAY_PREFIX: GATEWAY_KEY},
        client=client,
        gateway_id="gw",
        keychain=chain,
    )
    assert await fetcher.refresh_keys() == "installed"  # genesis: still k1 only
    assert await fetcher.refresh(GATEWAY_PREFIX) == "rejected:unknown_kid"
    sets.append(k1.sign_set(2, [k2.entry(), k1.entry("retiring")], None, t0 + timedelta(days=1)))
    fetcher._keys_at = None
    assert await fetcher.refresh(GATEWAY_PREFIX) == "rejected:unknown_kid"  # forces key refresh
    assert chain.sequence == 2
    assert await fetcher.refresh(GATEWAY_PREFIX) == "installed"
    fetcher._keys_at = None
    assert await fetcher.refresh_keys() == "not_modified"  # ?since=2: nothing newer
    sets.append(k1.sign_set(3, [k1.entry()], None, t0))  # signed by the retired key
    fetcher._keys_at = None
    assert await fetcher.refresh_keys() == "rejected:unknown_signer"
    assert fetcher.stats.key_set_rejected == {"unknown_signer": 1} and chain.sequence == 2
