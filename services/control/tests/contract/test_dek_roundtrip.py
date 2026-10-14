"""B11 cross-lane round trips on the shared world (one DEK-wrap convention in ``core/crypto``).

(a) A payload sealed by **ingest** (``ingest.payloads.PayloadSealer`` + ``ingest.store
    .insert_payload_refs``, the code the ingest service runs) is served decrypted by the **reads**
    route ``GET /api/v1/payloads/{id}``.
(b) A credential vaulted by the **registry** route ``POST /api/v1/provider-credentials`` is opened
    by the **snapshot** bundle (``GET /api/v1/policy/credentials``) and sealed to the gateway's
    X25519 key, which the **gateway**'s own ``open_sealed`` recovers byte for byte.
Before B11 both failed: ingest's blob layout was opened as raw ciphertext, and the registry
wrapped DEKs under a ``sibyl.tenant_key`` AAD prefix the snapshot builder did not use.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import asyncpg
from sibyl_control.core.crypto.deks import ConnDekProvider
from sibyl_control.core.db import _init_connection
from sibyl_control.ingest.payloads import PayloadSealer
from sibyl_control.ingest.store import insert_payload_refs
from sibyl_gateway.credentials.sealing import open_sealed, seal_aad

from .pg_world import ContractWorld, kit
from .scenarios import seal_keypair, vaulted_chain


def test_a_payload_ingest_sealed_is_served_by_the_reads_route(cworld: ContractWorld) -> None:
    tenant, agent = cworld.a.id, cworld.a.agents["in_g1"]
    plaintext = b'{"messages":[{"role":"user","content":"hello"}]}'

    async def ingest() -> UUID:
        conn = await asyncpg.connect(cworld.db.dsn("sibyl_ingest"))
        await _init_connection(conn)
        try:
            async with conn.transaction():
                await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
                sealer = PayloadSealer(cworld.blob, ConnDekProvider(conn, kit.TEST_KEK))
                sealed = await sealer.seal(
                    tenant,
                    plaintext,
                    kind="span_content",
                    source_kind="event",
                    content_type="application/json",
                    parts=(),
                    capture_mode="full",
                    redaction_profile_hash=b"\x00" * 32,
                    now=datetime.now(UTC),
                    retention=timedelta(days=30),
                    agent_id=agent,
                )
                await insert_payload_refs(conn, tenant, [sealed])
            return sealed.id
        finally:
            await conn.close()

    ref = cworld.db.loop.run_until_complete(ingest())
    resp = cworld.client.get(f"/api/v1/payloads/{ref}", headers=cworld.headers("owner"))
    assert resp.status_code == 200, resp.text
    assert resp.content == plaintext
    assert resp.headers["x-sibyl-capture-mode"] == "full"


def test_a_registry_vaulted_credential_opens_in_the_snapshot_bundle(cworld: ContractWorld) -> None:
    secret = "sk-roundtrip-" + uuid4().hex
    _, credential = vaulted_chain(cworld, secret)
    private, public = seal_keypair()
    resp = cworld.client.get(
        "/api/v1/policy/credentials",
        params={"ids": credential},
        headers=cworld.headers("keys", **{"X-Sibyl-Seal-Key": public}),
    )
    assert resp.status_code == 200, resp.text
    item = resp.json()["items"][credential]
    aad = seal_aad(cworld.a.id, credential, item["key_version"])
    assert open_sealed(private, item["secret"], aad) == secret.encode()
    assert secret not in resp.text
