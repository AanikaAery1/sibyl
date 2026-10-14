"""Capture modes (most restrictive wins), payload sealing (AES-256-GCM, AAD-bound, blob before
row) and crypto-shred."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.crypto.deks import DekUnavailable, PgDekProvider
from sibyl_control.core.crypto.envelope import DecryptionError, LocalKek, generate_dek
from sibyl_control.core.crypto.sealed import SealedFormatError, open_payload, unpack
from sibyl_control.ingest.flusher import flush_tenant

from .conftest import FIXTURE_AGENT, KEK, World
from .otlp_build import chat_attrs, span, traces

MESSAGES = '[{"role":"user","content":"Email jane.doe@example.com about card 4111 1111 1111 1111"}]'
OUTPUT = '[{"role":"assistant","content":"Done, quote sent."}]'


def _chat(**extra: str) -> bytes:
    attrs = chat_attrs(
        **{
            "gen_ai.input.messages": MESSAGES,
            "gen_ai.output.messages": OUTPUT,
            "sibyl.agent_id": str(FIXTURE_AGENT),
            **extra,
        }
    )
    return traces([span(attrs)])


async def _flushed_row(world: World) -> dict:
    await flush_tenant(
        world.db, world.tenant_id, world.services.cfg, now=datetime.now(UTC) + timedelta(minutes=1)
    )
    row = await world.admin.fetchrow(
        "SELECT * FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'gen_ai.request'",
        world.tenant_id,
    )
    assert row is not None
    return dict(row)


def _attrs(row: dict) -> dict:
    return row["attrs"] if isinstance(row["attrs"], dict) else json.loads(row["attrs"])


async def _content(world: World, payload_ref_id: UUID) -> bytes:
    ref = await world.admin.fetchrow(
        "SELECT uri FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2",
        world.tenant_id,
        payload_ref_id,
    )
    return await open_payload(
        world.blob, world.services.service.deks, world.tenant_id, ref["uri"], payload_ref_id
    )  # type: ignore[union-attr]


async def test_full_mode_stores_the_scrubbed_body(world: World) -> None:
    await world.post("/v1/otlp/traces", _chat())
    row = await _flushed_row(world)
    assert row["capture_mode"] == "full"
    body = json.loads(await _content(world, row["payload_ref_id"]))
    assert body["input_messages"][0]["content"].startswith("Email jane.doe@example.com")
    ref = await world.admin.fetchrow(
        "SELECT * FROM sibyl.payload_refs WHERE id = $1", row["payload_ref_id"]
    )
    assert (
        ref["kind"] == "span_content" and ref["capture_mode"] == "full" and len(ref["nonce"]) == 12
    )
    assert ref["sha256"] == row["payload_sha256"]
    assert _attrs(row)["payload"]["ref"].startswith(f"blob://{world.tenant_id}/")


async def test_metadata_tenant_policy_keeps_hashes_only(world_factory) -> None:
    world = await world_factory(mode="metadata")
    await world.post("/v1/otlp/traces", _chat())
    row = await _flushed_row(world)
    assert row["capture_mode"] == "metadata" and row["payload_ref_id"] is None
    attrs = _attrs(row)
    assert set(attrs["content_hashes"]) == {"input_sha256", "output_sha256"}  # row storage form
    assert attrs["output_chars"] == len("Done, quote sent.") + len("assistant")
    kinds = {
        r["kind"]
        for r in await world.rows(
            "SELECT kind FROM sibyl.payload_refs WHERE tenant_id = $1", world.tenant_id
        )
    }
    assert kinds == {"raw_batch"}
    raw = await world.admin.fetchrow(
        "SELECT id, uri FROM sibyl.payload_refs WHERE tenant_id = $1", world.tenant_id
    )
    text = await open_payload(
        world.blob, world.services.service.deks, world.tenant_id, raw["uri"], raw["id"]
    )  # type: ignore[union-attr]
    assert b"jane.doe" not in text  # the raw batch never carries content


async def test_emitter_mode_stricter_than_policy_wins(world: World) -> None:
    await world.post("/v1/otlp/traces", _chat(**{"sibyl.capture.mode": "metadata"}))
    row = await _flushed_row(world)
    assert row["capture_mode"] == "metadata" and row["payload_ref_id"] is None


async def test_agent_policy_stricter_than_tenant(world: World) -> None:
    await world.set_capture("metadata", agent=FIXTURE_AGENT)
    await world.post("/v1/otlp/traces", _chat())
    row = await _flushed_row(world)
    assert row["capture_mode"] == "metadata"


async def test_redacted_mode_applies_the_pii_profile(world: World) -> None:
    await world.set_capture("redacted", profile="pii_standard")
    await world.post("/v1/otlp/traces", _chat())
    row = await _flushed_row(world)
    assert row["capture_mode"] == "redacted"
    text = (await _content(world, row["payload_ref_id"])).decode()
    assert "jane.doe@example.com" not in text and "4111 1111 1111 1111" not in text
    assert "[PII_EMAIL:" in text and "[PII_CREDIT_CARD:" in text
    pii_hash = await world.val(
        "SELECT content_hash FROM sibyl.redaction_profile WHERE tenant_id = $1 AND name ="
        " 'pii_standard'",
        world.tenant_id,
    )
    assert row["redaction_profile_hash"] == pii_hash


async def test_payload_over_the_policy_cap_is_truncated_tail_first(world: World) -> None:
    from .test_replay import _batch
    from .test_scrub_e2e import _tool_event

    event = _tool_event({"field": "tool_args", "text": "z" * 300_000}, 1)
    resp = await world.post("/v1/events", _batch([event]))
    assert resp.json()["accepted"] == 1
    row = await world.admin.fetchrow(
        "SELECT attrs::text AS a FROM sibyl.events WHERE tenant_id = $1", world.tenant_id
    )
    ref = json.loads(row["a"])["payload"]
    assert ref["truncated"] is True and ref["bytes_original"] > 262_144 and ref["bytes"] == 262_144
    assert "payload truncated" in " ".join(resp.json()["warnings"])


async def test_every_payload_row_has_its_blob(world: World) -> None:
    await world.post("/v1/otlp/traces", _chat())
    for ref in await world.rows(
        "SELECT uri, stored_bytes FROM sibyl.payload_refs WHERE tenant_id = $1", world.tenant_id
    ):
        info = await world.blob.head(ref["uri"])
        assert info is not None and info.size == ref["stored_bytes"]


async def test_ciphertext_is_bound_to_tenant_and_object(world: World) -> None:
    await world.post("/v1/otlp/traces", _chat())
    row = await _flushed_row(world)
    ref = await world.admin.fetchrow(
        "SELECT uri FROM sibyl.payload_refs WHERE id = $1", row["payload_ref_id"]
    )
    deks = world.services.service.deks  # type: ignore[union-attr]
    raw = await world.blob.get(ref["uri"])
    assert b"jane.doe" not in raw
    with pytest.raises(DecryptionError):
        await open_payload(
            world.blob, deks, world.tenant_id, ref["uri"], uuid4()
        )  # wrong object id
    tampered = raw[:-1] + bytes([raw[-1] ^ 1])
    await world.blob.put(
        ref["uri"], tampered, content_type="application/vnd.sibyl.sealed", if_absent=False
    )
    with pytest.raises(DecryptionError):
        await open_payload(world.blob, deks, world.tenant_id, ref["uri"], row["payload_ref_id"])
    with pytest.raises(SealedFormatError):
        unpack(b"nope")


async def test_crypto_shred_makes_objects_unreadable(world: World) -> None:
    await world.post("/v1/otlp/traces", _chat())
    row = await _flushed_row(world)
    ref = await world.admin.fetchrow(
        "SELECT uri FROM sibyl.payload_refs WHERE id = $1", row["payload_ref_id"]
    )
    deks = world.services.service.deks  # type: ignore[union-attr]
    assert await open_payload(world.blob, deks, world.tenant_id, ref["uri"], row["payload_ref_id"])
    async with world.admin.transaction():
        await world.admin.execute("SELECT sibyl.set_tenant($1)", world.tenant_id)
        await world.admin.execute(
            "SET LOCAL session_replication_role = replica"
        )  # no erasure_request row needed
        await world.admin.execute(
            "UPDATE sibyl.tenant_key SET state = 'shredded', wrapped_dek = NULL, shredded_at ="
            " now(),"
            " erasure_request_id = $2 WHERE tenant_id = $1 AND purpose = 'payload'",
            world.tenant_id,
            uuid4(),
        )
    deks.invalidate(world.tenant_id)
    with pytest.raises(DekUnavailable, match="shredded"):
        await open_payload(world.blob, deks, world.tenant_id, ref["uri"], row["payload_ref_id"])
    fresh = PgDekProvider(world.db, KEK)
    with pytest.raises(DekUnavailable):
        await fresh.by_version(world.tenant_id, "payload", 1)
    # New writes cannot be sealed either: the batch is refused as erasing, never stored in clear.
    count_sql = "SELECT count(*) FROM sibyl.payload_refs WHERE tenant_id = $1"
    before = await world.val(count_sql, world.tenant_id)
    blobs_before = await world.blob.list_prefix(f"tenant/{world.tenant_id}/")
    resp = await world.post("/v1/otlp/traces", _chat())
    assert resp.status_code == 429 and resp.headers["x-sibyl-backpressure"] == "tenant_erasing"
    assert await world.val(count_sql, world.tenant_id) == before
    assert await world.blob.list_prefix(f"tenant/{world.tenant_id}/") == blobs_before


async def test_dek_cache_rules(world: World) -> None:
    with pytest.raises(ValueError, match="60"):
        PgDekProvider(world.db, KEK, ttl_s=61)
    other = PgDekProvider(world.db, LocalKek("another-kek", generate_dek()))
    with pytest.raises(DekUnavailable, match="another KEK"):
        await other.active(world.tenant_id, "payload")
    clock = [0.0]
    provider = PgDekProvider(world.db, KEK, ttl_s=1, clock=lambda: clock[0])
    first = await provider.active(world.tenant_id, "payload")
    assert (await provider.active(world.tenant_id, "payload")) is first
    clock[0] = 2.0
    assert (await provider.active(world.tenant_id, "payload")) is not first
    provider.invalidate(world.tenant_id)
    assert not any(slot[0] == world.tenant_id for slot in provider._cache)
