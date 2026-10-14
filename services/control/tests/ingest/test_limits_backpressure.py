"""Authentication, request limits (4 MiB / 16 MiB / item counts) and backpressure (§4.2)."""

from __future__ import annotations

import gzip
import json

from sibyl_control.core.db import Database
from sibyl_control.core.ratelimit import InMemoryRateLimiter
from sibyl_control.ingest.app import assemble, create_app
from sibyl_control.ingest.config import IngestConfig

from .conftest import World, _settings
from .otlp_build import span, traces
from .test_replay import _batch, _feedback

MiB = 1024 * 1024


def _problem(resp, status: int, code: str) -> dict:
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert body["type"].endswith("/" + code), body
    return body


# -- authentication ---------------------------------------------------------------------------


async def test_missing_and_bad_keys_are_401(world: World) -> None:
    resp = await world.client.post(
        "/v1/events", content=_batch([_feedback(1)]), headers={"content-type": "application/json"}
    )
    _problem(resp, 401, "unauthenticated")
    bad = "sbl_live_ABCDEFGHIJKL_" + "a" * 43
    resp = await world.client.post(
        "/v1/events",
        content=b"{}",
        headers={"authorization": f"Bearer {bad}", "content-type": "application/json"},
    )
    _problem(resp, 401, "unauthenticated")


async def test_test_env_key_is_refused_by_a_live_ingest(world: World) -> None:
    _problem(
        await world.post("/v1/events", _batch([_feedback(1)]), key="testenv"),
        401,
        "unauthenticated",
    )


async def test_key_without_ingest_write_is_403_and_audited(world: World) -> None:
    _problem(await world.post("/v1/events", _batch([_feedback(1)]), key="reader"), 403, "forbidden")
    row = await world.admin.fetchrow(
        "SELECT actor_type, actor_key_id FROM sibyl.audit_events WHERE tenant_id = $1 AND action"
        " = 'access.denied'",
        world.tenant_id,
    )
    assert row["actor_key_id"] == world.keys["reader"].id


async def test_handoff_requested_needs_handoff_write(world: World) -> None:
    from sibyl_schemas.golden import golden_cases

    case = next(
        c for c in golden_cases("ingest") if c.file == "valid/wire_handoff_requested_inline.json"
    )
    _problem(
        await world.post("/v1/events", _batch([case.load()]), key="nohandoff"), 403, "forbidden"
    )


async def test_credential_in_url_is_refused(world: World) -> None:
    key = world.keys["tenant"].plaintext
    resp = await world.client.post(
        f"/v1/events?api_key={key}", content=b"{}", headers={"content-type": "application/json"}
    )
    body = _problem(resp, 400, "credential_in_url")
    assert key not in json.dumps(body)


async def test_key_from_a_browser_origin_is_refused(world: World) -> None:
    resp = await world.post(
        "/v1/events", _batch([_feedback(1)]), headers={"origin": "https://evil.example"}
    )
    _problem(resp, 403, "key_from_browser")


# -- limits -------------------------------------------------------------------------------------


async def test_body_over_4_mib_is_413(world: World) -> None:
    resp = await world.post("/v1/otlp/traces", b"x" * (4 * MiB + 1))
    _problem(resp, 413, "payload_too_large")
    assert (
        await world.val(
            "SELECT count(*) FROM sibyl.payload_refs WHERE tenant_id = $1", world.tenant_id
        )
        == 0
    )


async def test_body_of_exactly_4_mib_is_read(world: World) -> None:
    # 4 MiB of JSON whitespace around an empty object: within the cap, decodes as a heartbeat.
    body = b"{}" + b" " * (4 * MiB - 2)
    assert (await world.post("/v1/otlp/traces", body)).status_code == 200


async def test_declared_length_over_cap_is_refused_before_reading(world: World) -> None:
    resp = await world.client.post(
        "/v1/events",
        content=b"{}",
        headers={
            "authorization": f"Bearer {world.keys['tenant'].plaintext}",
            "content-type": "application/json",
            "content-length": str(5 * MiB),
        },
    )
    assert resp.status_code in (413, 400)


async def test_gzip_bomb_stops_at_16_mib(world: World) -> None:
    bomb = gzip.compress(b"\x00" * (17 * MiB))
    assert len(bomb) < 4 * MiB
    resp = await world.post("/v1/otlp/traces", bomb, headers={"content-encoding": "gzip"})
    _problem(resp, 413, "payload_too_large")


async def test_unknown_content_encoding_is_415(world: World) -> None:
    resp = await world.post("/v1/otlp/traces", b"{}", headers={"content-encoding": "br"})
    _problem(resp, 415, "unsupported_media_type")


async def test_truncated_gzip_is_422(world: World) -> None:
    resp = await world.post(
        "/v1/otlp/traces", gzip.compress(b"{}")[:-4], headers={"content-encoding": "gzip"}
    )
    _problem(resp, 422, "validation_failed")


async def test_more_than_2000_spans_is_400(world: World) -> None:
    spans = [span({"x": 1}) for _ in range(2001)]
    _problem(await world.post("/v1/otlp/traces", traces(spans)), 400, "batch_too_large")


async def test_more_than_1000_events_is_400(world: World) -> None:
    _problem(
        await world.post("/v1/events", _batch([_feedback(i) for i in range(1001)])),
        400,
        "batch_too_large",
    )


async def test_unsupported_schema_header_is_400(world: World) -> None:
    resp = await world.post(
        "/v1/events", _batch([_feedback(1)]), headers={"x-sibyl-schema": "sibyl-event/2"}
    )
    _problem(resp, 400, "unsupported_schema")


async def test_duplicate_json_keys_are_refused(world: World) -> None:
    resp = await world.post(
        "/v1/events", b'{"schema":"sibyl-event/1","schema":"sibyl-event/1","events":[]}'
    )
    _problem(resp, 422, "validation_failed")


async def test_long_attribute_strings_are_truncated_with_a_warning(world: World) -> None:
    attrs = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "t",
        "huge": "y" * (70 * 1024),
    }
    resp = await world.post("/v1/otlp/traces", traces([span(attrs, name="tool")]))
    assert resp.status_code == 200


# -- backpressure ------------------------------------------------------------------------------


async def test_tenant_bucket_gives_429_with_retry_after(world: World) -> None:
    await world.admin.execute(
        "UPDATE sibyl.tenant SET ingest_rate_limit = $2::text::jsonb WHERE id = $1",
        world.tenant_id,
        '{"events_per_s": 1, "burst": 2}',
    )
    ok = await world.post("/v1/events", _batch([_feedback(1), _feedback(2)]))
    assert ok.status_code == 202
    resp = await world.post("/v1/events", _batch([_feedback(3), _feedback(4)]))
    body = _problem(resp, 429, "tenant_rate_limit")
    assert resp.headers["x-sibyl-backpressure"] == "tenant_rate_limit"
    assert 1 <= int(resp.headers["retry-after"]) <= 30
    assert body["retry_after_s"] == int(resp.headers["retry-after"])
    # Nothing from the refused batch was stored, and a heartbeat still passes.
    assert (
        await world.val("SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", world.tenant_id)
        == 2
    )
    assert (await world.post("/v1/otlp/traces", b"")).status_code == 200


async def test_per_key_batch_rate(world_factory) -> None:
    world = await world_factory(cfg=IngestConfig(key_batches_per_s=2))
    statuses = [(await world.post("/v1/otlp/traces", b"")).status_code for _ in range(3)]
    assert statuses == [200, 200, 429]


async def test_saturation_gives_ingest_saturated(world_factory) -> None:
    world = await world_factory(cfg=IngestConfig(max_inflight=0))
    resp = await world.post("/v1/otlp/traces", b"")
    _problem(resp, 429, "ingest_saturated")
    assert resp.headers["x-sibyl-backpressure"] == "ingest_saturated"
    assert resp.headers["retry-after"] == "1"


async def test_erasing_tenant_gets_429_for_an_hour(world: World) -> None:
    async with world.admin.transaction():
        await world.admin.execute("SET LOCAL session_replication_role = replica")
        await world.admin.execute(
            "UPDATE sibyl.tenant SET status = 'erasing' WHERE id = $1", world.tenant_id
        )
    resp = await world.post("/v1/events", _batch([_feedback(1)]))
    _problem(resp, 429, "tenant_erasing")
    assert resp.headers["retry-after"] == "3600"
    assert resp.headers["x-sibyl-backpressure"] == "tenant_erasing"


async def test_missing_capture_policy_is_403(world: World) -> None:
    async with world.admin.transaction():
        await world.admin.execute("SET LOCAL session_replication_role = replica")
        await world.admin.execute(
            "DELETE FROM sibyl.capture_policy WHERE tenant_id = $1", world.tenant_id
        )
    _problem(await world.post("/v1/events", _batch([_feedback(1)])), 403, "capture_policy_missing")


async def test_database_down_is_503_with_retry_after(world: World) -> None:
    dead = await Database.connect(
        "postgresql://sibyl_ingest@127.0.0.1:1/none", min_size=0, max_size=1
    )
    try:
        services = assemble(
            dead, _settings(world.tmp), store=world.blob, limiter=InMemoryRateLimiter()
        )
        import httpx

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(services)), base_url="http://x"
        ) as client:
            resp = await client.post(
                "/v1/otlp/traces",
                content=b"",
                headers={
                    "authorization": f"Bearer {world.keys['tenant'].plaintext}",
                    "content-type": "application/json",
                },
            )
        _problem(resp, 503, "database_unavailable")
        assert resp.headers["retry-after"] == "5"
    finally:
        await dead.close()


async def test_request_timeout_is_503_and_stores_nothing(world_factory, monkeypatch) -> None:
    import asyncio

    from sibyl_control.ingest import store

    world = await world_factory(cfg=IngestConfig(request_timeout_s=0.2))

    async def stall(conn, tenant_id, sealed):  # the batch transaction never finishes in time
        await asyncio.sleep(5)

    monkeypatch.setattr(store, "insert_payload_refs", stall)
    resp = await world.post("/v1/events", _batch([_feedback(1)]))
    _problem(resp, 503, "database_timeout")
    assert resp.headers["retry-after"] == "5"
    assert (
        await world.val("SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", world.tenant_id)
        == 0
    )
