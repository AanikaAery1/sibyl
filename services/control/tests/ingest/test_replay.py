"""Three-layer idempotency: batch replay via ``ingest_batch_seen``, deterministic span event ids,
and ``ON CONFLICT DO NOTHING`` on events."""

from __future__ import annotations

import json
import uuid

from sibyl_control.ingest.ids import uuid7

from .conftest import FIXTURE_AGENT, World
from .otlp_build import span, traces


def _feedback(i: int) -> dict:
    return {
        "schema": "sibyl-event/1",
        "event_id": str(uuid7()),
        "type": "feedback",
        "tenant_id": str(uuid.uuid4()),
        "agent_id": str(FIXTURE_AGENT),
        "ts": "2026-10-10T09:00:00.000000Z",
        "source": "sdk",
        "emitter_id": "sdk:test:1",
        "seq": i,
        "capture_mode": "full",
        "redaction_profile": {"id": "secrets_only", "version": 1, "secrets_scrubbed": 0},
        "policy_state": {"state": "fresh"},
        "attrs": {
            "feedback_id": str(uuid7()),
            "target": {"kind": "trace", "id": "t"},
            "score": 1,
            "scale": "thumbs",
            "rater": "end_user",
        },
    }


def _batch(events: list[dict]) -> bytes:
    return json.dumps({"schema": "sibyl-event/1", "events": events}).encode()


async def _counts(world: World) -> tuple[int, int, int]:
    t = world.tenant_id
    return (
        await world.val("SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", t),
        await world.val("SELECT count(*) FROM sibyl.payload_refs WHERE tenant_id = $1", t),
        await world.val("SELECT count(*) FROM sibyl.ingest_batch_seen WHERE tenant_id = $1", t),
    )


async def test_batch_replay_returns_the_cached_response_and_writes_nothing(world: World) -> None:
    batch_id = str(uuid7())
    events = [_feedback(i) for i in range(3)] + [{"schema": "sibyl-event/1", "type": "nope"}]
    first = await world.post("/v1/events", _batch(events), headers={"x-sibyl-batch-id": batch_id})
    assert first.status_code == 202
    body = first.json()
    assert (body["accepted"], len(body["rejected"]), body["replayed"]) == (3, 1, False)
    assert body["batch_id"] == batch_id
    before = await _counts(world)
    second = await world.post("/v1/events", _batch(events), headers={"x-sibyl-batch-id": batch_id})
    assert second.status_code == 202
    assert second.headers["x-sibyl-replayed"] == "true"
    replayed = second.json()
    assert replayed["replayed"] is True
    assert {k: v for k, v in replayed.items() if k != "replayed"} == {
        k: v for k, v in body.items() if k != "replayed"
    }
    assert await _counts(world) == before
    stored = await world.admin.fetchrow(
        "SELECT jsonb_typeof(response_body) AS t, (response_body->>'accepted')::int AS n"
        " FROM sibyl.ingest_batch_seen WHERE tenant_id = $1",
        world.tenant_id,
    )
    assert (stored["t"], stored["n"]) == ("object", 3)  # a jsonb object, not a string


async def test_otlp_replay_without_batch_id_dedupes_by_event_id(world: World) -> None:
    body = traces(
        [span({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "t"}, name="tool")]
    )
    for _ in range(2):
        assert (await world.post("/v1/otlp/traces", body)).status_code == 200
    count = await world.val(
        "SELECT count(*) FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'tool.call'",
        world.tenant_id,
    )
    assert count == 1


async def test_otlp_batch_replay_keeps_partial_success(world: World) -> None:
    batch_id = str(uuid7())
    body = traces([span({"gen_ai.operation.name": "chat"})])
    first = await world.post("/v1/otlp/traces", body, headers={"x-sibyl-batch-id": batch_id})
    second = await world.post("/v1/otlp/traces", body, headers={"x-sibyl-batch-id": batch_id})
    assert first.json() == second.json()
    assert second.headers["x-sibyl-replayed"] == "true"
    assert (
        await world.val(
            "SELECT count(*) FROM sibyl.events_rejected WHERE tenant_id = $1", world.tenant_id
        )
        == 1
    )


async def test_same_event_twice_in_one_batch_is_stored_once(world: World) -> None:
    event = _feedback(1)
    resp = await world.post("/v1/events", _batch([event, event]))
    assert resp.json()["accepted"] == 2
    assert (
        await world.val("SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", world.tenant_id)
        == 1
    )


async def test_batch_id_must_be_uuidv7(world: World) -> None:
    resp = await world.post(
        "/v1/events", _batch([_feedback(1)]), headers={"x-sibyl-batch-id": str(uuid.uuid4())}
    )
    assert resp.status_code == 422


async def test_replay_is_scoped_to_the_tenant(world_factory) -> None:
    a = await world_factory()
    b = await world_factory()
    batch_id = str(uuid7())
    await a.post("/v1/events", _batch([_feedback(1)]), headers={"x-sibyl-batch-id": batch_id})
    resp = await b.post(
        "/v1/events", _batch([_feedback(2)]), headers={"x-sibyl-batch-id": batch_id}
    )
    assert resp.json()["replayed"] is False
    assert await b.val("SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", b.tenant_id) == 1
