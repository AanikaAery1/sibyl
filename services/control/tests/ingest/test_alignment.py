"""Cross-lane alignment: SDK (lane K) OTLP/JSON attributes, nil-UUID identities, checkpoints
over 64 KiB, and gateway-minted UUIDv8 agents (lane G)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sibyl_control.core.crypto.sealed import open_payload
from sibyl_control.ingest.flusher import flush_tenant
from sibyl_control.ingest.ids import uuid7

from .conftest import FIXTURE_AGENT, World
from .otlp_build import chat_attrs, span, traces
from .test_replay import _batch, _feedback

NIL = "00000000-0000-0000-0000-000000000000"
H = "ab" * 32


def _attrs(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else json.loads(value)


async def test_invoke_agent_span_with_sdk_attributes(world: World) -> None:
    parent = str(uuid7())
    attrs = {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.agent.name": "quote-worker",
        "sibyl.agent_id": str(FIXTURE_AGENT),
        "sibyl.parent_task_id": parent,
        "sibyl.invoke.status": "cancelled",
        "sibyl.invoke.cancel_reason": "user_abort",
        "sibyl.invoke.steps": 4,
        "sibyl.invoke.tool_calls": 2,
        "sibyl.invoke.model_calls": 3,
    }
    resp = await world.post("/v1/otlp/traces", traces([span(attrs, name="invoke_agent quote")]))
    assert resp.status_code == 200 and resp.json() == {}
    row = await world.admin.fetchrow(
        "SELECT status, attrs::text AS a FROM sibyl.events WHERE tenant_id = $1 AND event_type ="
        " 'agent.invoke'",
        world.tenant_id,
    )
    a = _attrs(row["a"])
    assert row["status"] == "cancelled"
    assert (a["phase"], a["parent_task_id"], a["error_type"]) == ("end", parent, "user_abort")
    assert (a["steps"], a["tool_calls"], a["model_calls"]) == (4, 2, 3)


async def test_sdk_content_hashes_and_output_chars(world: World) -> None:
    attrs = chat_attrs(
        **{
            "sibyl.agent_id": str(FIXTURE_AGENT),
            "sibyl.capture.mode": "metadata",
            "sibyl.content_hash.input": H,
            "sibyl.content_hash.output": H,
            "sibyl.content_hash.args": H,
            "sibyl.content_hash.result": H,
            "sibyl.output_chars": 42,
            "sibyl.redaction.emitter_profile_hash": "cd" * 32,
        }
    )
    resp = await world.post("/v1/otlp/traces", traces([span(attrs)]))
    assert resp.status_code == 200
    contribution = await world.val(
        "SELECT sdk_contribution::text FROM sibyl.call_merge WHERE tenant_id = $1", world.tenant_id
    )
    event = json.loads(contribution)["event"]
    assert event["attrs"]["content_hashes"] == {"input": H, "output": H}
    assert event["attrs"]["output_chars"] == 42
    assert event["redaction_profile"]["emitter_profile_hash"] == "cd" * 32
    assert not any("unknown sibyl" in w for w in event["ingest"].get("warnings", []))
    await flush_tenant(
        world.db, world.tenant_id, world.services.cfg, now=datetime.now(UTC) + timedelta(minutes=1)
    )
    stored = await world.val(
        "SELECT attrs::text FROM sibyl.events WHERE tenant_id = $1", world.tenant_id
    )
    assert json.loads(stored)["content_hashes"] == {"input_sha256": H, "output_sha256": H}


async def test_nil_agent_id_resolves_from_the_key(world: World) -> None:
    resp = await world.post(
        "/v1/events", _batch([_feedback(1) | {"agent_id": NIL, "tenant_id": NIL}]), key="bound"
    )
    assert resp.json()["accepted"] == 1
    assert (
        await world.val("SELECT agent_id FROM sibyl.events WHERE tenant_id = $1", world.tenant_id)
        == FIXTURE_AGENT
    )


async def test_nil_agent_id_resolves_from_the_header(world: World) -> None:
    resp = await world.post(
        "/v1/events",
        _batch([_feedback(1) | {"agent_id": NIL}]),
        headers={"x-sibyl-agent": "quote-worker"},
    )
    assert resp.json()["accepted"] == 1
    assert (
        await world.val("SELECT agent_id FROM sibyl.events WHERE tenant_id = $1", world.tenant_id)
        == FIXTURE_AGENT
    )


async def test_nil_otlp_agent_claim_resolves_from_the_key(world: World) -> None:
    attrs = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "t",
        "sibyl.agent_id": NIL,
    }
    resp = await world.post("/v1/otlp/traces", traces([span(attrs, name="tool")]), key="bound")
    assert resp.json() == {}
    assert (
        await world.val("SELECT agent_id FROM sibyl.events WHERE tenant_id = $1", world.tenant_id)
        == FIXTURE_AGENT
    )


async def test_checkpoint_over_64_kib_goes_to_blob_storage(world: World) -> None:
    checkpoint_id, task_id = str(uuid7()), str(uuid7())
    state = {"rows": ["r" * 100] * 1000}  # ~100 KB of state
    doc = {
        "schema": "sibyl-checkpoint/1",
        "checkpoint_id": checkpoint_id,
        "state": state,
        "goal": "g",
    }
    event = _feedback(1) | {"type": "checkpoint", "task_id": task_id}
    event["attrs"] = {
        "checkpoint_id": checkpoint_id,
        "seq": 1,
        "step_index": 0,
        "state_bytes": 101_000,
        "completed_count": 0,
        "pending_count": 1,
        "payload_inline": {
            "encoding": "utf8",
            "data": json.dumps(doc),
            "content_type": "application/vnd.sibyl.checkpoint+json",
            "parts": ["state"],
        },
    }
    resp = await world.post("/v1/events", _batch([event]))
    assert resp.json()["accepted"] == 1, resp.json()
    row = await world.admin.fetchrow(
        "SELECT state, state_ref_id, state_bytes FROM sibyl.checkpoint WHERE tenant_id = $1",
        world.tenant_id,
    )
    assert row["state"] is None and row["state_ref_id"] is not None and row["state_bytes"] > 65_536
    attrs = _attrs(
        await world.val(
            "SELECT attrs::text FROM sibyl.events WHERE tenant_id = $1", world.tenant_id
        )
    )
    assert attrs["state_ref"]["ref"].startswith(f"blob://{world.tenant_id}/")
    ref = await world.admin.fetchrow(
        "SELECT uri, kind FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2",
        world.tenant_id,
        row["state_ref_id"],
    )
    assert ref["kind"] == "checkpoint_state"
    plain = await open_payload(
        world.blob, world.services.service.deks, world.tenant_id, ref["uri"], row["state_ref_id"]
    )  # type: ignore[union-attr]
    assert json.loads(plain) == state


def _uuid8(seed: int) -> uuid.UUID:
    raw = bytearray(seed.to_bytes(16, "big"))
    raw[6] = 0x80 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return uuid.UUID(bytes=bytes(raw))


async def test_gateway_uuidv8_agent_is_registered_under_its_id(world: World) -> None:
    minted = _uuid8(0xC0FFEE)
    assert minted.version == 8
    discovered = _feedback(1) | {
        "type": "agent.discovered",
        "agent_id": str(minted),
        "source": "gateway",
    }
    discovered["attrs"] = {
        "discovered_via": "gateway_header",
        "candidate": "billing-bot",
        "candidate_hash": "0123456789abcdef",
        "resolved_agent_id": str(minted),
        "fail_mode_applied": "open",
    }
    resp = await world.post("/v1/events", _batch([discovered]))
    assert resp.json()["accepted"] == 1, resp.json()
    agent = await world.admin.fetchrow(
        "SELECT id, is_provisional FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
        world.tenant_id,
        minted,
    )
    assert agent is not None and agent["is_provisional"]
    count = await world.val(
        "SELECT count(*) FROM sibyl.events WHERE tenant_id = $1 AND event_type ="
        " 'agent.discovered'",
        world.tenant_id,
    )
    assert count == 1  # the gateway's event; ingest does not announce the same agent twice
    resp = await world.post("/v1/events", _batch([_feedback(2) | {"agent_id": str(minted)}]))
    assert resp.json()["accepted"] == 1
    assert (
        await world.val("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", world.tenant_id)
        == 2
    )
