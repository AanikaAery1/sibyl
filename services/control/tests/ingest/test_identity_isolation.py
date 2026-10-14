"""Identity resolution, auto-registration in its own short transaction (R61), agent narrowing
(R13) and tenant isolation (API.md §10.1)."""

from __future__ import annotations

import json
import uuid

from sibyl_control.ingest.ids import uuid7
from sibyl_control.ingest.normalise.identity import unclaimed_slug

from .conftest import FIXTURE_AGENT, World
from .otlp_build import chat_attrs, span, traces
from .test_replay import _batch, _feedback


async def test_unknown_agent_is_auto_registered_with_audit_and_discovery_event(
    world: World,
) -> None:
    tool_attrs = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "t",
        "sibyl.agent_id": "billing-bot",
    }
    resp = await world.post("/v1/otlp/traces", traces([span(tool_attrs, name="tool")]))
    assert resp.status_code == 200
    agent = await world.admin.fetchrow(
        "SELECT id, slug, is_provisional, lifecycle, fail_mode FROM sibyl.agent WHERE tenant_id"
        " = $1 AND slug = $2",
        world.tenant_id,
        unclaimed_slug("billing-bot"),
    )
    assert agent is not None and agent["is_provisional"] and agent["lifecycle"] == "discovered"
    assert agent["fail_mode"] == "open"  # copied from tenant.unknown_agent_fail_mode
    state = await world.val(
        "SELECT state FROM sibyl.routing_state WHERE tenant_id = $1 AND agent_id = $2",
        world.tenant_id,
        agent["id"],
    )
    assert state == "active"
    audit = await world.admin.fetchrow(
        "SELECT actor_type, actor_id, actor_key_id, detail FROM sibyl.audit_events"
        " WHERE tenant_id = $1 AND action = 'agent.discovered'",
        world.tenant_id,
    )
    detail = audit["detail"] if isinstance(audit["detail"], dict) else json.loads(audit["detail"])
    # G0-6/G0-11: the discovering API key is the actor, never ``system``.
    assert audit["actor_type"] == "api_key" and audit["actor_id"] is None
    assert audit["actor_key_id"] == world.keys["tenant"].id
    transition = await world.admin.fetchrow(
        "SELECT actor_kind, actor_key_id FROM sibyl.routing_transition WHERE tenant_id = $1"
        " AND agent_id = $2",
        world.tenant_id,
        agent["id"],
    )
    assert transition["actor_kind"] == "api_key"
    assert transition["actor_key_id"] == world.keys["tenant"].id
    assert detail["slug"] == agent["slug"] and detail["api_key_id"] == str(world.keys["tenant"].id)
    assert detail["discovered_via"] == "span_attr"  # D50: agent.discovered audit
    discovered = await world.admin.fetchrow(
        "SELECT attrs FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'agent.discovered'",
        world.tenant_id,
    )
    attrs = (
        discovered["attrs"]
        if isinstance(discovered["attrs"], dict)
        else json.loads(discovered["attrs"])
    )
    assert attrs["discovered_via"] == "span_attr" and attrs["resolved_agent_id"] == str(agent["id"])
    tool = await world.val(
        "SELECT agent_id FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'tool.call'",
        world.tenant_id,
    )
    assert tool == agent["id"]
    # Second batch: same identity, no second registration or audit row.
    await world.post("/v1/otlp/traces", traces([span(tool_attrs, name="tool")]))
    assert (
        await world.val(
            "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1 AND action ="
            " 'agent.discovered'",
            world.tenant_id,
        )
        == 1
    )


async def test_registered_slug_resolves_without_registration(world: World) -> None:
    attrs = chat_attrs(**{"sibyl.agent_id": "quote-worker"})
    await world.post("/v1/otlp/traces", traces([span(attrs)]))
    assert (
        await world.val("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", world.tenant_id)
        == 1
    )


async def test_bound_key_cannot_widen_by_header(world: World) -> None:
    other = str(uuid.uuid4())
    resp = await world.post(
        "/v1/events", _batch([_feedback(1)]), key="bound", headers={"x-sibyl-agent": other}
    )
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("/agent_not_permitted")
    denied = await world.val(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1 AND action = 'access.denied'",
        world.tenant_id,
    )
    assert denied == 1


async def test_bound_key_rejects_other_agents_per_event(world: World) -> None:
    mine = _feedback(1)
    theirs = _feedback(2) | {"agent_id": str(uuid.uuid4())}
    resp = await world.post("/v1/events", _batch([mine, theirs]), key="bound")
    body = resp.json()
    assert body["accepted"] == 1
    assert body["rejected"] == [
        {
            "index": 1,
            "event_id": theirs["event_id"],
            "reason": "agent_not_permitted",
            "detail": "agent is outside what the key may act as",
        }
    ]
    assert (
        await world.val("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", world.tenant_id)
        == 1
    )


async def test_bound_key_without_claims_acts_as_its_agent(world: World) -> None:
    resp = await world.post("/v1/otlp/traces", traces([span(chat_attrs())]), key="bound")
    assert resp.status_code == 200
    assert (
        await world.val(
            "SELECT agent_id FROM sibyl.call_merge c, LATERAL (SELECT"
            " (c.sdk_contribution->'event'->>'agent_id')::uuid AS agent_id) x WHERE c.tenant_id"
            " = $1",
            world.tenant_id,
        )
        == FIXTURE_AGENT
    )


async def test_header_narrows_a_tenant_key(world: World) -> None:
    resp = await world.post(
        "/v1/events",
        _batch([_feedback(1) | {"agent_id": str(uuid.uuid4())}]),
        headers={"x-sibyl-agent": "quote-worker"},
    )
    assert resp.json()["rejected"][0]["reason"] == "agent_not_permitted"
    resp = await world.post(
        "/v1/otlp/traces", traces([span(chat_attrs())]), headers={"x-sibyl-agent": "quote-worker"}
    )
    assert resp.json() == {}


async def test_tenant_id_on_the_wire_is_never_trusted(world_factory) -> None:
    a = await world_factory()
    b = await world_factory()
    event = _feedback(1) | {"tenant_id": str(b.tenant_id)}
    resp = await a.post("/v1/events", _batch([event]))
    assert resp.json()["accepted"] == 1
    assert (
        await a.val(
            "SELECT tenant_id FROM sibyl.events WHERE event_id = $1::uuid", event["event_id"]
        )
        == a.tenant_id
    )
    assert await b.val("SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", b.tenant_id) == 0


async def test_another_tenants_agent_id_is_unknown_here(world_factory) -> None:
    a = await world_factory()
    b = await world_factory()
    foreign = uuid7()
    await b.admin.execute(
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, fail_mode) VALUES ($1, $2,"
        " 'b-agent', 'B', 'chatbot', 'open')",
        b.tenant_id,
        foreign,
    )
    resp = await a.post(
        "/v1/events", _batch([_feedback(1) | {"agent_id": str(foreign)}]), key="bound"
    )
    assert resp.json()["rejected"][0]["reason"] == "agent_not_permitted"
    resp = await a.post("/v1/events", _batch([_feedback(2) | {"agent_id": str(foreign)}]))
    stored = await a.val(
        "SELECT agent_id FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'feedback'",
        a.tenant_id,
    )
    assert stored != foreign  # auto-registered as a provisional agent of tenant A instead


async def test_ingest_role_sees_only_its_tenant(world_factory) -> None:
    a = await world_factory()
    b = await world_factory()
    await a.post("/v1/events", _batch([_feedback(1)]))
    await b.post("/v1/events", _batch([_feedback(2)]))
    async with a.db.tenant_tx(a.tenant_id, readonly=True) as conn:
        seen = await conn.fetch("SELECT DISTINCT tenant_id FROM sibyl.events")
        payloads = await conn.fetch("SELECT DISTINCT tenant_id FROM sibyl.payload_refs")
    assert {r["tenant_id"] for r in seen} == {a.tenant_id}
    assert {r["tenant_id"] for r in payloads} == {a.tenant_id}
    a_blobs = await a.blob.list_prefix(f"tenant/{b.tenant_id}/")
    assert a_blobs == []
