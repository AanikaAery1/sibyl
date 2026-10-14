"""Wave 3 PLUG (D50): run-tree attrs, model identity (system_fingerprint), refusals and
proposed tool calls through ingest; auto-discovery of handoff targets as `discovered`
agents (audit `agent.discovered`), never routed until confirmed; tenant isolation (RLS)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
import pytest
from sibyl_control.ingest.flusher import flush_tenant
from sibyl_control.ingest.normalise.identity import unclaimed_slug

from .conftest import FIXTURE_AGENT, World
from .otlp_build import chat_attrs, span, traces

PARENT = "0192767f-0000-7000-8000-0000000000f1"


def _attrs(row: Any) -> dict[str, Any]:
    value = row["attrs"]
    return value if isinstance(value, dict) else json.loads(value)


async def _events(world: World, etype: str) -> list[Any]:
    return await world.rows(
        "SELECT * FROM sibyl.events WHERE tenant_id = $1 AND event_type = $2",
        world.tenant_id,
        etype,
    )


def invoke(**extra: Any) -> dict[str, Any]:
    return {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.agent.name": "supervisor",
        "sibyl.agent_id": str(FIXTURE_AGENT),
        "sibyl.parent_run_id": PARENT,
        "sibyl.step_index": 2,
        "sibyl.handoff_to_agent": "researcher",
        **extra,
    }


async def test_run_tree_attrs_are_stored_and_handoff_target_is_discovered(world: World) -> None:
    tool = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "transfer_to_researcher",
        "sibyl.agent_id": str(FIXTURE_AGENT),
        "sibyl.parent_run_id": PARENT,
        "sibyl.step_index": 0,
        "sibyl.handoff_to_agent": "researcher",
    }
    resp = await world.post(
        "/v1/otlp/traces", traces([span(invoke(), name="invoke_agent"), span(tool, name="t")])
    )
    assert resp.status_code == 200
    [run] = await _events(world, "agent.invoke")
    a = _attrs(run)
    assert a["parent_run_id"] == PARENT and a["step_index"] == 2
    assert a["handoff_to_agent"] == "researcher"
    assert run["agent_id"] == FIXTURE_AGENT  # the events keep their own identity
    [call] = await _events(world, "tool.call")
    assert _attrs(call)["handoff_to_agent"] == "researcher" and _attrs(call)["step_index"] == 0
    found = await world.admin.fetchrow(
        "SELECT id, name, lifecycle, is_provisional FROM sibyl.agent"
        " WHERE tenant_id = $1 AND slug = $2",
        world.tenant_id,
        unclaimed_slug("researcher"),
    )
    assert found["lifecycle"] == "discovered" and found["is_provisional"]
    assert found["name"] == "researcher"
    audit = await world.admin.fetchrow(
        "SELECT actor_type, actor_key_id, detail FROM sibyl.audit_events"
        " WHERE tenant_id = $1 AND action = 'agent.discovered'",
        world.tenant_id,
    )
    detail = audit["detail"] if isinstance(audit["detail"], dict) else json.loads(audit["detail"])
    assert detail["discovered_via"] == "run_tree" and audit["actor_type"] == "api_key"
    [event] = await _events(world, "agent.discovered")
    assert _attrs(event)["discovered_via"] == "run_tree"
    assert event["agent_id"] == found["id"]
    # Again: the discovered agent is preloaded by its slug; nothing new is registered.
    await world.post("/v1/otlp/traces", traces([span(invoke(), name="invoke_agent")]))
    count = await world.val(
        "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'agent.discovered'",
        world.tenant_id,
    )
    assert count == 1


async def test_handoff_to_a_registered_agent_registers_nothing(world: World) -> None:
    await world.post(
        "/v1/otlp/traces",
        traces([span(invoke(**{"sibyl.handoff_to_agent": "quote-worker"}), name="invoke_agent")]),
    )
    assert (
        await world.val(
            "SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1 AND lifecycle = 'discovered'"
            " AND is_provisional",
            world.tenant_id,
        )
        == 0
    )


async def test_bound_key_handoff_discovers_without_changing_event_identity(world: World) -> None:
    resp = await world.post(
        "/v1/otlp/traces",
        traces([span(invoke(**{"sibyl.handoff_to_agent": "auditor"}), name="invoke_agent")]),
        key="bound",
    )
    assert resp.status_code == 200
    [run] = await _events(world, "agent.invoke")
    assert run["agent_id"] == FIXTURE_AGENT
    assert (
        await world.val(
            "SELECT lifecycle FROM sibyl.agent WHERE tenant_id = $1 AND slug = $2",
            world.tenant_id,
            unclaimed_slug("auditor"),
        )
        == "discovered"
    )


async def test_model_identity_refusal_and_tool_calls_reach_the_gen_ai_row(world: World) -> None:
    sdk = span(
        chat_attrs(
            **{
                "sibyl.source": "sdk",
                "sibyl.agent_id": str(FIXTURE_AGENT),
                "sibyl.system_fingerprint": "fp_" + "a" * 200,
                "sibyl.refusal": True,
                "gen_ai.response.finish_reasons": ["stop"],
                "sibyl.tool_calls.names": ["lookup", "quote"],
                "sibyl.tool_calls.ids": ["call_1"],
                "sibyl.parent_run_id": PARENT,
                "sibyl.step_index": 4,
            }
        )
    )
    other = span(
        chat_attrs(
            **{
                "sibyl.agent_id": str(FIXTURE_AGENT),
                "gen_ai.openai.response.system_fingerprint": "fp_otel",
            }
        )
    )
    assert (await world.post("/v1/otlp/traces", traces([sdk, other]))).status_code == 200
    later = datetime.now(UTC) + timedelta(hours=1)
    await flush_tenant(world.db, world.tenant_id, world.services.cfg, now=later)
    rows = [_attrs(r) for r in await _events(world, "gen_ai.request")]
    mine = next(a for a in rows if a.get("parent_run_id") == PARENT)
    assert mine["system_fingerprint"] == ("fp_" + "a" * 200)[:128]
    assert mine["finish_reasons"] == ["stop", "refusal"]
    assert mine["tool_calls_requested"] == [{"name": "lookup", "id": "call_1"}, {"name": "quote"}]
    assert mine["step_index"] == 4
    otel = next(a for a in rows if a is not mine)
    assert otel["system_fingerprint"] == "fp_otel"


async def test_discovered_agents_are_never_routed_until_confirmed(world: World) -> None:
    await world.post("/v1/otlp/traces", traces([span(invoke(), name="invoke_agent")]))
    agent_id = await world.val(
        "SELECT id FROM sibyl.agent WHERE tenant_id = $1 AND slug = $2",
        world.tenant_id,
        unclaimed_slug("researcher"),
    )

    async def degrade(key: str) -> Any:
        async with world.db.tenant_tx(world.tenant_id) as conn:
            return await conn.fetchrow(
                "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'degraded', NULL,"
                " 'rule', 'rule', NULL, NULL, '{}', '{}', NULL, NULL, NULL, NULL, NULL, NULL,"
                " $3, 'route.changed', NULL, NULL, NULL, NULL)",
                world.tenant_id,
                agent_id,
                key,
            )

    with pytest.raises(asyncpg.PostgresError) as info:
        await degrade("plug-degrade-1")
    assert info.value.sqlstate == "SB051" and "agent_unconfirmed" in str(info.value)
    await world.admin.execute(
        "UPDATE sibyl.agent SET is_provisional = false WHERE tenant_id = $1 AND id = $2",
        world.tenant_id,
        agent_id,
    )
    try:
        await degrade("plug-degrade-2")
    except asyncpg.PostgresError as exc:  # any other refusal is not the discovery guard
        assert exc.sqlstate != "SB051"


async def test_discovered_agents_are_tenant_isolated(world_factory: Any) -> None:
    one: World = await world_factory()
    two: World = await world_factory()
    await one.post("/v1/otlp/traces", traces([span(invoke(), name="invoke_agent")]))
    seen = await two.val(
        "SELECT count(*) FROM sibyl.agent WHERE slug = $1", unclaimed_slug("researcher")
    )
    async with two.db.tenant_tx(two.tenant_id) as conn:
        visible = await conn.fetchval(
            "SELECT count(*) FROM sibyl.agent WHERE slug = $1", unclaimed_slug("researcher")
        )
    assert visible == 0
    assert seen >= 1  # the admin connection sees the other tenant's row; RLS hides it
