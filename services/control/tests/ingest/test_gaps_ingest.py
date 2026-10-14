"""Lane GAPS: Action Gate outcome on tool calls (OTLP ``sibyl.action.*`` and sibyl-event) and
the discovery fields (``discovered_via``, ``first_trace_id``) stored on discovered agents."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sibyl_control.ingest.normalise.fields import rfc3339
from sibyl_control.ingest.normalise.identity import unclaimed_slug

from .conftest import FIXTURE_AGENT, World
from .otlp_build import span, traces

HELD = "0192767f-0000-7000-8000-0000000000a7"
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def _attrs(row: Any) -> dict[str, Any]:
    value = row["attrs"]
    return value if isinstance(value, dict) else json.loads(value)


def _tool(**extra: Any) -> dict[str, Any]:
    return {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "refund_payment",
        "sibyl.agent_id": str(FIXTURE_AGENT),
        **extra,
    }


async def _tool_rows(world: World) -> dict[str, dict[str, Any]]:
    rows = await world.rows(
        "SELECT attrs FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'tool.call'",
        world.tenant_id,
    )
    return {_attrs(r)["tool_name"]: _attrs(r) for r in rows}


async def test_otlp_tool_span_action_gate_outcome_is_mapped(world: World) -> None:
    spans = [
        span(
            _tool(
                **{
                    "gen_ai.tool.name": "approved_tool",
                    "sibyl.action.effect": "approved",
                    "sibyl.action.rule_id": "refunds.large",
                    "sibyl.action.held_action_id": HELD,
                }
            ),
            name="t1",
        ),
        span(
            _tool(
                **{
                    "gen_ai.tool.name": "blocked_tool",
                    "sibyl.action.effect": "block",
                    "sibyl.action.rule_id": "sibyl:tool_allowlist",
                }
            ),
            name="t2",
            error=True,
        ),
        span(
            _tool(
                **{
                    "gen_ai.tool.name": "odd_tool",
                    "sibyl.action.effect": "escalate",  # not an outcome: dropped
                    "sibyl.action.rule_id": "x" * 300,  # clipped to 128
                    "sibyl.action.held_action_id": "not-a-uuid",  # dropped
                }
            ),
            name="t3",
        ),
        span(_tool(**{"gen_ai.tool.name": "plain_tool"}), name="t4"),
    ]
    resp = await world.post("/v1/otlp/traces", traces(spans))
    assert resp.status_code == 200
    rows = await _tool_rows(world)
    approved = rows["approved_tool"]
    assert approved["action_effect"] == "approved"
    assert approved["action_rule_id"] == "refunds.large"
    assert approved["held_action_id"] == HELD
    blocked = rows["blocked_tool"]
    assert blocked["action_effect"] == "block" and "held_action_id" not in blocked
    assert blocked["action_rule_id"] == "sibyl:tool_allowlist"
    odd = rows["odd_tool"]
    assert "action_effect" not in odd and "held_action_id" not in odd
    assert odd["action_rule_id"] == "x" * 128
    assert not {"action_effect", "action_rule_id", "held_action_id"} & set(rows["plain_tool"])
    warnings = await world.val(
        "SELECT count(*) FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'tool.call'"
        " AND attrs::text LIKE '%unknown sibyl%'",
        world.tenant_id,
    )
    assert warnings == 0


def _wire_tool(effect: str) -> dict[str, Any]:
    return {
        "schema": "sibyl-event/1",
        "event_id": "019276a3-0002-7000-8000-0000000000c1",
        "type": "tool.call",
        "tenant_id": None,
        "agent_id": str(FIXTURE_AGENT),
        "task_id": None,
        "call_id": None,
        "trace_id": TRACE,
        "span_id": "7a1b2c3d4e5f6072",
        "ts": rfc3339(datetime.now(UTC) - timedelta(minutes=1)),
        "source": "sdk",
        "emitter_id": "sdk:gaps:1",
        "seq": 1,
        "capture_mode": "metadata",
        "redaction_profile": {
            "id": "secrets_only",
            "version": 1,
            "rules_fired": [],
            "secrets_scrubbed": 0,
        },
        "policy_state": {"state": "fresh", "policy_version": 1, "fail_mode": "open"},
        "attrs": {
            "tool_name": "wire_tool",
            "tool_type": "function",
            "status": "error",
            "latency_ms": 3.0,
            "action_effect": effect,
            "action_rule_id": "refunds.large",
            "held_action_id": HELD,
        },
    }


async def test_sibyl_event_tool_call_carries_action_gate_outcome(world: World) -> None:
    event = _wire_tool("denied")
    event["tenant_id"] = str(world.tenant_id)
    body = json.dumps({"schema": "sibyl-event/1", "events": [event]}).encode()
    resp = await world.post("/v1/events", body, headers={"X-Sibyl-Schema": "sibyl-event/1"})
    assert resp.status_code == 202, resp.text
    assert resp.json()["accepted"] == 1
    stored = (await _tool_rows(world))["wire_tool"]
    assert stored["action_effect"] == "denied" and stored["held_action_id"] == HELD
    assert stored["action_rule_id"] == "refunds.large"


async def test_sibyl_event_unknown_action_effect_is_rejected(world: World) -> None:
    event = _wire_tool("escalate")
    event["tenant_id"] = str(world.tenant_id)
    body = json.dumps({"schema": "sibyl-event/1", "events": [event]}).encode()
    resp = await world.post("/v1/events", body, headers={"X-Sibyl-Schema": "sibyl-event/1"})
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 0


async def test_discovered_agent_records_how_and_first_trace(world: World) -> None:
    run = {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.agent.name": "supervisor",
        "sibyl.agent_id": str(FIXTURE_AGENT),
        "sibyl.handoff_to_agent": "researcher",
    }
    other = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "t",
        "sibyl.agent_id": "brand-new-agent",
    }
    resp = await world.post(
        "/v1/otlp/traces",
        traces([span(run, name="invoke_agent", trace=TRACE), span(other, name="t")]),
    )
    assert resp.status_code == 200
    rows = {
        r["slug"]: r
        for r in await world.rows(
            "SELECT slug, discovered_via, first_trace_id, confirmed_at, is_provisional"
            " FROM sibyl.agent WHERE tenant_id = $1 AND lifecycle = 'discovered'",
            world.tenant_id,
        )
    }
    handoff = rows[unclaimed_slug("researcher")]
    assert handoff["discovered_via"] == "run_tree"
    assert handoff["first_trace_id"].hex == TRACE
    assert handoff["confirmed_at"] is None and handoff["is_provisional"]
    claimed = rows[unclaimed_slug("brand-new-agent")]
    assert claimed["discovered_via"] == "span_attr" and claimed["first_trace_id"] is not None
    [event] = await world.rows(
        "SELECT attrs FROM sibyl.events WHERE tenant_id = $1 AND event_type = 'agent.discovered'"
        " AND agent_id = (SELECT id FROM sibyl.agent WHERE tenant_id = $1 AND slug = $2)",
        world.tenant_id,
        unclaimed_slug("researcher"),
    )
    assert _attrs(event)["first_trace_id"] == TRACE
