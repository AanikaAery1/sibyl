"""Runs (D50 run tree) on PG17: the paged list (window, root_only, status, agent, group scope)
and one run's tree (ordered steps, model calls with requested vs served model, tool calls with
the Action Gate outcome, child runs, handoffs resolved to agents, 404s and bounds)."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

import pytest
import sibyl_lane_a_kit as kit  # loaded by conftest
from sibyl_control.api.reads import runs as runs_module

API = "/api/v1"
RH = hashlib.sha256(b"profile").digest()


@pytest.fixture
def lane(lane_db: Any) -> Any:
    with kit.lane_app(lane_db) as app:
        yield app


def tok(lane: Any, w: Any, role: str) -> str:
    return kit.add_session(lane.db, w.tenant, w.users[role])


def get(lane: Any, token: str, path: str, **params: Any) -> Any:
    return lane.client.get(f"{API}{path}", headers=lane.bearer(token), params=params)


def event(
    lane: Any,
    w: Any,
    agent: UUID,
    event_type: str,
    attrs: dict[str, Any],
    *,
    task: UUID | None = None,
    ago_s: float = 5,
    status: str | None = "ok",
    trace: UUID | None = None,
    model: str | None = None,
    response_model: str | None = None,
) -> UUID:
    eid = uuid4()
    with lane.db.admin.tx(w.tenant):
        lane.db.admin.execute(
            "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id,"
            " task_id, call_id, trace_id, emitter_id, seq, policy_state, capture_mode,"
            " redaction_profile_hash, normaliser_version, status, provider, model, response_model,"
            " latency_ms, tokens_in, tokens_out, attrs)"
            " VALUES ($1, $2, now() - make_interval(secs => $3), $4, 'sdk', $5, $6, $7, $8, 'sdk',"
            " 1, 'fresh', 'full', $9, 'normaliser/1.0', $10, $11, $12, $13, 40, 10, 20,"
            " $14::text::jsonb)",
            w.tenant,
            eid,
            ago_s,
            event_type,
            agent,
            task,
            uuid4() if event_type == "gen_ai.request" else None,
            trace,
            RH,
            status,
            "openai" if event_type == "gen_ai.request" else None,
            model,
            response_model,
            json.dumps(attrs),
        )
    return eid


def run(
    lane: Any,
    w: Any,
    agent: UUID,
    name: str,
    *,
    parent: UUID | None = None,
    step: int | None = None,
    ago_s: float = 60,
    end: str | None = "ok",
    handoff: str | None = None,
    trace: UUID | None = None,
) -> UUID:
    """A run: a start event, and an end event unless ``end`` is None (still running)."""
    task = uuid4()
    tree: dict[str, Any] = {"agent_name": name}
    if parent:
        tree["parent_run_id"] = str(parent)
    if step is not None:
        tree["step_index"] = step
    event(
        lane,
        w,
        agent,
        "agent.invoke",
        {"phase": "start", **tree},
        task=task,
        ago_s=ago_s,
        status=None,
        trace=trace,
    )
    if end is not None:
        extra = {"handoff_to_agent": handoff} if handoff else {}
        event(
            lane,
            w,
            agent,
            "agent.invoke",
            {
                "phase": "end",
                "status": end,
                "duration_ms": 1500.0,
                "steps": 3,
                "tool_calls": 1,
                "model_calls": 1,
                **tree,
                **extra,
            },
            task=task,
            ago_s=ago_s - 1.5,
            status=end,
            trace=trace,
        )
    return task


def test_run_tree_with_steps_children_and_handoffs(lane: Any, world: Any) -> None:
    agent = world.agents["in_g1"]
    trace = uuid4()
    root = run(lane, world, agent, "supervisor", trace=trace, ago_s=100)
    child = run(lane, world, agent, "researcher", parent=root, step=1, ago_s=90, handoff="writer")
    grandchild = run(lane, world, agent, "fetcher", parent=child, step=0, ago_s=85, end=None)
    task = str(root)
    event(
        lane,
        world,
        agent,
        "gen_ai.request",
        {
            "request_model": "gpt-4o",
            "parent_run_id": task,
            "step_index": 0,
            "system_fingerprint": "fp_1",
        },
        task=root,
        ago_s=95,
        model="gpt-4o",
        response_model="gpt-4o-mini-2024-07-18",
    )
    event(
        lane,
        world,
        agent,
        "tool.call",
        {
            "tool_name": "refund",
            "tool_type": "function",
            "parent_run_id": task,
            "step_index": 2,
            "action_effect": "approved",
            "action_rule_id": "refunds.large",
            "held_action_id": str(uuid4()),
            "handoff_to_agent": "auditor",
        },
        task=root,
        ago_s=80,
    )
    event(
        lane,
        world,
        agent,
        "tool.call",
        {"tool_name": "plain", "tool_type": "function", "step_index": 0},
        task=child,
        ago_s=88,
    )
    owner = tok(lane, world, "owner")
    resp = get(lane, owner, f"/runs/{root}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["run_id"] == task and body["status"] == "ok" and body["truncated"] is False
    assert body["run_count"] == 3 and body["trace_id"] == trace.hex
    assert body["agent_name"] == "supervisor" and body["duration_ms"] == 1500.0
    assert [s["kind"] for s in body["steps"]] == ["model_call", "child_run", "tool_call"]
    model = body["steps"][0]["model_call"]
    assert (model["requested_model"], model["served_model"]) == ("gpt-4o", "gpt-4o-mini-2024-07-18")
    assert model["model_mismatch"] is True and model["system_fingerprint"] == "fp_1"
    gate = body["steps"][2]["tool_call"]["action_gate"]
    assert gate["effect"] == "approved" and gate["rule_id"] == "refunds.large"
    assert body["steps"][1]["child_run_id"] == str(child)
    [kid] = body["children"]
    assert kid["run_id"] == str(child) and kid["parent_run_id"] == task
    assert [s["tool_call"]["tool_name"] for s in kid["steps"] if s["kind"] == "tool_call"] == [
        "plain"
    ]
    assert kid["steps"][0]["tool_call"]["action_gate"] is None
    [grand] = kid["children"]
    assert grand["run_id"] == str(grandchild) and grand["status"] == "running"
    assert grand["ended_at"] is None
    [tool_handoff] = body["handoffs"]
    assert tool_handoff["via"] == "tool" and tool_handoff["to_agent"] == "auditor"
    assert tool_handoff["to_agent_id"] is None
    [run_handoff] = kid["handoffs"]
    assert run_handoff["via"] == "run"
    # a child is a run of its own
    assert get(lane, owner, f"/runs/{child}").json()["run_count"] == 2
    assert get(lane, owner, f"/runs/{uuid4()}").status_code == 404


def test_handoff_resolves_a_registered_agent(lane: Any, world: Any) -> None:
    agent = world.agents["in_g1"]
    slug = lane.db.admin.fetchval(
        "SELECT slug FROM sibyl.agent WHERE tenant_id = $1 AND id = $2", world.tenant, agent
    )
    root = run(lane, world, agent, "a", handoff=slug)
    owner = tok(lane, world, "owner")
    [h] = get(lane, owner, f"/runs/{root}").json()["handoffs"]
    assert h["to_agent"] == slug and h["to_agent_id"] == str(agent)


def test_runs_list_filters_window_and_paging(lane: Any, world: Any) -> None:
    agent, other = world.agents["in_g1"], world.agents["other"]
    old = run(lane, world, agent, "old", ago_s=26 * 3600)
    roots = [run(lane, world, agent, f"r{i}", ago_s=300 - i * 10) for i in range(3)]
    child = run(lane, world, agent, "child", parent=roots[0], step=0, ago_s=200)
    failed = run(lane, world, other, "failed", ago_s=100, end="error")
    live = run(lane, world, agent, "live", ago_s=50, end=None)
    owner = tok(lane, world, "owner")
    data = get(lane, owner, "/runs").json()["data"]
    ids = [r["run_id"] for r in data]
    assert str(old) not in ids and ids[0] == str(live)
    assert set(ids) == {*(str(r) for r in roots), str(child), str(failed), str(live)}
    roots_only = {r["run_id"] for r in get(lane, owner, "/runs", root_only="true").json()["data"]}
    assert str(child) not in roots_only and str(roots[0]) in roots_only
    assert [r["run_id"] for r in get(lane, owner, "/runs", status="error").json()["data"]] == [
        str(failed)
    ]
    assert [r["run_id"] for r in get(lane, owner, "/runs", status="running").json()["data"]] == [
        str(live)
    ]
    mine = get(lane, owner, "/runs", agent_id=str(other)).json()["data"]
    assert [r["run_id"] for r in mine] == [str(failed)]
    first = get(lane, owner, "/runs", limit=2).json()
    assert first["has_more"] and len(first["data"]) == 2
    other_filter = get(lane, owner, "/runs", status="ok", cursor=first["next_cursor"])
    assert other_filter.status_code == 400  # a cursor is bound to its filters
    rest = get(lane, owner, "/runs", limit=2, cursor=first["next_cursor"]).json()
    assert not {r["run_id"] for r in rest["data"]} & {r["run_id"] for r in first["data"]}
    since = get(lane, owner, "/runs", since="2000-01-01T00:00:00Z", until="2000-01-02T00:00:00Z")
    assert since.json()["data"] == []
    wide = get(lane, owner, "/runs", since="2000-01-01T00:00:00Z", until="2001-01-01T00:00:00Z")
    assert wide.status_code == 422
    with_old = get(lane, owner, "/runs", since="2000-01-01T00:00:00Z")
    assert with_old.status_code == 422  # since..now is wider than 31 days
    assert get(lane, owner, "/runs", status="bogus").status_code == 422


def test_runs_are_group_scoped(lane: Any, world: Any) -> None:
    mine = run(lane, world, world.agents["in_g1"], "mine")
    theirs = run(lane, world, world.agents["other"], "theirs")
    child = run(lane, world, world.agents["other"], "hidden", parent=mine, step=0)
    eng = tok(lane, world, "engineer")
    ids = {r["run_id"] for r in get(lane, eng, "/runs").json()["data"]}
    assert str(mine) in ids and str(theirs) not in ids and str(child) not in ids
    assert get(lane, eng, f"/runs/{theirs}").status_code == 404
    tree = get(lane, eng, f"/runs/{mine}").json()
    assert tree["children"] == [] and tree["run_count"] == 1


def test_tree_bounds_mark_truncated(lane: Any, world: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(runs_module, "MAX_RUNS", 2)
    monkeypatch.setattr(runs_module, "MAX_STEPS", 1)
    agent = world.agents["in_g1"]
    root = run(lane, world, agent, "root")
    for i in range(3):
        run(lane, world, agent, f"kid{i}", parent=root, step=i)
    for i in range(2):
        event(
            lane,
            world,
            agent,
            "tool.call",
            {"tool_name": f"t{i}", "tool_type": "function"},
            task=root,
        )
    body = get(lane, tok(lane, world, "owner"), f"/runs/{root}").json()
    assert body["truncated"] is True and body["run_count"] == 2
    assert len([s for s in body["steps"] if s["kind"] == "tool_call"]) == 1
