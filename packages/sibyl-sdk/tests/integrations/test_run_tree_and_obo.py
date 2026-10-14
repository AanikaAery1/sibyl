"""Run tree (parent_run_id, step_index, handoff_to_agent) on hand-instrumented runs and tools,
and `sibyl.on_behalf_of(...)` on held actions and model-call headers."""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable
from typing import Any

import pytest
import sibyl
from pydantic import TypeAdapter
from sibyl import _obo
from sibyl._run import activate, close_run, current_run, open_run
from sibyl.testing import FakeActionApi, Ingest, SnapshotServer, attrs, wait_for
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.models import WireEvent

PAYMENTS = load_fixture("action_gate", "vectors.json")["policies"]["payments"]
USER = "0192767f-0000-7000-8000-0000000000aa"
WIRE = TypeAdapter(WireEvent)


def invoke_spans(ingest: Ingest) -> dict[str, dict[str, Any]]:
    assert sibyl.flush(2)
    return {
        attrs(s)["gen_ai.agent.name"]: attrs(s)
        for s in ingest.spans()
        if attrs(s).get("gen_ai.operation.name") == "invoke_agent"
    }


def test_nested_runs_tools_and_handoffs_form_a_tree(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    start()

    @sibyl.tool
    def lookup(order: str) -> str:
        return order

    with sibyl.agent("supervisor") as root:
        lookup("A-1")
        with sibyl.agent("researcher") as child:
            lookup("A-2")
        root.handoff_to("billing-agent")
    spans = invoke_spans(ingest)
    sup, res = spans["supervisor"], spans["researcher"]
    assert "sibyl.parent_run_id" not in sup and sup["sibyl.handoff_to_agent"] == "billing-agent"
    assert res["sibyl.parent_run_id"] == str(root.task_id) and res["sibyl.step_index"] == 1
    tools = [attrs(s) for s in ingest.spans() if attrs(s).get("gen_ai.tool.name") == "lookup"]
    by_parent = {t["sibyl.parent_run_id"]: t["sibyl.step_index"] for t in tools}
    assert by_parent == {str(root.task_id): 0, str(child.task_id): 0}
    starts = [e for e in ingest.events() if e["type"] == "agent.invoke"]
    child_start = next(e for e in starts if e["attrs"]["agent_name"] == "researcher")
    assert child_start["attrs"]["parent_run_id"] == str(root.task_id)
    assert child_start["attrs"]["step_index"] == 1
    for event in starts:
        assert sj.is_valid("sibyl-event-wire/1", event)
        WIRE.validate_python(event)


def test_handoff_ref_is_trimmed_and_blank_is_ignored(start: Callable[..., sibyl.Client]) -> None:
    start()
    with sibyl.agent("a") as run:
        run.handoff_to("   ")
        assert run.handoff_to_agent is None
        run.handoff_to("x" * 400)
        assert run.handoff_to_agent == "x" * 256


def test_framework_runs_open_and_close_without_context_tokens(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    start()
    root = open_run("graph", parent=None)
    activate(root)
    child = open_run("node", parent=root, step_index=3)
    errors: list[BaseException] = []

    def close_elsewhere() -> None:  # a framework may end a run on another thread
        try:
            close_run(child, error=RuntimeError("boom"))
        except BaseException as exc:  # pragma: no cover - the assertion reports it
            errors.append(exc)

    worker = threading.Thread(target=close_elsewhere)
    worker.start()
    worker.join()
    close_run(root, status="ok")
    activate(None)
    assert not errors and current_run() is None
    spans = invoke_spans(ingest)
    assert spans["node"]["sibyl.step_index"] == 3
    assert spans["node"]["error.type"] == "RuntimeError"
    assert spans["node"]["sibyl.parent_run_id"] == str(root.task_id)


def test_on_behalf_of_validation_and_nesting() -> None:
    assert _obo.parse(user=USER) == {"kind": "user", "id": USER}
    assert _obo.parse({"kind": "external", "ref": "crm:1"}) == {"kind": "external", "ref": "crm:1"}
    assert _obo.parse("crm:2") == {"kind": "external", "ref": "crm:2"}
    from uuid import UUID

    assert _obo.parse(UUID(USER))["kind"] == "user"
    for bad in (
        {"value": None},
        {"user": "not-a-uuid"},
        {"external": ""},
        {"external": "x" * 129},
        {"external": "a\nb"},
        {"value": {"kind": "robot"}},
    ):
        with pytest.raises(sibyl.SibylConfigError):
            _obo.parse(**bad)
    with pytest.raises(sibyl.SibylConfigError):
        _obo.parse(user=USER, external="x")
    assert _obo.current() is None
    with sibyl.on_behalf_of(external="outer") as outer:
        assert outer == {"kind": "external", "ref": "outer"}
        with sibyl.on_behalf_of(user=USER):
            assert _obo.header_value() == f"user:{USER}"
        assert _obo.header_value() == "external:outer"
    assert _obo.current() is None
    _obo.set_default({"kind": "external", "ref": "proc"})
    assert _obo.header_value() == "external:proc"


def test_held_action_request_carries_on_behalf_of(
    start: Callable[..., sibyl.Client],
    server: SnapshotServer,
    api: FakeActionApi,
) -> None:
    server.publish(action_policies=[copy.deepcopy(PAYMENTS)])
    client = start()
    assert wait_for(lambda: client.snapshot is not None and bool(client.snapshot.action_policies))

    @sibyl.tool(name="payments.refund")
    def refund(customer_id: str) -> str:
        return "refunded"

    with sibyl.on_behalf_of(user=USER):
        assert refund("c-1") == "refunded"
    assert refund("c-2") == "refunded"
    first, second = api.holds.values()
    assert first["on_behalf_of"] == {"kind": "user", "id": USER}
    assert "on_behalf_of" not in second
