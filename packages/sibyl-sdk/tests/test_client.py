"""End-to-end SDK behaviour against a recording ingest and a signed snapshot server:
runs, tools, instrumentation, header propagation, kill switch, labels, schema conformance."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import sibyl
from pydantic import TypeAdapter
from sibyl.testing import (
    AGENT_UUID,
    TENANT_UUID,
    TEST_KEY,
    Ingest,
    OffsetClock,
    SnapshotServer,
    attrs,
    wait_for,
)
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.models import Checkpoint, HandoffPacket, WireEvent

WIRE = TypeAdapter(WireEvent)
FAST = sibyl.ExporterConfig(
    schedule_delay=timedelta(milliseconds=20),
    heartbeat_interval=timedelta(hours=1),
    buffer_report_interval=timedelta(hours=1),
)


@pytest.fixture
def server(clock: OffsetClock, ingest: Ingest) -> SnapshotServer:
    srv = SnapshotServer(clock)
    srv.install(ingest)
    return srv


@pytest.fixture
def start(ingest: Ingest, tmp_path: Path) -> Callable[..., sibyl.Client]:
    def _start(**kwargs: Any) -> sibyl.Client:
        policy = kwargs.pop("policy", None) or sibyl.PolicyConfig(
            cache_dir=str(tmp_path / "policy"), poll_interval=timedelta(hours=1)
        )
        args: dict[str, Any] = {
            "endpoint": "http://127.0.0.1:8445",
            "agent_id": "quote-assistant",
            "exporter": FAST,
            "policy": policy,
            "transport": ingest.transport,
        }
        args.update(kwargs)
        return sibyl.init(TEST_KEY, **args)

    return _start


def ready(client: sibyl.Client) -> bool:
    return wait_for(lambda: client.snapshot is not None)


def assert_wire_valid(event: dict[str, Any]) -> None:
    assert sj.is_valid("sibyl-event-wire/1", event), (
        sj.errors("sibyl-event-wire/1", event) if hasattr(sj, "errors") else event
    )
    WIRE.validate_python(event)


# ----------------------------------------------------------------------- fakes


class FakeCompletions:
    def __init__(
        self,
        response: Any = None,
        chunks: list[Any] | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response = response or {
            "id": "chatcmpl-1",
            "model": "gpt-5-mini-2026",
            "usage": {"prompt_tokens": 12, "completion_tokens": 5},
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Quote: INR 4,18,000"},
                }
            ],
        }
        self.chunks = chunks
        self.error = error

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        if kwargs.get("stream"):
            return iter(self.chunks or [])
        return self.response


class FakeEmbeddings:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return {
            "model": "text-embedding-3-small",
            "usage": {"prompt_tokens": 3},
            "data": [{"embedding": [0.1]}],
        }


class FakeChat:
    def __init__(self, completions: FakeCompletions) -> None:
        self.completions = completions


class FakeOpenAI:
    def __init__(self, **kw: Any) -> None:
        self.chat = FakeChat(FakeCompletions(**kw))
        self.embeddings = FakeEmbeddings()


class FakeMessages:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if kwargs.get("stream"):
            return iter(
                [
                    {
                        "type": "message_start",
                        "message": {
                            "id": "msg_1",
                            "model": "claude-x",
                            "usage": {"input_tokens": 9},
                        },
                    },
                    {"type": "content_block_delta", "delta": {"text": "Hel"}},
                    {"type": "content_block_delta", "delta": {"text": "lo"}},
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn"},
                        "usage": {"output_tokens": 2},
                    },
                ]
            )
        return {
            "id": "msg_1",
            "model": "claude-x",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 9, "output_tokens": 2},
            "content": [{"type": "text", "text": "Hello"}],
        }


class FakeAnthropic:
    def __init__(self) -> None:
        self.messages = FakeMessages()


def chat_spans(ingest: Ingest) -> list[dict[str, Any]]:
    return [s for s in ingest.spans() if attrs(s).get("gen_ai.operation.name") == "chat"]


# ----------------------------------------------------------------------- init


def test_init_without_key_raises_config_error() -> None:
    with pytest.raises(sibyl.SibylConfigError):
        sibyl.init(endpoint="http://127.0.0.1:1")


def test_get_client_before_init_raises_and_helpers_are_noops() -> None:
    with pytest.raises(sibyl.SibylConfigError):
        sibyl.get_client()
    assert sibyl.flush() is True
    sibyl.policy.check()
    assert sibyl.policy.current() is None
    with sibyl.agent(goal="g") as run:
        assert sibyl.checkpoint({"a": 1}) is not None
        assert sibyl.feedback(1.0) is not None
        sibyl.outcome("success")
        packet = sibyl.handoff.packet(
            reason="provider failed while drafting",
            failure_mode="provider_outage",
            next_action="Do it by hand",
        )
        assert run.handoff(packet) == __import__("uuid").UUID(packet.packet_id)


def test_reinit_replaces_client(start: Callable[..., sibyl.Client]) -> None:
    first = start()
    second = start()
    assert sibyl.get_client() is second and first is not second


# ----------------------------------------------------------------------- runs and tools


def test_agent_run_emits_start_event_and_end_span(
    start: Callable[..., sibyl.Client], ingest: Ingest, server: SnapshotServer
) -> None:
    client = start()
    assert ready(client)
    with sibyl.agent("quote-assistant", goal="Quote order A-1") as run:
        with sibyl.agent("sub") as child:
            assert child.parent_task_id == run.task_id
            assert child.trace_id == run.trace_id
    assert sibyl.flush(2)
    (start_event,) = [e for e in ingest.events() if e["type"] == "agent.invoke"][:1]
    assert start_event["attrs"]["phase"] == "start"
    assert start_event["agent_id"] == AGENT_UUID and start_event["tenant_id"] == TENANT_UUID
    for event in ingest.events():
        assert_wire_valid(event)
    spans = {
        attrs(s)["sibyl.task_id"]: s
        for s in ingest.spans()
        if attrs(s).get("gen_ai.operation.name") == "invoke_agent"
    }
    outer = attrs(spans[str(run.task_id)])
    assert outer["sibyl.invoke.status"] == "ok" and outer["gen_ai.agent.name"] == "quote-assistant"
    inner = attrs(spans[str(child.task_id)])
    assert inner["sibyl.parent_task_id"] == str(run.task_id)
    assert spans[str(child.task_id)]["parentSpanId"] == spans[str(run.task_id)]["spanId"]


@pytest.mark.parametrize(
    ("action", "status"), [("raise", "error"), ("cancel", "cancelled"), ("handoff", "handed_off")]
)
def test_agent_run_status_mapping(
    start: Callable[..., sibyl.Client], ingest: Ingest, action: str, status: str
) -> None:
    start()
    with pytest.raises(ValueError) if action == "raise" else _null():
        with sibyl.agent("a") as run:
            if action == "raise":
                raise ValueError("boom")
            if action == "cancel":
                run.cancel("operator asked")
            if action == "handoff":
                run.handoff(
                    sibyl.handoff.packet(
                        reason="tool failed after three retries",
                        failure_mode="tool_failure",
                        next_action="Finish manually",
                    )
                )
    assert sibyl.flush(2)
    span = next(
        s for s in ingest.spans() if attrs(s).get("gen_ai.operation.name") == "invoke_agent"
    )
    assert attrs(span)["sibyl.invoke.status"] == status


class _null:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *a: object) -> None:
        return None


def test_async_agent_run(start: Callable[..., sibyl.Client], ingest: Ingest) -> None:
    start()

    async def main() -> str:
        async with sibyl.agent("async-agent") as run:
            return str(run.task_id)

    task_id = asyncio.run(main())
    assert sibyl.flush(2)
    assert any(attrs(s).get("sibyl.task_id") == task_id for s in ingest.spans())


def test_tool_sync_async_generator_and_errors(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    start()

    @sibyl.tool(side_effect="read")
    def lookup(order_id: str) -> dict[str, str]:
        return {"order": order_id, "token": "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0" * 3}

    @sibyl.tool(name="send", side_effect="external", capture_args=False)
    async def send(to: str) -> None:
        return None

    @sibyl.tool
    def pages() -> Iterator[int]:
        yield 1
        yield 2

    @sibyl.tool
    def broken() -> None:
        raise KeyError("missing")

    with sibyl.agent("t") as run:
        assert lookup("A-1")["order"] == "A-1"
        asyncio.run(send("x@example.com"))
        assert list(pages()) == [1, 2]
        with pytest.raises(KeyError):
            broken()
    assert run.tool_calls == 4
    assert sibyl.flush(2)
    tools = {
        attrs(s)["gen_ai.tool.name"]: (s, attrs(s))
        for s in ingest.spans()
        if attrs(s).get("gen_ai.operation.name") == "execute_tool"
    }
    _, look = tools["lookup"]
    assert look["sibyl.tool.side_effect_class"] == "read"
    assert json.loads(look["gen_ai.tool.call.arguments"]) == {"order_id": "A-1"}
    assert "sk-proj-a1B2" not in look["gen_ai.tool.call.result"]
    assert look["sibyl.redaction.secrets_scrubbed"] >= 1
    assert "gen_ai.tool.call.arguments" not in tools["send"][1]
    span, info = tools["broken"]
    assert span["status"]["code"] == 2 and info["error.type"] == "KeyError"


# ----------------------------------------------------------------------- instrumentation


def test_instrumented_chat_call_injects_headers_and_records_span(
    start: Callable[..., sibyl.Client], ingest: Ingest, server: SnapshotServer
) -> None:
    client = start()
    assert ready(client)
    oai = sibyl.instrument(FakeOpenAI())
    with sibyl.agent("quote-assistant") as run:
        oai.chat.completions.create(
            model="gpt-5-mini",
            temperature=0.2,
            messages=[{"role": "user", "content": "quote please"}],
            extra_headers={"X-Custom": "1"},
        )
    sent = oai.chat.completions.calls[0]["extra_headers"]
    assert sent["X-Custom"] == "1"
    assert sent["X-Sibyl-Task-Id"] == str(run.task_id)
    assert sent["X-Sibyl-Agent"] == AGENT_UUID
    assert sent["X-Sibyl-Capture-Owner"] == "sdk"
    assert sent["X-Sibyl-Policy-Version"] == str(server.version)
    assert "X-Sibyl-Key" not in sent
    assert sibyl.flush(2)
    (span,) = chat_spans(ingest)
    a = attrs(span)
    assert sent["X-Sibyl-Call-Id"] == a["sibyl.call_id"]
    assert sent["traceparent"] == f"00-{span['traceId']}-{span['spanId']}-01"
    assert span["kind"] == 3 and span["name"] == "chat gpt-5-mini"
    assert a["gen_ai.provider.name"] == "openai"
    assert a["gen_ai.usage.input_tokens"] == 12 and a["gen_ai.usage.output_tokens"] == 5
    assert a["gen_ai.response.finish_reasons"] == ["stop"]
    assert a["gen_ai.request.temperature"] == 0.2
    assert json.loads(a["gen_ai.input.messages"])[0]["content"] == "quote please"
    assert "INR" in a["gen_ai.output.messages"]
    assert len(a["sibyl.content_hash.input"]) == 64
    assert a["sibyl.policy.state"] == "fresh" and a["sibyl.policy.version"] == server.version
    assert run.model_calls == 1


def test_instrument_is_idempotent(start: Callable[..., sibyl.Client], ingest: Ingest) -> None:
    start()
    oai = sibyl.instrument(sibyl.instrument(FakeOpenAI()))
    oai.chat.completions.create(model="m", messages=[])
    assert sibyl.flush(2)
    assert len(chat_spans(ingest)) == 1


def test_metadata_capture_ships_hashes_only_and_gateway_owns_body(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    start(capture_mode="metadata")
    oai = sibyl.instrument(FakeOpenAI())
    oai.chat.completions.create(model="m", messages=[{"role": "user", "content": "secret plan"}])
    assert oai.chat.completions.calls[0]["extra_headers"]["X-Sibyl-Capture-Owner"] == "gateway"
    assert sibyl.flush(2)
    a = attrs(chat_spans(ingest)[0])
    assert "gen_ai.input.messages" not in a and "gen_ai.output.messages" not in a
    assert len(a["sibyl.content_hash.output"]) == 64 and a["sibyl.output_chars"] > 0


def test_registry_capture_policy_tightens_init_mode(
    start: Callable[..., sibyl.Client], ingest: Ingest, server: SnapshotServer
) -> None:
    server.publish(capture="redacted")
    client = start(capture_mode="full")
    assert ready(client)
    assert client.capture_mode == "redacted"


def test_streaming_openai_reassembles_and_records_ttfb(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    start()
    chunks = [
        {"id": "c1", "model": "m-2026", "choices": [{"delta": {"content": "Hel"}}]},
        {"id": "c1", "choices": [{"delta": {"content": "lo"}, "finish_reason": "stop"}]},
        {"id": "c1", "choices": [], "usage": {"prompt_tokens": 4, "completion_tokens": 2}},
    ]
    oai = sibyl.instrument(FakeOpenAI(chunks=chunks))
    stream = oai.chat.completions.create(model="m", stream=True, messages=[])
    assert chat_spans(ingest) == []
    assert len(list(stream)) == 3
    assert sibyl.flush(2)
    a = attrs(chat_spans(ingest)[0])
    assert a["sibyl.streamed"] is True and "sibyl.ttfb_ms" in a
    assert json.loads(a["gen_ai.output.messages"])[0]["content"] == "Hello"
    assert a["gen_ai.usage.output_tokens"] == 2 and a["gen_ai.response.finish_reasons"] == ["stop"]


def test_anthropic_messages_plain_and_streaming(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    start()
    ant = sibyl.instrument(FakeAnthropic())
    ant.messages.create(model="claude-x", system="be brief", messages=[])
    list(ant.messages.create(model="claude-x", stream=True, messages=[]))
    assert sibyl.flush(2)
    plain, streamed = [attrs(s) for s in chat_spans(ingest)]
    assert plain["gen_ai.provider.name"] == "anthropic"
    assert plain["gen_ai.response.finish_reasons"] == ["end_turn"]
    assert plain["gen_ai.system_instructions"] == "be brief"
    assert (
        streamed["gen_ai.usage.input_tokens"] == 9 and streamed["gen_ai.usage.output_tokens"] == 2
    )
    assert "Hello" in streamed["gen_ai.output.messages"]


def test_provider_error_is_recorded_and_reraised(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    class RateLimited(Exception):
        status_code = 429

    start()
    oai = sibyl.instrument(FakeOpenAI(error=RateLimited("slow down")))
    with pytest.raises(RateLimited):
        oai.chat.completions.create(model="m", messages=[])
    assert sibyl.flush(2)
    a = attrs(chat_spans(ingest)[0])
    assert a["error.type"] == "RateLimited" and a["http.response.status_code"] == 429


def test_embeddings_are_instrumented(start: Callable[..., sibyl.Client], ingest: Ingest) -> None:
    start()
    oai = sibyl.instrument(FakeOpenAI())
    oai.embeddings.create(model="text-embedding-3-small", input="hello")
    assert sibyl.flush(2)
    span = next(s for s in ingest.spans() if attrs(s).get("gen_ai.operation.name") == "embeddings")
    assert attrs(span)["gen_ai.usage.input_tokens"] == 3


def test_async_client_is_instrumented(start: Callable[..., sibyl.Client], ingest: Ingest) -> None:
    class AsyncCompletions:
        async def create(self, **kwargs: Any) -> Any:
            return {"id": "x", "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]}

    class AsyncOpenAI:
        def __init__(self) -> None:
            self.chat = type("C", (), {})()
            self.chat.completions = AsyncCompletions()

    start()
    client = sibyl.instrument(AsyncOpenAI())
    asyncio.run(client.chat.completions.create(model="m", messages=[]))
    assert sibyl.flush(2)
    assert len(chat_spans(ingest)) == 1


def test_auto_instrument_patches_importable_sdk_classes(
    monkeypatch: pytest.MonkeyPatch, start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    import sys
    import types

    module = types.ModuleType("openai.resources.chat.completions")

    class Completions:
        def create(self, **kwargs: Any) -> Any:
            return {"choices": []}

    class AsyncCompletions:
        async def create(self, **kwargs: Any) -> Any:
            return {"choices": []}

    module.Completions = Completions  # type: ignore[attr-defined]
    module.AsyncCompletions = AsyncCompletions  # type: ignore[attr-defined]
    for name in ("openai", "openai.resources", "openai.resources.chat"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "openai.resources.chat.completions", module)
    start()
    assert getattr(Completions.create, "__sibyl_wrapped__", False)
    Completions().create(model="m", messages=[])
    assert sibyl.flush(2)
    assert len(chat_spans(ingest)) == 1


# ----------------------------------------------------------------------- kill switch / policy


def test_killed_snapshot_raises_before_any_provider_request(
    start: Callable[..., sibyl.Client], ingest: Ingest, server: SnapshotServer
) -> None:
    server.publish(state="killed")
    client = start()
    assert ready(client)
    oai = sibyl.instrument(FakeOpenAI())
    with pytest.raises(sibyl.SibylKilled) as info:
        oai.chat.completions.create(model="m", messages=[])
    assert oai.chat.completions.calls == []
    assert str(info.value.agent_id) == AGENT_UUID and info.value.policy_version == server.version
    assert sibyl.flush(2)
    decisions = [e for e in ingest.events() if e["type"] == "policy.decision"]
    assert decisions and decisions[0]["attrs"]["action"] == "reject_killed"
    assert_wire_valid(decisions[0])


@pytest.mark.parametrize("scope", ["agent", "tenant"])
def test_kill_switch_scopes(
    start: Callable[..., sibyl.Client], server: SnapshotServer, scope: str
) -> None:
    server.publish(kill_switch=scope)
    client = start()
    assert ready(client)
    with pytest.raises(sibyl.SibylKilled):
        sibyl.policy.check()


def test_cached_killed_persists_through_staleness_and_restart(
    start: Callable[..., sibyl.Client], server: SnapshotServer, ingest: Ingest
) -> None:
    server.publish(state="killed", issued_offset=-10_000)  # far past max_stale
    client = start()
    assert ready(client)
    assert client.snapshot is not None and client.snapshot.freshness == "unavailable"
    with pytest.raises(sibyl.SibylKilled):
        sibyl.policy.check()
    server.down = True
    restarted = start()  # restored from the on-disk cache, no network
    assert restarted.snapshot is not None and restarted.snapshot.state == "killed"
    with pytest.raises(sibyl.SibylKilled):
        sibyl.policy.check()


def test_a_snapshot_is_on_disk_before_anyone_can_see_it(
    start: Callable[..., sibyl.Client], server: SnapshotServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Persist, then publish: a restart (or a crash) right after the client shows a snapshot
    finds it in the cache. Publishing first made the restart above flaky under load."""
    from sibyl._policy import PolicyManager

    seen_at_write: list[object] = []
    original = PolicyManager._write_cache

    def spy(self: PolicyManager, verified: Any, headers: Any) -> None:
        seen_at_write.append(self._snapshot)
        original(self, verified, headers)

    monkeypatch.setattr(PolicyManager, "_write_cache", spy)
    server.publish(state="killed")
    client = start()
    assert ready(client)
    assert seen_at_write and seen_at_write[0] is None, "written before it was published"


def test_fresh_snapshot_releases_the_kill(
    start: Callable[..., sibyl.Client], server: SnapshotServer
) -> None:
    server.publish(state="killed")
    client = start()
    assert ready(client)
    changes: list[str] = []
    sibyl.policy.on_change(lambda snap: changes.append(snap.state))
    server.publish(state="active")
    client.policy.poll_once()
    sibyl.policy.check()
    assert changes == ["active"]


def test_lower_or_replayed_version_is_refused(
    start: Callable[..., sibyl.Client], server: SnapshotServer
) -> None:
    client = start()
    assert ready(client)
    old_raw, old_headers = server.raw, server.headers
    server.publish(state="killed")
    client.policy.poll_once()
    assert not client.policy.ingest(old_raw, old_headers)  # replay of the unkilled version
    assert client.policy.rejections.get("non_monotonic") == 1
    assert client.snapshot is not None and client.snapshot.state == "killed"


def test_tampered_snapshot_is_rejected(
    start: Callable[..., sibyl.Client], server: SnapshotServer
) -> None:
    client = start()
    assert ready(client)
    server.publish(state="killed")
    tampered = server.raw.replace(b'"killed"', b'"active"')
    assert not client.policy.ingest(tampered, server.headers)
    assert client.policy.rejections.get("bad_signature") == 1


@pytest.mark.parametrize(
    ("offset", "fail_mode", "raises", "decision"),
    [
        (0, "closed", False, None),
        (-120, "closed", False, None),  # stale still serves
        (-600, "open", False, "forward_stale"),
        (-600, "closed", True, "reject_closed"),
        (-10_000, "closed", True, "reject_closed"),
    ],
)
def test_freshness_and_fail_mode_table(
    start: Callable[..., sibyl.Client],
    server: SnapshotServer,
    ingest: Ingest,
    offset: float,
    fail_mode: str,
    raises: bool,
    decision: str | None,
) -> None:
    server.publish(fail_mode=fail_mode, issued_offset=offset)
    client = start()
    assert ready(client)
    if raises:
        with pytest.raises(sibyl.SibylPolicyUnavailable):
            sibyl.policy.check()
    else:
        sibyl.policy.check()
    sibyl.policy.check() if not raises else None
    assert sibyl.flush(2)
    actions = [e["attrs"]["action"] for e in ingest.events() if e["type"] == "policy.decision"]
    assert actions == ([decision] if decision else [])  # rate-limited to once per minute


def test_no_snapshot_ever(start: Callable[..., sibyl.Client]) -> None:
    client = start()  # no snapshot route: 404
    sibyl.policy.check()  # fail-open default proceeds
    assert client.snapshot is None
    sibyl.shutdown(0.5)
    start(fail_mode="closed")
    with pytest.raises(sibyl.SibylPolicyUnavailable):
        sibyl.policy.check()


def test_quarantined_proceeds(start: Callable[..., sibyl.Client], server: SnapshotServer) -> None:
    server.publish(state="quarantined")
    client = start()
    assert ready(client)
    sibyl.policy.check()
    assert sibyl.policy.current() is not None
    assert sibyl.policy.current("quote-assistant") is client.snapshot
    assert sibyl.policy.current("someone-else") is None


def test_snapshot_view_uses_the_seven_routing_states(
    start: Callable[..., sibyl.Client], server: SnapshotServer
) -> None:
    server.publish(state="awaiting_approval")
    client = start()
    assert ready(client)
    assert client.snapshot is not None and client.snapshot.state == "awaiting_approval"


def test_gateway_key_is_refused_and_telemetry_disabled(
    start: Callable[..., sibyl.Client], server: SnapshotServer, ingest: Ingest
) -> None:
    server.publish(scopes=["gateway:proxy", "routing:read"])
    client = start()
    assert ready(client)
    assert wait_for(
        lambda: (
            client.stats().dropped_by_reason is not None and client.exporter._disabled is not None
        )
    )
    with sibyl.agent("x"):
        pass
    assert sibyl.flush(1)
    assert ingest.posts("/v1/otlp/traces") == []


def test_poll_sends_if_none_match_and_handles_304(
    start: Callable[..., sibyl.Client], server: SnapshotServer, ingest: Ingest
) -> None:
    client = start()
    assert ready(client)
    client.policy.poll_once()
    polls = [r for r in ingest.requests if r.path == "/api/v1/policy/snapshot"]
    assert polls[-1].headers["if-none-match"] == f'"{server.version}"'
    assert polls[-1].headers["authorization"] == f"Bearer {TEST_KEY}"
    assert "agent_id" not in polls[0].headers


def test_explicit_pin_and_unknown_signer(
    start: Callable[..., sibyl.Client], server: SnapshotServer, tmp_path: Path
) -> None:
    from sibyl.testing import SnapshotSigner

    rogue = SnapshotSigner(n=3, kid="snap-rogue")
    policy = sibyl.PolicyConfig(
        cache_dir=str(tmp_path / "p2"), public_key=rogue.pin(), poll_interval=timedelta(hours=1)
    )
    client = start(policy=policy)
    assert not wait_for(lambda: client.snapshot is not None, timeout=0.3)
    assert client.policy.rejections.get("unknown_kid", 0) >= 1


# ----------------------------------------------------------------------- labels


def test_checkpoint_handoff_feedback_outcome_conform(
    start: Callable[..., sibyl.Client], ingest: Ingest, server: SnapshotServer
) -> None:
    client = start()
    assert ready(client)
    with sibyl.agent("quote-assistant", goal="Quote order A-88213") as run:
        cp = sibyl.checkpoint(
            {"rfq": {"sku": "PAL-40"}, "api_key": "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0" * 3},
            step="lookup_order",
            completed=["parse_rfq", sibyl.Step("lookup_order", tool_name="lookup_order")],
            pending=["price_quote", sibyl.Step("send_quote", description="email it")],
            side_effects=[sibyl.SideEffect("api_call", target="crm.lookup", reversible=True)],
            state_schema="app:quote/v1",
        )
        packet = sibyl.handoff.packet(
            reason="Provider call failed while drafting the quote",
            failure_mode="provider_outage",
            next_action="Review the order and send the quote manually.",
        )
        assert packet.fidelity.value == "checkpoint"
        assert packet.provenance.checkpoint_id == str(cp)
        run.handoff(packet)
        sibyl.feedback(1, comment="great, thanks")
        sibyl.feedback(5, scale="stars")
        run.outcome("handed_off", reason="needs a human")
    assert sibyl.flush(2)
    events = ingest.events()
    for event in events:
        assert_wire_valid(event)
    by_type = {e["type"]: e for e in events}
    cp_event = by_type["checkpoint"]
    doc = json.loads(cp_event["attrs"]["payload_inline"]["data"])
    Checkpoint.model_validate(doc)
    assert doc["state"]["rfq"] == {"sku": "PAL-40"}
    assert "sk-proj-a1B2" not in cp_event["attrs"]["payload_inline"]["data"]
    assert cp_event["redaction_profile"]["secrets_scrubbed"] >= 1
    ho = by_type["handoff.requested"]
    HandoffPacket.model_validate_json(ho["attrs"]["payload_inline"]["data"])
    assert ho["attrs"]["fidelity"] == "checkpoint" and ho["attrs"]["checkpoint_seq"] == 1
    fb = [e for e in events if e["type"] == "feedback"]
    assert fb[0]["attrs"]["payload_inline"]["data"] == "great, thanks"
    assert fb[1]["attrs"]["score"] == 1.0 and fb[1]["attrs"]["raw_value"] == 5.0
    outcome = by_type["task.outcome"]
    assert outcome["attrs"]["outcome"] == "handed_off" and outcome["attrs"]["metrics"]["steps"] == 1
    critical = [
        r
        for r in ingest.posts("/v1/events")
        if any(e["type"] == "checkpoint" for e in r.body["events"])
    ]
    assert critical


def test_request_only_packet_without_checkpoint(start: Callable[..., sibyl.Client]) -> None:
    start()
    with sibyl.agent("a", goal="g"):
        packet = sibyl.handoff.packet(reason="short", failure_mode="tool_failure", next_action="go")
    assert packet.fidelity.value == "request_only" and packet.pending_steps == []
    assert len(packet.reason.plain_language) >= 20 and len(packet.next_action) >= 5


def test_handoff_without_scope_is_not_sent(
    start: Callable[..., sibyl.Client], server: SnapshotServer, ingest: Ingest
) -> None:
    server.publish(scopes=["ingest:write", "routing:read"])
    client = start()
    assert ready(client)
    with sibyl.agent("a"):
        sibyl.handoff.request(
            sibyl.handoff.packet(
                reason="the provider returned 503 three times",
                failure_mode="provider_outage",
                next_action="Retry later by hand",
            )
        )
    assert sibyl.flush(2)
    assert not [e for e in ingest.events() if e["type"] == "handoff.requested"]


def test_oversize_checkpoint_is_dropped_not_sent(
    start: Callable[..., sibyl.Client], ingest: Ingest
) -> None:
    client = start()
    with sibyl.agent("a"):
        sibyl.checkpoint({"blob": "x" * (16 * 1024 * 1024 + 10)})
    assert sibyl.flush(5)
    assert not [e for e in ingest.events() if e["type"] == "checkpoint"]
    assert client.stats().dropped_by_reason.get("finalize") == 1


def test_scrub_hook_from_init(start: Callable[..., sibyl.Client], ingest: Ingest) -> None:
    start(scrub=lambda text, ctx: text.replace("ACME", "[CUST]"))
    oai = sibyl.instrument(FakeOpenAI())
    oai.chat.completions.create(model="m", messages=[{"role": "user", "content": "ACME order"}])
    assert sibyl.flush(2)
    a = attrs(chat_spans(ingest)[0])
    assert "[CUST]" in a["gen_ai.input.messages"] and "ACME" not in a["gen_ai.input.messages"]
    assert "sdk.hook:<lambda>" in a["sibyl.redaction.rules"]
