"""Fixtures for plug-and-play tests: fake provider SDKs and agent frameworks installed into
`sys.modules` (the real packages are never needed), a recording ingest, a signed snapshot
server and a fake Action API. The fakes mirror the public surfaces Sibyl hooks:

* openai: `resources.chat.completions.{Completions,AsyncCompletions}.create`,
  `resources.responses.{Responses,AsyncResponses}.create`, `resources.embeddings`;
* anthropic: `resources.messages.{Messages,AsyncMessages}.create`;
* google.genai: `models.{Models,AsyncModels}.generate_content[_stream]`;
* langchain_core: `callbacks.BaseCallbackHandler`, `tracers.context.register_configure_hook`;
* agents (OpenAI Agents SDK): `add_trace_processor`, `FunctionTool`, `tracing`;
* crewai: `events.crewai_event_bus` + event classes, `tools.base_tool.BaseTool`,
  `tools.structured_tool.CrewStructuredTool`.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import sibyl
from sibyl import _gate, _obo
from sibyl._run import activate
from sibyl.integrations import _common
from sibyl.testing import TEST_KEY, FakeActionApi, Ingest, OffsetClock, SnapshotServer, wait_for

FAST = sibyl.ExporterConfig(
    schedule_delay=timedelta(milliseconds=20),
    heartbeat_interval=timedelta(hours=1),
    buffer_report_interval=timedelta(hours=1),
)
QUICK = sibyl.ActionConfig(
    hold_poll_interval=timedelta(milliseconds=5),
    hold_poll_max_interval=timedelta(milliseconds=20),
    max_hold_wait=timedelta(seconds=3),
)


@pytest.fixture(autouse=True)
def _reset_integrations() -> Iterator[None]:
    from sibyl.integrations import crewai, langchain, openai_agents

    def clear() -> None:
        _common.reset_active()
        for module in (crewai, langchain, openai_agents):
            module._installed.clear()
        _gate.set_sensitive(None)
        _obo.set_default(None)
        activate(None)  # framework callbacks set the current run without reset tokens

    clear()
    yield
    clear()


def _module(monkeypatch: pytest.MonkeyPatch, name: str, **attrs: Any) -> types.ModuleType:
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    parent, _, child = name.rpartition(".")
    if parent and parent in sys.modules:
        setattr(sys.modules[parent], child, module)
    return module


@pytest.fixture
def server(clock: OffsetClock, ingest: Ingest) -> SnapshotServer:
    srv = SnapshotServer(clock)
    srv.install(ingest)
    return srv


@pytest.fixture
def api(ingest: Ingest) -> FakeActionApi:
    fake = FakeActionApi(decide="approved", decide_after=1)
    fake.install(ingest)
    return fake


@pytest.fixture
def start(ingest: Ingest, tmp_path: Path, clock: OffsetClock) -> Callable[..., sibyl.Client]:
    def _start(**kwargs: Any) -> sibyl.Client:
        args: dict[str, Any] = {
            "endpoint": "http://127.0.0.1:8445",
            "agent_id": "quote-assistant",
            "exporter": FAST,
            "policy": sibyl.PolicyConfig(
                cache_dir=str(tmp_path / "policy"), poll_interval=timedelta(hours=1)
            ),
            "transport": ingest.transport,
            "actions": QUICK,
        }
        args.update(kwargs)
        client = sibyl.init(TEST_KEY, **args)
        client.clock = clock
        client.policy._clock = clock
        return client

    return _start


@pytest.fixture
def ready() -> Callable[[sibyl.Client], bool]:
    return lambda client: wait_for(lambda: client.snapshot is not None)


# ----------------------------------------------------------------------- provider SDKs


@dataclass
class Script:
    """What fake provider methods return, and what they were called with."""

    responses: list[Any] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    error: BaseException | None = None

    def next(self, kwargs: dict[str, Any]) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.responses.pop(0) if self.responses else {}


def _sync_create(script: Script) -> Callable[..., Any]:
    def create(self: Any, **kwargs: Any) -> Any:
        result = script.next(kwargs)
        return iter(result) if kwargs.get("stream") else result

    return create


def _async_create(script: Script) -> Callable[..., Any]:
    async def create(self: Any, **kwargs: Any) -> Any:
        result = script.next(kwargs)
        return _aiter(result) if kwargs.get("stream") else result

    return create


async def _agen(items: list[Any]) -> Any:
    for item in items:
        yield item


def _aiter(items: Any) -> Any:
    return _agen(list(items))


@pytest.fixture
def fake_openai(monkeypatch: pytest.MonkeyPatch) -> dict[str, Script]:
    scripts = {k: Script() for k in ("chat", "responses", "embeddings")}
    _module(monkeypatch, "openai")
    _module(monkeypatch, "openai.resources")
    _module(monkeypatch, "openai.resources.chat")
    _module(
        monkeypatch,
        "openai.resources.chat.completions",
        Completions=type("Completions", (), {"create": _sync_create(scripts["chat"])}),
        AsyncCompletions=type("AsyncCompletions", (), {"create": _async_create(scripts["chat"])}),
    )
    _module(
        monkeypatch,
        "openai.resources.responses",
        Responses=type("Responses", (), {"create": _sync_create(scripts["responses"])}),
        AsyncResponses=type("AsyncResponses", (), {"create": _async_create(scripts["responses"])}),
    )
    _module(
        monkeypatch,
        "openai.resources.embeddings",
        Embeddings=type("Embeddings", (), {"create": _sync_create(scripts["embeddings"])}),
        AsyncEmbeddings=type(
            "AsyncEmbeddings", (), {"create": _async_create(scripts["embeddings"])}
        ),
    )
    return scripts


@pytest.fixture
def fake_anthropic(monkeypatch: pytest.MonkeyPatch) -> Script:
    script = Script()
    _module(monkeypatch, "anthropic")
    _module(monkeypatch, "anthropic.resources")
    _module(
        monkeypatch,
        "anthropic.resources.messages",
        Messages=type("Messages", (), {"create": _sync_create(script)}),
        AsyncMessages=type("AsyncMessages", (), {"create": _async_create(script)}),
    )
    return script


@pytest.fixture
def fake_google(monkeypatch: pytest.MonkeyPatch) -> Script:
    script = Script()

    def generate(self: Any, **kwargs: Any) -> Any:
        return script.next(kwargs)

    def generate_stream(self: Any, **kwargs: Any) -> Any:
        return iter(script.next(kwargs))

    async def agenerate(self: Any, **kwargs: Any) -> Any:
        return script.next(kwargs)

    async def agenerate_stream(self: Any, **kwargs: Any) -> Any:
        return _aiter(script.next(kwargs))

    _module(monkeypatch, "google")
    _module(monkeypatch, "google.genai")
    _module(
        monkeypatch,
        "google.genai.models",
        Models=type(
            "Models",
            (),
            {"generate_content": generate, "generate_content_stream": generate_stream},
        ),
        AsyncModels=type(
            "AsyncModels",
            (),
            {"generate_content": agenerate, "generate_content_stream": agenerate_stream},
        ),
    )
    return script


# ----------------------------------------------------------------------- frameworks


class BaseCallbackHandler:
    raise_error = False
    run_inline = False


@dataclass
class LangChainFake:
    hooks: list[tuple[Any, bool]] = field(default_factory=list)

    def handler(self) -> Any:
        (var, inheritable), *_ = self.hooks
        assert inheritable is True
        return var.get()


@pytest.fixture
def fake_langchain(monkeypatch: pytest.MonkeyPatch) -> LangChainFake:
    fake = LangChainFake()

    def register_configure_hook(var: Any, inheritable: bool, *_: Any, **__: Any) -> None:
        fake.hooks.append((var, inheritable))

    _module(monkeypatch, "langchain_core")
    _module(monkeypatch, "langchain_core.callbacks", BaseCallbackHandler=BaseCallbackHandler)
    _module(monkeypatch, "langchain_core.tracers")
    _module(
        monkeypatch,
        "langchain_core.tracers.context",
        register_configure_hook=register_configure_hook,
    )
    return fake


@dataclass
class FunctionTool:
    name: str
    on_invoke_tool: Callable[..., Any]


@dataclass
class AgentsFake:
    processors: list[Any] = field(default_factory=list)


@pytest.fixture
def fake_agents(monkeypatch: pytest.MonkeyPatch) -> AgentsFake:
    fake = AgentsFake()
    tool_cls = type("FunctionTool", (FunctionTool,), {})
    _module(
        monkeypatch,
        "agents",
        add_trace_processor=fake.processors.append,
        FunctionTool=tool_cls,
    )
    _module(monkeypatch, "agents.tracing", add_trace_processor=fake.processors.append)
    return fake


class EventBus:
    def __init__(self) -> None:
        self.handlers: dict[type, list[Callable[[Any, Any], None]]] = {}

    def on(self, event_type: type) -> Callable[[Callable[[Any, Any], None]], Any]:
        def register(fn: Callable[[Any, Any], None]) -> Callable[[Any, Any], None]:
            self.handlers.setdefault(event_type, []).append(fn)
            return fn

        return register

    def emit(self, source: Any, event: Any) -> None:
        for fn in self.handlers.get(type(event), []):
            fn(source, event)


def _event(name: str) -> type:
    def init(self: Any, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

    return type(name, (), {"__init__": init})


@dataclass
class CrewFake:
    bus: EventBus
    events: types.ModuleType
    base_tool: type
    structured_tool: type


@pytest.fixture
def fake_crewai(monkeypatch: pytest.MonkeyPatch) -> CrewFake:
    bus = EventBus()
    names = [
        "CrewKickoffStartedEvent",
        "CrewKickoffCompletedEvent",
        "CrewKickoffFailedEvent",
        "AgentExecutionStartedEvent",
        "AgentExecutionCompletedEvent",
        "AgentExecutionErrorEvent",
        "ToolUsageStartedEvent",
        "ToolUsageFinishedEvent",
        "ToolUsageErrorEvent",
    ]
    _module(monkeypatch, "crewai")
    events = _module(
        monkeypatch, "crewai.events", crewai_event_bus=bus, **{n: _event(n) for n in names}
    )

    class BaseTool:
        name = "tool"

        def __init__(self, name: str, fn: Callable[..., Any]) -> None:
            self.name = name
            self._fn = fn

        def run(self, *args: Any, **kwargs: Any) -> Any:
            return self._fn(*args, **kwargs)

    class CrewStructuredTool:
        def __init__(self, name: str, tool: BaseTool) -> None:
            self.name = name
            self._tool = tool

        def invoke(self, input: Any, config: Any = None) -> Any:
            return self._tool.run(**input)

        async def ainvoke(self, input: Any, config: Any = None) -> Any:
            return self._tool.run(**input)

    _module(monkeypatch, "crewai.tools")
    _module(monkeypatch, "crewai.tools.base_tool", BaseTool=BaseTool)
    _module(monkeypatch, "crewai.tools.structured_tool", CrewStructuredTool=CrewStructuredTool)
    return CrewFake(bus, events, BaseTool, CrewStructuredTool)
