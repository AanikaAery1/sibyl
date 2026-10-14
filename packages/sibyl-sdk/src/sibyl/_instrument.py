"""Provider client instrumentation: OpenAI (Chat Completions, Responses, Embeddings),
Anthropic (Messages) and Google Gen AI (generate_content), sync and async, streaming.

Each wrapped call: `policy.check()` (may raise `SibylKilled`) → `gen_ai.*` client span
(semconv 1.37) → `X-Sibyl-*`, `X-Sibyl-On-Behalf-Of` and `traceparent` injected (§8.6) →
served model, `system_fingerprint`, usage, finish reasons, refusals and proposed tool calls
(metadata, always) and content per capture mode (`_extract`) → end. Streams are proxied:
the span ends when the stream is exhausted or closed; `sibyl.ttfb_ms` is first-chunk
latency. Inside a run the span records `sibyl.parent_run_id` and `sibyl.step_index`.
"""

from __future__ import annotations

import functools
import importlib
import inspect
import logging
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sibyl import _obo, _state
from sibyl._client import Client
from sibyl._extract import Accumulator, extract, get, plain
from sibyl._ids import uuid7
from sibyl._run import current_run, tree_attributes
from sibyl._spans import KIND_CLIENT, Span
from sibyl._types import CaptureMode

__all__ = [
    "AUTO_TARGETS",
    "MARK",
    "auto_instrument",
    "get",
    "instrument_client",
    "is_wrapped",
    "plain",
    "wrap",
]

log = logging.getLogger("sibyl")
MARK: Final = "__sibyl_wrapped__"
GOOGLE_PROVIDER: Final = "gcp.gen_ai"
_PARAMS: Final = {
    "temperature": "gen_ai.request.temperature",
    "top_p": "gen_ai.request.top_p",
    "top_k": "gen_ai.request.top_k",
    "max_tokens": "gen_ai.request.max_tokens",
    "max_completion_tokens": "gen_ai.request.max_tokens",
    "max_output_tokens": "gen_ai.request.max_tokens",
    "seed": "gen_ai.request.seed",
    "frequency_penalty": "gen_ai.request.frequency_penalty",
    "presence_penalty": "gen_ai.request.presence_penalty",
    "n": "gen_ai.request.choice.count",
    "candidate_count": "gen_ai.request.choice.count",
}


@dataclass(frozen=True)
class Api:
    """How one provider API is called: provider name, semconv operation, input keys."""

    name: str
    provider: str
    operation: str
    input_key: str
    system_key: str | None


APIS: Final[dict[str, Api]] = {
    a.name: a
    for a in (
        Api("openai.chat", "openai", "chat", "messages", None),
        Api("openai.responses", "openai", "chat", "input", "instructions"),
        Api("openai.embeddings", "openai", "embeddings", "input", None),
        Api("anthropic.messages", "anthropic", "chat", "messages", "system"),
        Api("google.generate_content", GOOGLE_PROVIDER, "generate_content", "contents", None),
    )
}

AUTO_TARGETS: Final[dict[str, list[tuple[str, str, str, str, bool]]]] = {
    # library: [(module, class, method, api, streaming method)]
    "openai": [
        ("openai.resources.chat.completions", "Completions", "create", "openai.chat", False),
        ("openai.resources.chat.completions", "AsyncCompletions", "create", "openai.chat", False),
        ("openai.resources.responses", "Responses", "create", "openai.responses", False),
        ("openai.resources.responses", "AsyncResponses", "create", "openai.responses", False),
        ("openai.resources.embeddings", "Embeddings", "create", "openai.embeddings", False),
        ("openai.resources.embeddings", "AsyncEmbeddings", "create", "openai.embeddings", False),
    ],
    "anthropic": [
        ("anthropic.resources.messages", "Messages", "create", "anthropic.messages", False),
        ("anthropic.resources.messages", "AsyncMessages", "create", "anthropic.messages", False),
    ],
    "google": [
        ("google.genai.models", "Models", "generate_content", "google.generate_content", False),
        (
            "google.genai.models",
            "Models",
            "generate_content_stream",
            "google.generate_content",
            True,
        ),
        (
            "google.genai.models",
            "AsyncModels",
            "generate_content",
            "google.generate_content",
            False,
        ),
        (
            "google.genai.models",
            "AsyncModels",
            "generate_content_stream",
            "google.generate_content",
            True,
        ),
    ],
}


def _config_value(config: Any, key: str) -> Any:
    return config.get(key) if isinstance(config, Mapping) else getattr(config, key, None)


class _Call:
    """One provider call: span lifecycle plus response extraction."""

    def __init__(
        self,
        client: Client,
        api: Api,
        kwargs: dict[str, Any],
        capture_mode: CaptureMode | None,
        streamed: bool,
    ) -> None:
        self.api = api
        self.model = str(kwargs.get("model", "unknown"))
        self.started = time.perf_counter()
        self.ttfb_ms: float | None = None
        self.call_id = uuid7()
        self.run = current_run()
        if self.run is not None:
            self.run.model_calls += 1
        span = client.start_span(
            f"{api.operation} {self.model}", kind=KIND_CLIENT, capture_mode=capture_mode
        )
        self.span: Span = span
        self.client = client
        span.set_many(
            {
                "gen_ai.operation.name": api.operation,
                "gen_ai.provider.name": api.provider,
                "gen_ai.request.model": self.model,
                "sibyl.call_id": str(self.call_id),
                "sibyl.task_id": str(self.run.task_id) if self.run else None,
                "sibyl.streamed": streamed,
                **tree_attributes(self.run),
            }
        )
        config = kwargs.get("config")
        for key, attr in _PARAMS.items():
            value = kwargs.get(key)
            if value is None and config is not None:
                value = _config_value(config, key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                span.set(attr, value)
        tools = kwargs.get("tools") or (_config_value(config, "tools") if config else None)
        if tools:
            span.set("gen_ai.request.tool_definitions_count", len(tools))
        self._capture_input(kwargs, config)

    def _capture_input(self, kwargs: dict[str, Any], config: Any) -> None:
        api, span = self.api, self.span
        value = kwargs.get(api.input_key)
        if api.operation == "embeddings":
            span.add_content("gen_ai.input.messages", "input_messages", plain(value))
            return
        span.add_content("gen_ai.input.messages", "input_messages", plain(value))
        system = kwargs.get(api.system_key) if api.system_key else None
        if system is None and config is not None:
            system = _config_value(config, "system_instruction")
        if system is not None:
            span.add_content("gen_ai.system_instructions", "system_instructions", plain(system))

    def _ours(self) -> dict[str, str]:
        mode = str(self.span.attributes.get("sibyl.capture.mode", "full"))
        ours: dict[str, str] = {
            "traceparent": f"00-{self.span.trace_id}-{self.span.span_id}-01",
            "X-Sibyl-Call-Id": str(self.call_id),
            "X-Sibyl-Capture-Owner": "sdk" if mode in ("full", "redacted") else "gateway",
        }
        agent = self.client.agent_header()
        if agent:
            ours["X-Sibyl-Agent"] = agent
        if self.run is not None:
            ours["X-Sibyl-Task-Id"] = str(self.run.task_id)
        snap = self.client.snapshot
        if snap is not None:
            ours["X-Sibyl-Policy-Version"] = str(snap.policy_version)
        obo = _obo.header_value()
        if obo is not None:
            ours[_obo.HEADER] = obo
        return ours

    def headers(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        ours = self._ours()
        if self.api.provider == GOOGLE_PROVIDER:
            return _google_headers(kwargs, ours)
        user = kwargs.get("extra_headers") or {}
        return {**kwargs, "extra_headers": {**ours, **dict(user)}}

    def first_chunk(self) -> None:
        if self.ttfb_ms is None:
            self.ttfb_ms = (time.perf_counter() - self.started) * 1000
            self.span.set("sibyl.ttfb_ms", round(self.ttfb_ms, 3))

    def fail(self, exc: BaseException) -> None:
        status = get(exc, "status_code") or get(exc, "code")
        if isinstance(status, int) and 100 <= status <= 599:
            self.span.set("http.response.status_code", status)
        self.span.set_error(type(exc).__name__, str(exc)[:256])
        self.span.end()

    def finish(self, response: Any) -> None:
        span = self.span
        try:
            found = extract(self.api.name, response)
        except Exception:  # extraction never breaks the application's call
            log.exception("sibyl: could not read the %s response", self.api.name)
            span.end()
            return
        span.set_many(found.span_attributes())
        if self.api.operation != "embeddings" and found.output is not None:
            span.add_content("gen_ai.output.messages", "output_messages", found.output)
        span.end()


def _google_headers(kwargs: dict[str, Any], ours: dict[str, str]) -> dict[str, Any]:
    """google-genai takes headers in `config.http_options.headers`; only dict configs (or no
    config) are rewritten, a typed config object is left untouched."""
    config = kwargs.get("config")
    if config is not None and not isinstance(config, Mapping):
        return kwargs
    base = dict(config or {})
    http = base.get("http_options") or {}
    if not isinstance(http, Mapping):
        return kwargs
    headers = {**ours, **dict(http.get("headers") or {})}
    return {**kwargs, "config": {**base, "http_options": {**dict(http), "headers": headers}}}


class _StreamProxy:
    """Wraps a sync or async provider stream; ends the span exactly once."""

    def __init__(self, stream: Any, call: _Call) -> None:
        self._stream = stream
        self._call = call
        self._acc = Accumulator(call.api.name)
        self._done = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    def _end(self, exc: BaseException | None = None) -> None:
        if self._done:
            return
        self._done = True
        if exc is not None:
            self._call.fail(exc)
        else:
            self._call.finish(self._acc.response())

    def _take(self, chunk: Any) -> Any:
        self._call.first_chunk()
        try:
            self._acc.add(chunk)
        except Exception:  # a malformed chunk must not break the stream
            log.debug("sibyl: unreadable stream chunk ignored", exc_info=True)
        return chunk

    def __iter__(self) -> _StreamProxy:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
        except StopIteration:
            self._end()
            raise
        except BaseException as exc:
            self._end(exc)
            raise
        return self._take(chunk)

    def __aiter__(self) -> _StreamProxy:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
        except StopAsyncIteration:
            self._end()
            raise
        except BaseException as exc:
            self._end(exc)
            raise
        return self._take(chunk)

    def close(self) -> None:
        self._end()
        closer = getattr(self._stream, "close", None)
        if callable(closer):
            closer()

    def __enter__(self) -> _StreamProxy:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def __aenter__(self) -> _StreamProxy:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._end()
        closer = getattr(self._stream, "aclose", None) or getattr(self._stream, "close", None)
        if callable(closer):
            result = closer()
            if inspect.isawaitable(result):
                await result


def wrap(
    original: Callable[..., Any],
    api: str,
    capture_mode: CaptureMode | None = None,
    *,
    streaming: bool = False,
) -> Callable[..., Any]:
    """Wrap a provider call (bound or unbound, sync or async). Idempotent. `streaming` marks
    a method that always returns a stream (google `generate_content_stream`)."""
    if getattr(original, MARK, False):
        return original
    spec = APIS[api]
    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            client = _state.get()
            if client is None:
                return await original(*args, **kwargs)
            client.policy.check()
            streamed = streaming or bool(kwargs.get("stream"))
            call = _Call(client, spec, kwargs, capture_mode, streamed)
            try:
                result = await original(*args, **call.headers(kwargs))
            except BaseException as exc:
                call.fail(exc)
                raise
            if streamed:
                return _StreamProxy(result, call)
            call.finish(result)
            return result

        setattr(async_wrapper, MARK, True)
        return async_wrapper

    @functools.wraps(original)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        client = _state.get()
        if client is None:
            return original(*args, **kwargs)
        client.policy.check()
        streamed = streaming or bool(kwargs.get("stream"))
        call = _Call(client, spec, kwargs, capture_mode, streamed)
        try:
            result = original(*args, **call.headers(kwargs))
        except BaseException as exc:
            call.fail(exc)
            raise
        if streamed:
            return _StreamProxy(result, call)
        call.finish(result)
        return result

    setattr(sync_wrapper, MARK, True)
    return sync_wrapper


def _patch(
    resource: Any,
    method: str,
    api: str,
    capture_mode: CaptureMode | None,
    *,
    streaming: bool = False,
) -> bool:
    target = getattr(resource, method, None)
    if target is None or not callable(target):
        return False
    if getattr(target, MARK, False):
        return True
    setattr(resource, method, wrap(target, api, capture_mode, streaming=streaming))
    return True


def _module_root(obj: Any) -> str:
    return type(obj).__module__.split(".", 1)[0]


def _patch_google(models: Any, capture_mode: CaptureMode | None) -> bool:
    patched = _patch(models, "generate_content", "google.generate_content", capture_mode)
    _patch(
        models, "generate_content_stream", "google.generate_content", capture_mode, streaming=True
    )
    return patched


def instrument_client(client: Any, *, capture_mode: CaptureMode | None = None) -> Any:
    """Explicitly wrap an OpenAI, Anthropic or google-genai client instance (idempotent)."""
    root = _module_root(client)
    patched = False
    completions = get(client, "chat", "completions")
    if completions is not None and root != "anthropic":
        patched |= _patch(completions, "create", "openai.chat", capture_mode)
        for attr, api in (("embeddings", "openai.embeddings"), ("responses", "openai.responses")):
            resource = get(client, attr)
            if resource is not None:
                _patch(resource, "create", api, capture_mode)
    elif get(client, "responses") is not None and root != "anthropic":
        patched |= _patch(get(client, "responses"), "create", "openai.responses", capture_mode)
    messages = get(client, "messages")
    if messages is not None and get(client, "chat") is None:
        patched |= _patch(messages, "create", "anthropic.messages", capture_mode)
    models = get(client, "models")
    if models is not None and callable(get(models, "generate_content")):
        patched |= _patch_google(models, capture_mode)
        aio_models = get(client, "aio", "models")
        if aio_models is not None:
            _patch_google(aio_models, capture_mode)
    if not patched:
        _state.warn_once(
            f"instrument:{type(client).__name__}",
            f"instrument(): {type(client).__name__} is not a known client",
        )
    return client


def auto_instrument(libraries: tuple[str, ...]) -> list[str]:
    """Patch importable provider SDK classes; returns the `module.Class.method` names patched."""
    patched: list[str] = []
    for library in libraries:
        for module_name, class_name, method, api, streaming in AUTO_TARGETS.get(library, []):
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                continue
            except Exception:  # a broken optional install must not break the application
                log.warning("sibyl: could not import %s; not instrumented", module_name)
                continue
            cls = getattr(module, class_name, None)
            original = getattr(cls, method, None) if cls is not None else None
            if original is None or getattr(original, MARK, False):
                continue
            setattr(cls, method, wrap(original, api, streaming=streaming))
            patched.append(f"{module_name}.{class_name}.{method}")
    return patched


def is_wrapped(library: str) -> bool:
    """True when at least one of the library's targets is currently wrapped."""
    for module_name, class_name, method, _api, _streaming in AUTO_TARGETS.get(library, []):
        module = sys.modules.get(module_name)
        target = getattr(getattr(module, class_name, None), method, None)
        if target is not None and getattr(target, MARK, False):
            return True
    return False
