"""LangChain / LangGraph: a global callback handler (installed through LangChain's configure
hook, so every runnable picks it up without passing `callbacks=`).

Run-tree mapping:
* the outermost chain (graph) is a run (`invoke_agent`), nested under any open
  `sibyl.agent()` block;
* a LangGraph node (`metadata.langgraph_node` equals the chain name) is a child run whose
  `step_index` is the graph's `langgraph_step` (0-based);
* other chains are transparent: their calls attach to the nearest run;
* tools are `execute_tool` spans; a `transfer_to_<agent>` tool or a `Command(goto=...,
  graph=PARENT)` records `handoff_to_agent`;
* models: calls through an instrumented OpenAI/Anthropic client are captured by the client
  wrapper (nested under the node); other providers get a `gen_ai` span from `LLMResult`.

Action Gate: `on_tool_start` runs the pre-execution check; the handler sets `raise_error`,
so a blocked, denied or held call propagates and the tool never runs.
"""

from __future__ import annotations

import logging
import threading
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Final
from uuid import UUID

from sibyl import _gate
from sibyl._errors import SibylError
from sibyl._extract import Extracted, get, plain
from sibyl._run import AgentRun, activate, close_run, current_run, open_run
from sibyl._spans import Span
from sibyl.integrations._common import (
    agent_ref,
    annotate,
    end_model_span,
    end_tool_span,
    is_active,
    model_span,
    safe,
    start_tool_span,
)

log = logging.getLogger("sibyl")
HANDOFF_PREFIX: Final = "transfer_to_"
CONTROL_FLOW: Final = frozenset({"GraphInterrupt", "GraphBubbleUp", "NodeInterrupt"})
_installed: dict[str, Any] = {}
_install_lock = threading.Lock()


@dataclass
class _Node:
    kind: str  # run | chain | tool | llm | skip
    run: AgentRun | None
    span: Span | None = None
    previous: AgentRun | None = None


def _name(serialized: Any, kwargs: dict[str, Any], default: str) -> str:
    name = kwargs.get("name") or get(serialized, "name")
    if not name:
        ident = get(serialized, "id")
        name = ident[-1] if isinstance(ident, list) and ident else None
    return str(name or default)[:256]


def _provider(serialized: Any, kwargs: dict[str, Any]) -> str:
    ident = get(serialized, "id")
    path = " ".join(str(p) for p in ident).lower() if isinstance(ident, list) else ""
    params = kwargs.get("invocation_params") or {}
    kind = str(get(params, "_type") or "").lower()
    for provider in ("anthropic", "openai", "google", "ollama", "bedrock", "mistral", "cohere"):
        if provider in path or provider in kind:
            return provider
    return kind or "unknown"


def _model(kwargs: dict[str, Any]) -> str:
    params = kwargs.get("invocation_params") or {}
    meta = kwargs.get("metadata") or {}
    for value in (
        get(params, "model"),
        get(params, "model_name"),
        get(meta, "ls_model_name"),
    ):
        if value:
            return str(value)[:256]
    return "unknown"


def _llm_extracted(response: Any) -> Extracted:
    out = Extracted()
    llm_output = get(response, "llm_output") or {}
    usage = get(llm_output, "token_usage") or get(llm_output, "usage") or {}
    out.response_model = get(llm_output, "model_name") or get(llm_output, "model")
    out.system_fingerprint = get(llm_output, "system_fingerprint")
    out.input_tokens = get(usage, "prompt_tokens") or get(usage, "input_tokens")
    out.output_tokens = get(usage, "completion_tokens") or get(usage, "output_tokens")
    outputs: list[dict[str, Any]] = []
    for batch in get(response, "generations") or []:
        for gen in batch or []:
            info = get(gen, "generation_info") or {}
            reason = get(info, "finish_reason") or get(info, "stop_reason")
            if reason:
                out.finish_reasons.append(str(reason).lower())
            message = get(gen, "message")
            meta = get(message, "usage_metadata")
            if meta is not None and out.input_tokens is None:
                out.input_tokens = get(meta, "input_tokens")
                out.output_tokens = get(meta, "output_tokens")
            for call in get(message, "tool_calls") or []:
                out.add_tool(get(call, "id"), get(call, "name"))
            if get(message, "additional_kwargs", "refusal"):
                out.refusal = True
            outputs.append({"role": "assistant", "content": get(gen, "text")})
    out.output = outputs
    return out


class _Tracer:
    """The handler's behaviour; mixed into `BaseCallbackHandler` by `make_handler()`."""

    raise_error = True  # Action Gate errors from on_tool_start must reach LangChain
    run_inline = True  # same context as the runnable: client calls nest under the run

    def __init__(self) -> None:
        self._nodes: dict[UUID, _Node] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ helpers

    def _parent_run(self, parent_run_id: UUID | None) -> AgentRun | None:
        with self._lock:
            node = self._nodes.get(parent_run_id) if parent_run_id else None
        return node.run if node is not None else current_run()

    def _put(self, run_id: UUID, node: _Node) -> None:
        with self._lock:
            self._nodes[run_id] = node

    def _pop(self, run_id: UUID) -> _Node | None:
        with self._lock:
            return self._nodes.pop(run_id, None)

    # ------------------------------------------------------------------ chains

    @safe
    def on_chain_start(
        self,
        serialized: Any,
        inputs: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        name = _name(serialized, kwargs, "chain")
        meta = metadata or {}
        with self._lock:
            parent = self._nodes.get(parent_run_id) if parent_run_id else None
        is_node = meta.get("langgraph_node") == name and parent is not None
        if parent is not None and not is_node:
            self._put(run_id, _Node("chain", parent.run))
            return
        step = meta.get("langgraph_step") if is_node else None
        parent_run = parent.run if parent is not None else current_run()
        run = open_run(
            name,
            parent=parent_run,
            step_index=step if isinstance(step, int) and step >= 0 else None,
        )
        self._put(run_id, _Node("run", run, previous=current_run()))
        activate(run)

    def _end_chain(self, run_id: UUID, error: BaseException | None) -> None:
        node = self._pop(run_id)
        if node is None or node.kind != "run" or node.run is None:
            return
        kind = type(error).__name__ if error is not None else ""
        if kind == "ParentCommand":
            goto = get(error, "args", 0, "goto")
            target = goto[0] if isinstance(goto, (list, tuple)) and goto else goto
            ref = agent_ref(get(target, "node") or target)
            if ref:
                node.run.handoff_to(ref)
            error = None
        elif kind in CONTROL_FLOW:
            error = None
        close_run(node.run, error=error)
        activate(node.previous)

    @safe
    def on_chain_end(self, outputs: Any, *, run_id: UUID, **kwargs: Any) -> None:
        self._end_chain(run_id, None)

    @safe
    def on_chain_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        self._end_chain(run_id, error)

    # ------------------------------------------------------------------ tools

    def on_tool_start(
        self,
        serialized: Any,
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            name = _name(serialized, kwargs, "tool")
            run = self._parent_run(parent_run_id)
            handoff = (
                agent_ref(name[len(HANDOFF_PREFIX) :]) if name.startswith(HANDOFF_PREFIX) else None
            )
            if handoff and run is not None:
                run.handoff_to(handoff)
            args = inputs if inputs is not None else input_str
            call_id = get(kwargs.get("metadata"), "tool_call_id") or kwargs.get("tool_call_id")
            span = start_tool_span(run, name, plain(args), call_id=call_id, handoff_to=handoff)
            self._put(run_id, _Node("tool", run, span))
        except Exception:
            log.debug("sibyl: langchain on_tool_start failed", exc_info=True)
            return
        try:
            verdict = _gate.gate(name, args, call_id=call_id)
        except SibylError as exc:
            annotate(span, exc)
            self._pop(run_id)
            end_tool_span(span, error=exc)
            raise
        annotate(span, verdict)

    @safe
    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> None:
        node = self._pop(run_id)
        if node is not None:
            end_tool_span(node.span, result=plain(get(output, "content") or output))

    @safe
    def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        node = self._pop(run_id)
        if node is not None:
            end_tool_span(node.span, error=error)

    # ------------------------------------------------------------------ models

    def _model_start(
        self,
        serialized: Any,
        inputs: Any,
        run_id: UUID,
        parent_run_id: UUID | None,
        kwargs: dict[str, Any],
    ) -> None:
        provider = _provider(serialized, kwargs)
        run = self._parent_run(parent_run_id)
        if provider in ("openai", "anthropic") and is_active(provider):
            self._put(run_id, _Node("skip", run))  # the client wrapper records this call
            return
        span = model_span(run, provider=provider, model=_model(kwargs), inputs=plain(inputs))
        self._put(run_id, _Node("llm", run, span))

    @safe
    def on_chat_model_start(
        self,
        serialized: Any,
        messages: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._model_start(serialized, messages, run_id, parent_run_id, kwargs)

    @safe
    def on_llm_start(
        self,
        serialized: Any,
        prompts: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._model_start(serialized, prompts, run_id, parent_run_id, kwargs)

    @safe
    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        node = self._pop(run_id)
        if node is not None and node.kind == "llm":
            end_model_span(node.span, _llm_extracted(response))

    @safe
    def on_llm_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        node = self._pop(run_id)
        if node is not None and node.kind == "llm":
            end_model_span(node.span, None, error=error)


def make_handler() -> Any:
    """A `BaseCallbackHandler` instance (needs `langchain_core`)."""
    from langchain_core.callbacks import BaseCallbackHandler

    cls = type("SibylCallbackHandler", (_Tracer, BaseCallbackHandler), {})
    return cls()


def install() -> bool:
    """Register the handler for every LangChain run in the process (idempotent)."""
    with _install_lock:
        if "handler" in _installed:
            return True
        from langchain_core.tracers.context import register_configure_hook

        handler = make_handler()
        var: ContextVar[Any] = ContextVar("sibyl_langchain_handler", default=handler)
        register_configure_hook(var, True)
        _installed.update(handler=handler, var=var)
    return True


def handler() -> Any | None:
    """The installed handler (pass it as `callbacks=[...]` where hooks are disabled)."""
    return _installed.get("handler")


def uninstall() -> None:
    """Tests only: stop tracing new LangChain runs."""
    var = _installed.pop("var", None)
    _installed.pop("handler", None)
    if var is not None:
        var.set(None)
