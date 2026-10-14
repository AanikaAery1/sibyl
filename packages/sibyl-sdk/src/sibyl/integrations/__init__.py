"""Plug-and-play instrumentation (D50): detect installed libraries and instrument each one.

Every integration is optional and import-guarded: a library that is not installed is
skipped, and one that fails to instrument is logged and skipped (never raised). Install
extras with `pip install "sibyl-sdk[openai,langchain]"` (or `[all]`).

| name            | detects (module)  | what is captured                                     |
|-----------------|-------------------|------------------------------------------------------|
| `openai`        | `openai`          | chat completions, responses, embeddings (sync+async) |
| `anthropic`     | `anthropic`       | messages (sync+async, streaming, tool_use)           |
| `google`        | `google.genai`    | `generate_content` / `_stream` (sync+async)           |
| `langchain`     | `langchain_core`  | LangChain + LangGraph callback handler (global)      |
| `openai_agents` | `agents.tracing`  | OpenAI Agents SDK tracing processor + tool gate      |
| `crewai`        | `crewai`          | CrewAI event listener + tool gate                    |
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from collections.abc import Callable, Iterable
from typing import Final

from sibyl.integrations._common import is_active, mark_active

log = logging.getLogger("sibyl")

MODEL_CLIENTS: Final = ("openai", "anthropic", "google")
FRAMEWORKS: Final = ("langchain", "openai_agents", "crewai")
LIBRARIES: Final = (*MODEL_CLIENTS, *FRAMEWORKS)
ALIASES: Final = {
    "openai-agents": "openai_agents",
    "google-genai": "google",
    "langgraph": "langchain",
}
DETECT: Final = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "google.genai",
    "langchain": "langchain_core",
    "openai_agents": "agents.tracing",
    "crewai": "crewai",
}


def canonical(name: str) -> str:
    return ALIASES.get(name, name)


def installed(library: str) -> bool:
    module = DETECT[canonical(library)]
    if module in sys.modules:
        return sys.modules[module] is not None
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _instrument_models(library: str) -> bool:
    from sibyl._instrument import auto_instrument, is_wrapped

    auto_instrument((library,))
    return is_wrapped(library)


def _instrument_framework(library: str) -> bool:
    module = importlib.import_module(f"sibyl.integrations.{library}")
    install: Callable[[], bool] = module.install
    return install()


def instrument_libraries(libraries: Iterable[str]) -> list[str]:
    """Instrument every named library that is installed; returns the names now active.
    Idempotent: a library already instrumented is reported but not patched again."""
    done: list[str] = []
    for raw in libraries:
        name = canonical(raw)
        if name not in LIBRARIES:
            continue
        if name in FRAMEWORKS and is_active(name):
            done.append(name)
            continue
        if not installed(name):
            continue
        try:
            ok = _instrument_models(name) if name in MODEL_CLIENTS else _instrument_framework(name)
        except Exception:
            log.warning("sibyl: could not instrument %s; continuing without it", name)
            log.debug("sibyl: %s instrumentation failure", name, exc_info=True)
            continue
        if ok:
            mark_active(name)
            done.append(name)
    return done


__all__ = ["FRAMEWORKS", "LIBRARIES", "MODEL_CLIENTS", "installed", "instrument_libraries"]
