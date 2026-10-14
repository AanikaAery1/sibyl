"""Shared simulator state: the three provider doubles, their status feeds and the Sentinel
LLM double."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final

from sibyl_sim.doubles.engine import Double
from sibyl_sim.doubles.sentinel_stub import SentinelStub
from sibyl_sim.status_feed.feed import ProviderFeed

Sleep = Callable[[float], Awaitable[None]]

DOUBLES: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "openai-stub": ("openai", ("gpt-5-mini", "gpt-5.4", "text-embedding-3-small")),
    "anthropic-stub": ("anthropic", ("claude-sonnet-5", "claude-haiku-4-5")),
    "ollama-stub": ("ollama", ("qwen3:32b", "llama3.3")),
}
"""B2 cut: every double, the anthropic one included, exposes the OpenAI-compatible surface."""
FEEDS: Final[dict[str, tuple[str, str]]] = {
    "openai": ("OpenAI (sim)", "openai-stub"),
    "anthropic": ("Anthropic (sim)", "anthropic-stub"),
    "ollama": ("Ollama (sim)", "ollama-stub"),
}
DEFAULT_DOUBLE: Final = "openai-stub"


@dataclass
class SimState:
    clock: Callable[[], float]
    sleep: Sleep
    seed: int
    doubles: dict[str, Double] = field(default_factory=dict)
    feeds: dict[str, ProviderFeed] = field(default_factory=dict)
    default_double: str = DEFAULT_DOUBLE
    admin_token: str | None = None
    ca_path: str | None = None
    sentinel: SentinelStub | None = None  # the Sentinel LLM double (sentinel_stub)

    def outage_at(self, double: str, when: float) -> bool:
        target = self.doubles.get(double)
        return target.outage_at(when) if target is not None else False


def build_state(
    *,
    seed: int | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Sleep = asyncio.sleep,
    default_double: str | None = None,
    admin_token: str | None = None,
) -> SimState:
    resolved_seed = seed if seed is not None else int(os.environ.get("SIBYL_SIM_SEED", "1"))
    state = SimState(
        clock=clock,
        sleep=sleep,
        seed=resolved_seed,
        default_double=default_double or os.environ.get("SIBYL_SIM_DEFAULT_DOUBLE", DEFAULT_DOUBLE),
        admin_token=(
            admin_token if admin_token is not None else os.environ.get("SIBYL_SIM_ADMIN_TOKEN")
        )
        or None,
    )
    state.sentinel = SentinelStub.from_env(resolved_seed, clock)
    if state.default_double not in DOUBLES:
        raise ValueError(f"unknown default double {state.default_double!r}")
    for name, (provider, models) in DOUBLES.items():
        state.doubles[name] = Double(
            name, models, seed=resolved_seed, clock=clock, provider=provider
        )
    for provider, (page, double) in FEEDS.items():
        feed = ProviderFeed(
            provider=provider, page_name=page, clock=clock, outage_at=state.outage_at
        )
        feed.configure({"link_double": double})
        state.feeds[provider] = feed
    return state
