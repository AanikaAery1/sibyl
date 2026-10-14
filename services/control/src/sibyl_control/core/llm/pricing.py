"""Cost estimation from a small price table (USD per million tokens).

Exact-match lookup on ``(provider, model)``, then the longest matching model prefix. A model
not in the table is priced at ``FALLBACK`` (the most expensive row), flagged ``estimated``, so a
daily budget still binds when a tenant runs a model we have no price for; a tenant may set its
own prices on the Sentinel config instead. Costs are ``Decimal`` USD rounded **up** to 1e-6.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from typing import Final

from .types import Usage

MTOK: Final = Decimal(1_000_000)
QUANTUM: Final = Decimal("0.000001")


@dataclass(frozen=True)
class Price:
    input_per_mtok: Decimal
    output_per_mtok: Decimal
    estimated: bool = False


def _p(i: str, o: str) -> Price:
    return Price(Decimal(i), Decimal(o))


# Anthropic first-party list prices (claude-api reference, cached 2026-10-06). OpenAI and Gemini
# prices change often and are not pinned here: they fall back unless the tenant sets its own.
PRICES: Final[Mapping[tuple[str, str], Price]] = {
    ("anthropic", "claude-fable-5-1"): _p("10", "50"),
    ("anthropic", "claude-fable-5"): _p("10", "50"),
    ("anthropic", "claude-opus-5-5"): _p("4", "20"),
    ("anthropic", "claude-opus-5"): _p("5", "25"),
    ("anthropic", "claude-opus-4-8"): _p("5", "25"),
    ("anthropic", "claude-sonnet-5-5"): _p("2", "10"),
    ("anthropic", "claude-sonnet-5"): _p("2", "10"),
    ("anthropic", "claude-sonnet-4-6"): _p("3", "15"),
    ("anthropic", "claude-haiku-5-5"): _p("0.10", "0.50"),
    ("anthropic", "claude-haiku-4-5"): _p("1", "5"),
}
FALLBACK: Final = Price(Decimal("10"), Decimal("50"), estimated=True)


def price_for(
    provider: str,
    model: str,
    *,
    override: Price | None = None,
    table: Mapping[tuple[str, str], Price] = PRICES,
) -> Price:
    if override is not None:
        return override
    exact = table.get((provider, model))
    if exact is not None:
        return exact
    candidates = [
        (len(m), p) for (prov, m), p in table.items() if prov == provider and model.startswith(m)
    ]
    if candidates:
        return max(candidates, key=lambda c: c[0])[1]
    return FALLBACK


def cost_usd(usage: Usage, price: Price) -> Decimal:
    raw = (
        Decimal(usage.input_tokens) * price.input_per_mtok
        + Decimal(usage.output_tokens) * price.output_per_mtok
    ) / MTOK
    return raw.quantize(QUANTUM, rounding=ROUND_CEILING)


def estimate_tokens(text: str) -> int:
    """A deliberately high token estimate for budget reservation (~3 chars per token)."""
    return len(text) // 3 + 16
