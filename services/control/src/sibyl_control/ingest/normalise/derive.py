"""Step 8: derived fields. ``cost_usd`` is never trusted from the wire; it is priced here from
the tenant's ``model`` rows, falling back to the platform ``model_catalog``."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

_PER_MILLION = Decimal(1_000_000)
_COST_QUANTUM = Decimal("0.00000001")


@dataclass(frozen=True)
class Price:
    input_per_1m: Decimal | None
    output_per_1m: Decimal | None
    cached_input_per_1m: Decimal | None
    source: str
    context_window: int | None = None


def error_class(attrs: dict[str, Any], event_type: str) -> str | None:
    status = attrs.get("status")
    http = attrs.get("http_status")
    error_type = str(attrs.get("error_type") or "").lower()
    if event_type == "policy.decision" and attrs.get("action") in (
        "block",
        "blocked",
        "deny",
        "kill",
    ):
        return "blocked"
    if status != "error":
        return None
    if http == 429 or ("rate" in error_type and "limit" in error_type) or error_type == "429":
        return "rate_limit"
    if "timeout" in error_type or "timed out" in error_type:
        return "timeout"
    if (isinstance(http, int) and http >= 500) or (
        error_type.startswith("5") and error_type[:3].isdigit()
    ):
        return "server_error"
    if (isinstance(http, int) and 400 <= http < 500) or (
        error_type.startswith("4") and error_type[:3].isdigit()
    ):
        return "client_error"
    return "other"


def utilisation(attrs: dict[str, Any], context_window: int | None) -> None:
    context = attrs.get("context") or {}
    limit = context.get("model_context_limit") or context_window
    tokens = (attrs.get("usage") or {}).get("input_tokens")
    if limit and tokens is not None:
        attrs["context"] = {
            **context,
            "model_context_limit": int(limit),
            "utilisation": min(1.0, tokens / limit),
        }


def headroom(attrs: dict[str, Any]) -> None:
    rl = attrs.get("ratelimit")
    if not rl:
        return
    ratios = [
        rl[f"remaining_{u}"] / rl[f"limit_{u}"]
        for u in ("requests", "tokens")
        if rl.get(f"limit_{u}") and rl.get(f"remaining_{u}") is not None
    ]
    if ratios:
        attrs["ratelimit"] = {**rl, "headroom": max(0.0, min(1.0, min(ratios)))}


def cost(usage: dict[str, Any] | None, price: Price | None) -> Decimal | None:
    if not usage or price is None or price.input_per_1m is None or price.output_per_1m is None:
        return None
    tokens_in = Decimal(usage.get("input_tokens") or 0)
    tokens_out = Decimal(usage.get("output_tokens") or 0)
    cached = Decimal(usage.get("cached_input_tokens") or 0)
    total = (tokens_in - cached) * price.input_per_1m + tokens_out * price.output_per_1m
    if cached:
        total += cached * (
            price.cached_input_per_1m
            if price.cached_input_per_1m is not None
            else price.input_per_1m
        )
    return (total / _PER_MILLION).quantize(_COST_QUANTUM, rounding=ROUND_HALF_UP)


def apply(event: dict[str, Any], price: Price | None) -> tuple[str | None, Decimal | None]:
    """Mutates ``event['attrs']`` with derived values; returns (error_class, cost)."""
    attrs = event["attrs"]
    klass = error_class(attrs, event["type"])
    amount: Decimal | None = None
    if event["type"] == "gen_ai.request":
        utilisation(attrs, price.context_window if price else None)
        headroom(attrs)
        amount = cost(attrs.get("usage"), price)
        if amount is not None and price is not None:
            attrs["cost_usd"] = float(amount)
            attrs["cost_source"] = price.source
    return klass, amount
