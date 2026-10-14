"""Static facts about the rules lane P reasons over (ML.md §2.1, §4.3; Tier B1 cut).

Phase 1 ships the leading rules L1-L5 plus the provider-status leading facet (L5 restored from
the Tier B1 cut in wave 3: without it a primary outage the inline fallback absorbs is invisible);
L6-L7 and the other leading rows move to Phase 1.5 (the seed carries them, nothing evaluates them).
``horizon_s`` and ``trend_windows`` are ``alert_rule`` columns the engine's ``RuleSpec`` does not
carry, so the values from ``rules/v1`` are mirrored here.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from ..scoring.config import EngineConfig

PHASE1_LEADING: tuple[str, ...] = (
    "error_trend",
    "latency_trend",
    "ratelimit_proximity",
    "budget_proximity",
    "fallback_pressure",
)
PROVIDER_FACET = "provider_status"
TREND_WINDOWS = 3

HORIZON_KEYS: tuple[str, ...] = ("15m", "1h", "24h")
HORIZON_S: Mapping[str, int] = MappingProxyType({"15m": 900, "1h": 3600, "24h": 86400})

LEADING_HORIZON_S: Mapping[str, int] = MappingProxyType(
    {
        "error_trend": 900,
        "latency_trend": 900,
        "ratelimit_proximity": 900,
        "budget_proximity": 3600,
        "fallback_pressure": 900,
        "refusal_trend": 900,
        "context_saturation": 900,
        "credential_expiry": 86400,
        "model_deprecation": 86400,
        "continuity_unverified": 86400,
        "drift_cusum": 3600,
        PROVIDER_FACET: 900,
    }
)

_FAMILY: Mapping[str, str] = MappingProxyType(
    {
        "error_rate": "availability",
        "consecutive_failures": "availability",
        "heartbeat_missing": "availability",
        "error_trend": "availability",
        "p95_latency": "latency",
        "latency_trend": "latency",
        "ratelimit_proximity": "rate_limit_headroom",
        "fallback_pressure": "rate_limit_headroom",
        "provider_status": "budget_dependency",
        "budget_breach": "budget_dependency",
        "budget_proximity": "budget_dependency",
        "continuity_unverified": "budget_dependency",
        "credential_expiry": "budget_dependency",
        "model_deprecation": "budget_dependency",
        "refusal_share": "output_quality",
        "truncation_share": "output_quality",
        "schema_fail_share": "output_quality",
        "quality_proxy": "output_quality",
        "refusal_trend": "output_quality",
        "context_saturation": "output_quality",
        "drift_cusum": "output_quality",
        "tool_loop": "task_completion",
    }
)

# Failure mode a detected rule points at when its band carries into the horizons.
DETECTED_MODE: Mapping[str, str] = MappingProxyType(
    {
        "p95_latency": "latency_degradation",
        "consecutive_failures": "provider_outage",
        "provider_status": "provider_outage",
        "budget_breach": "cost_runaway",
        "refusal_share": "quality_collapse",
        "truncation_share": "quality_collapse",
        "schema_fail_share": "quality_collapse",
        "quality_proxy": "quality_collapse",
        "tool_loop": "infinite_loop",
    }
)


def family(code: str, cfg: EngineConfig | None = None) -> str:
    """The SLI family of ``code``: the seed's ``sli_family`` first, then the ML.md §2.1 map."""
    if cfg is not None and cfg.has_rule(code):
        declared = cfg.rule(code).sli_family
        if declared:
            return declared
    return _FAMILY.get(code, code)


def horizon_key(seconds: int) -> str:
    for key, value in HORIZON_S.items():
        if value == seconds:
            return key
    raise ValueError(f"no horizon of {seconds} s")
