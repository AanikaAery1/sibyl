"""Tier gating, pure (ML.md §4.5-§4.6, API.md §6.5; D13, D22, D36, D39, R36, R40, R41).

Two questions, answered without a database so they can be tested exhaustively:

* ``approval_for`` — does this target step need a human approval before routing moves?
  Detected failures: only a tier-1 ``backup_agent`` hop (always, even on detected failure).
  Predicted failures: tier 1 (or ``preemptive_mode=approval``, or the per-agent breaker) needs
  approval for an alternate provider or a backup agent; an alternate model on the same provider,
  safe mode and the human queue are automatic on every tier. Operator-initiated: a tier-1
  ``backup_agent`` hop needs a second human (four-eyes, R36).
* ``decide_predicted`` — what a 15-minute prediction does: nothing, a ``watch``, ``degrade`` only,
  ``degrade_then_auto`` (tier 2 by default: degraded now, failover after 20 s if it persists), an
  automatic saga, or an approval saga.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

BANDS: tuple[str, ...] = ("0.05", "0.25", "0.60", "0.90")
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
APPROVAL_BAND = "0.60"  # tier-1 approval requests start here (ML §4.5)
SAGA_HORIZON_S = 900  # 1 h and 24 h horizons never trigger a saga in Phase 1
AUTOMATIC_STEP_KINDS: frozenset[str] = frozenset(
    {"retry", "alt_model_same_provider", "degraded_safe_mode", "human_queue"}
)
BREAKER_THRESHOLD = 2  # ML §4.6 guard rail 5: two undone / fp automated transitions in 7 d

# Leading rule -> signal family; "two families" means two independent kinds of evidence.
RULE_FAMILY = {
    "error_trend": "errors",
    "latency_trend": "latency",
    "ratelimit_proximity": "capacity",
    "fallback_pressure": "capacity",
    "budget_proximity": "cost",
    "refusal_trend": "quality",
    "context_saturation": "quality",
    "drift_cusum": "quality",
    "credential_expiry": "config",
    "model_deprecation": "config",
    "continuity_unverified": "continuity",
    "provider_status": "provider",
}


def band_rank(band: str) -> int:
    return BANDS.index(band) if band in BANDS else -1


def at_least(band: str, floor: str) -> bool:
    return band_rank(band) >= band_rank(floor)


def families(rules: Iterable[str]) -> frozenset[str]:
    return frozenset(RULE_FAMILY.get(code, code) for code in rules)


def approval_for(
    *,
    tier: int,
    trigger: str,
    actor_kind: str,
    step_kind: str,
    preemptive_mode: str = "auto",
    breaker_open: bool = False,
) -> str | None:
    """The ``approval.requested_action`` this hop needs, or ``None`` when it is automatic."""
    if step_kind == "backup_agent" and tier == 1:
        return "backup_agent_failover"
    if actor_kind == "human" or trigger != "predicted":
        return None
    if step_kind in AUTOMATIC_STEP_KINDS:
        return None
    if tier == 1 or preemptive_mode == "approval" or breaker_open:
        return (
            "alt_provider_failover"
            if step_kind == "alt_provider"
            else ("backup_agent_failover" if step_kind == "backup_agent" else "preemptive_failover")
        )
    return None


@dataclass(frozen=True)
class PredictedDecision:
    action: str  # none | watch | degrade | degrade_then_auto | saga | approval
    reason: str
    mode: str | None = None  # effective preemptive_mode


def effective_mode(tier: int, preemptive_mode: str | None, breaker_open: bool) -> str:
    if breaker_open or tier == 1:
        return "approval"
    if preemptive_mode in ("auto", "degrade_then_auto", "approval"):
        return preemptive_mode
    return "degrade_then_auto" if tier == 2 else "auto"


def decide_predicted(
    *,
    tier: int,
    horizon_s: int,
    band: str,
    confidence: str,
    contributing_rules: Iterable[str],
    preemptive_mode: str | None,
    breaker_open: bool = False,
    automation_band: str = "0.90",
) -> PredictedDecision:
    """ML.md §4.5 table, with the D36 release gate as ``automation_band`` (tiers 2-3)."""
    if horizon_s != SAGA_HORIZON_S:
        return PredictedDecision("none", "only the 15 m horizon can open a saga in Phase 1")
    fams = families(contributing_rules)
    medium = CONFIDENCE_RANK.get(confidence, 0) >= CONFIDENCE_RANK["medium"]
    strong = at_least(band, APPROVAL_BAND) and medium and len(fams) >= 2
    mode = effective_mode(tier, preemptive_mode, breaker_open)
    if tier == 1:
        if strong:
            return PredictedDecision("approval", "tier 1 predicted failover needs approval", mode)
        if at_least(band, "0.25"):
            return PredictedDecision("watch", "evidence below the tier-1 approval gate", mode)
        return PredictedDecision("none", "band below watch", mode)
    automatable = strong and at_least(band, automation_band)
    if automatable:
        if mode == "approval":
            return PredictedDecision(
                "approval", "per-agent breaker or plan asks for approval", mode
            )
        if mode == "degrade_then_auto":
            return PredictedDecision(
                "degrade_then_auto", "D39 degraded now, failover in 20 s", mode
            )
        return PredictedDecision("saga", "tier automation", mode)
    if at_least(band, APPROVAL_BAND):
        why = (
            "below the D36 automation gate"
            if strong
            else "low confidence or a single rule family: degrade only"
        )
        return PredictedDecision("degrade", why, mode)
    if at_least(band, "0.25"):
        return PredictedDecision("watch", "watch band", mode)
    return PredictedDecision("none", "band below watch", mode)
