"""Tier gating for predicted failovers (ML.md §4.5-§4.6; D13, D36, D39/R40, R41).

A 15-minute prediction crosses the gate when

* its band reaches the tier's minimum band: ``"0.60"`` on tier 1 (an approval request, D13);
  on tiers 2-3 ``"0.90"`` until the R41/D36 release gate is open, then ``"0.60"``;
* its confidence is at least ``min_confidence`` (``medium``);
* its contributing rules span at least ``min_rule_families`` (2) SLI families.

The release gate has one source (B20): the deployment setting
``SIBYL_PREDICTED_AUTOMATION_BAND`` (``Settings.predicted_automation_band``), set to ``"0.60"``
only from harness evidence (precision >= 0.75 and recall >= 0.60 at 15 m). It is a release
criterion, never tenant-tunable: whatever a tenant's ``scoring_config`` says about the band or
its evidence is ignored here, exactly as the saga ignores it (``worker.saga.runner.worker_env``).

The effective mode is what lane S executes: tier 1 is always ``approval`` (predictions never
auto-act on tier 1, whatever the plan says); tiers 2-3 use the plan's ``preemptive_mode``
(seeded ``degrade_then_auto`` / ``auto``) unless the agent's persisted pre-emptive breaker is
tripped (``agent.preemptive_breaker_tripped_at``, see ``breaker``), which forces ``approval``
until a human clears it.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol
from uuid import UUID

from .bands import band_at_least, confidence_at_least

if TYPE_CHECKING:
    from ...core.settings import Settings

log = logging.getLogger("sibyl.worker.predict")

PreemptiveMode = Literal["approval", "degrade_then_auto", "auto"]
PREEMPTIVE_MODES: tuple[str, ...] = ("approval", "degrade_then_auto", "auto")
TIER1_BAND = "0.60"
CLOSED_BAND = "0.90"
RELEASE_BAND = "0.60"
SAGA_TARGET = "sibyl_control.worker.saga:request_predicted_failover"


class PredictedFailoverRequester(Protocol):
    """Lane S's saga entry for a predicted failover (wired by the chair at merge).

    Called inside the predict loop's tenant transaction, once per gate crossing (rising edge)
    of an agent's 15-minute prediction. ``mode`` is the effective preemptive mode decided here
    (tier gating and the per-agent breaker); S applies D21 (operator hold), D22 (forced hold on
    tier-1 PII/residency agents at approval timeout), viability and ``saga_in_flight``. Returns
    the ``failover`` id it created or joined, or ``None`` when it declined. ``settings`` is the
    worker's ``Settings`` (the D36 band and the saga gates come from it, B20).
    """

    async def __call__(
        self,
        conn: Any,
        tenant_id: UUID,
        agent_id: UUID,
        prediction_id: UUID,
        horizon: str,
        band: str,
        confidence: str,
        *,
        mode: PreemptiveMode,
        settings: Settings,
    ) -> UUID | None: ...


@dataclass(frozen=True)
class GateConfig:
    tier1_band: str = TIER1_BAND
    tiers23_band: str = CLOSED_BAND
    min_confidence: str = "medium"
    min_families: int = 2
    release_open: bool = False


def gate_config(scoring: Mapping[str, Any], settings: Settings) -> GateConfig:
    """The gate: the D36 band from ``settings`` (B20), the floors from the scoring config."""
    auto = scoring.get("automation") or {}
    release_open = settings.predicted_automation_band == RELEASE_BAND
    return GateConfig(
        tier1_band=TIER1_BAND,
        tiers23_band=RELEASE_BAND if release_open else CLOSED_BAND,
        min_confidence=str(auto.get("min_confidence", "medium")),
        min_families=int(auto.get("min_rule_families", 2)),
        release_open=release_open,
    )


def min_band(tier: int, gc: GateConfig) -> str:
    return gc.tier1_band if tier == 1 else gc.tiers23_band


def qualifies(tier: int, band: str, confidence: str, families: int, gc: GateConfig) -> bool:
    return (
        band_at_least(band, min_band(tier, gc))
        and confidence_at_least(confidence, gc.min_confidence)
        and families >= gc.min_families
    )


def effective_mode(tier: int, plan_mode: str | None, breaker_tripped: bool) -> PreemptiveMode:
    if tier == 1 or breaker_tripped:
        return "approval"
    if plan_mode == "auto":
        return "auto"
    if plan_mode == "approval":
        return "approval"
    return "degrade_then_auto"


# ---------------------------------------------------------------------- the S entry

_REQUESTER: PredictedFailoverRequester | None = None
_RESOLVED = False


def set_failover_requester(requester: PredictedFailoverRequester | None) -> None:
    """Install lane S's entry (tests install a fake; ``None`` restores lazy resolution)."""
    global _REQUESTER, _RESOLVED
    _REQUESTER = requester
    _RESOLVED = requester is not None


def failover_requester() -> PredictedFailoverRequester | None:
    """The installed requester, else ``worker.saga.request_predicted_failover`` once S lands."""
    global _REQUESTER, _RESOLVED
    if not _RESOLVED:
        module_name, _, attr = SAGA_TARGET.partition(":")
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if not (exc.name and module_name.startswith(exc.name)):
                raise
            module = None
        _REQUESTER = getattr(module, attr, None) if module is not None else None
        _RESOLVED = True
        if _REQUESTER is None:
            log.warning(
                "no predicted-failover saga entry yet (%s); gate crossings logged", SAGA_TARGET
            )
    return _REQUESTER
