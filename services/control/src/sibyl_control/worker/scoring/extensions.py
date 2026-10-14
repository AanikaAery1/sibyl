"""Extension points for lane P (leading rules L1-L7 and horizons, wave 2).

Lane P registers implementations at import time; the scoring tick consults them every tick.
Nothing in lane H depends on P: with nothing registered, no leading factors are scored and
``health_snapshot.horizons`` is ``{}``.

* ``LeadingEvaluator``: returns ``RuleOutcome``s with ``kind="leading"`` for one agent. They are
  scored with the same ``cap x severity`` arithmetic, use the ``worsen_leading`` band
  hysteresis when they are the only penalties, are ignored while the agent is provisional, and
  fire/resolve alerts through the same per-rule hysteresis as detected rules.
* ``PrepareHook``: ``await prepare(conn, tenant, now)`` runs once per tenant tick right after
  ``load_tenant`` (same connection, same ``now``) and before any agent is evaluated, so lane P can
  load its per-tenant feed (trend state, budgets) that the leading evaluator reads.
* ``HorizonPredictor``: returns ``(horizons, predicted_failure_mode)`` for the snapshot, in the
  frozen ``sibyl-health/1`` ``horizons`` shape. A change of any horizon band is a "change" for
  the write-on-change rule (pass it through ``Evaluation.horizons``).

Trend state (EWMA/CUSUM) is advanced by the rollup (``worker.rollup.trend``) and read from
``agent_trend_state``; ``TenantData`` exposes the tick's inputs for evaluators that need them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from .config import EngineConfig
from .engine import Evaluation
from .features import AgentInputs
from .rules import RuleOutcome


class LeadingEvaluator(Protocol):
    def __call__(
        self, inputs: AgentInputs, config: EngineConfig, now: datetime
    ) -> Sequence[RuleOutcome]: ...


class HorizonPredictor(Protocol):
    def __call__(
        self, inputs: AgentInputs, evaluation: Evaluation, config: EngineConfig, now: datetime
    ) -> tuple[Mapping[str, Any], str | None]: ...


class PrepareHook(Protocol):
    async def __call__(self, conn: Any, tenant: UUID, now: datetime) -> Any: ...


@dataclass(frozen=True)
class Extensions:
    leading: LeadingEvaluator | None = None
    horizons: HorizonPredictor | None = None
    prepare: PrepareHook | None = None


_REGISTERED = Extensions()


def register(
    *,
    leading: LeadingEvaluator | None = None,
    horizons: HorizonPredictor | None = None,
    prepare: PrepareHook | None = None,
) -> None:
    global _REGISTERED
    _REGISTERED = Extensions(
        leading=leading or _REGISTERED.leading,
        horizons=horizons or _REGISTERED.horizons,
        prepare=prepare or _REGISTERED.prepare,
    )


def registered() -> Extensions:
    return _REGISTERED


def reset() -> None:
    global _REGISTERED
    _REGISTERED = Extensions()
