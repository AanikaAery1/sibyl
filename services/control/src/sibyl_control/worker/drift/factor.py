"""Drift feeds the health engine's existing ``drift_cusum`` factor (D51), watch-only.

The seed gives ``drift_cusum`` cap 0 in every tier, so its penalty is ``0 x severity = 0``: the
score, the band, the horizons (``r = severity x cap``) and therefore every automation stay
exactly where the other rules put them. The factor only makes drift visible on the health
document next to the factors that do move the score (ruling B23): the outcome is ``alert_only``
(the engine lists it with penalty 0 and weight 0) and ``score_only`` (the engine skips its rule
hysteresis, so it never fires a ``drift_cusum`` alert). ``silent_drift`` / ``model_change`` from
the drift loop are the only drift alerts. Both flags are existing engine semantics: no edit in
``worker/scoring`` was needed.

Severity follows the ``drift_cusum`` curve's range (0 .. 0.5): ``watch`` 0.25, ``drift`` 0.5,
from each agent's latest behavioural verdict over its current frozen baselines (reports older
than two evaluation windows are ignored, so a stopped agent fades out).

Wiring (no edit in the scoring or prediction packages): ``install()`` composes with whatever is
registered in ``worker.scoring.extensions`` (lane P's feed loader and leading evaluator) instead
of replacing it: the composed ``prepare`` runs P's then loads the drift feed; the composed
``leading`` returns P's outcomes plus ``drift_cusum``. Lane P is imported first so its own
registration can never overwrite the composition.
"""

from __future__ import annotations

import contextvars
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any
from uuid import UUID

from ..scoring.config import EngineConfig
from ..scoring.extensions import registered
from ..scoring.features import AgentInputs
from ..scoring.rules import RuleOutcome
from .config import DEFAULT_CONFIG

CODE = "drift_cusum"
SEVERITY = MappingProxyType({"none": 0.0, "watch": 0.25, "drift": 0.5})
FEED_MAX_SKEW_S = 30.0
_MARK = "_sibyl_drift_composed"

_LATEST_SQL = """
SELECT DISTINCT ON (r.baseline_id) r.baseline_id, r.agent_id, r.provider, r.model, r.verdict,
       r.max_ratio, r.evaluated_at
  FROM sibyl.drift_report r
  JOIN sibyl.drift_baseline b ON b.tenant_id = r.tenant_id AND b.id = r.baseline_id
                             AND b.state = 'frozen'
 WHERE r.tenant_id = $1 AND r.evaluated_at > $2 AND r.behaviour_evaluated
 ORDER BY r.baseline_id, r.evaluated_at DESC
"""


@dataclass(frozen=True)
class AgentDrift:
    verdict: str
    severity: float
    ratio: float
    provider: str
    model: str
    evaluated_at: datetime


@dataclass(frozen=True)
class DriftFeed:
    tenant_id: UUID
    now: datetime
    agents: Mapping[UUID, AgentDrift]


_CURRENT: contextvars.ContextVar[DriftFeed | None] = contextvars.ContextVar(
    "sibyl_drift_feed", default=None
)


def worst(rows: Sequence[Mapping[str, Any]]) -> dict[UUID, AgentDrift]:
    """Per agent, the most severe latest verdict over its baselines (ties: the larger ratio)."""
    out: dict[UUID, AgentDrift] = {}
    for r in rows:
        candidate = AgentDrift(
            str(r["verdict"]),
            SEVERITY.get(str(r["verdict"]), 0.0),
            float(r["max_ratio"] or 0.0),
            str(r["provider"]),
            str(r["model"]),
            r["evaluated_at"],
        )
        held = out.get(r["agent_id"])
        if held is None or (candidate.severity, candidate.ratio) > (held.severity, held.ratio):
            out[r["agent_id"]] = candidate
    return out


async def load_feed(conn: Any, tenant: UUID, now: datetime) -> DriftFeed:
    since = now - 2 * DEFAULT_CONFIG.eval_window - timedelta(seconds=FEED_MAX_SKEW_S)
    rows = await conn.fetch(_LATEST_SQL, tenant, since)
    return DriftFeed(tenant, now, MappingProxyType(worst(rows)))


def current(agent_id: UUID, now: datetime) -> AgentDrift | None:
    feed = _CURRENT.get()
    if feed is None or abs((feed.now - now).total_seconds()) > FEED_MAX_SKEW_S:
        return None
    return feed.agents.get(agent_id)


def outcome(drift: AgentDrift | None, cfg: EngineConfig) -> RuleOutcome | None:
    """The ``drift_cusum`` leading outcome for one agent (None when nothing drifted)."""
    if drift is None or drift.severity <= 0 or not cfg.has_rule(CODE):
        return None
    return RuleOutcome(
        CODE,
        "leading",
        True,
        drift.severity,
        value=round(drift.ratio, 4),
        threshold=1.0,
        explanation=(
            f"Behaviour {drift.verdict} against the frozen baseline on {drift.provider or '?'}/"
            f"{drift.model} (largest statistic at {drift.ratio:.2f}x its drift threshold);"
            " watch only"
        )[:300],
        evidence="/api/v1/drift",
        alert_only=True,  # listed on the health document with penalty 0
        score_only=True,  # B23: no rule hysteresis, so the engine never fires a drift_cusum alert
        hint="silent_drift",
    )


def compose(prev_leading: Any, prev_prepare: Any) -> tuple[Any, Any]:
    async def prepare(conn: Any, tenant: UUID, now: datetime) -> Any:
        result = await prev_prepare(conn, tenant, now) if prev_prepare is not None else None
        _CURRENT.set(await load_feed(conn, tenant, now))
        return result

    def leading(inputs: AgentInputs, config: EngineConfig, now: datetime) -> list[RuleOutcome]:
        out = list(prev_leading(inputs, config, now)) if prev_leading is not None else []
        mine = outcome(current(inputs.agent_id, now), config)
        if mine is not None and all(o.code != CODE for o in out):
            out.append(mine)
        return out

    setattr(prepare, _MARK, True)
    setattr(leading, _MARK, True)
    return leading, prepare


def install() -> None:
    """Compose the drift feed with the registered extensions (idempotent)."""
    from ..predict import install as install_predict  # lane P first, never after us
    from ..scoring.extensions import register

    ext = registered()
    if getattr(ext.leading, _MARK, False):
        return
    install_predict()
    ext = registered()
    leading, prepare = compose(ext.leading, ext.prepare)
    register(leading=leading, prepare=prepare)
