"""Alert hysteresis for drift (pure). Counters live on the ``drift_baseline`` row.

Behaviour (``silent_drift``): raise after ``raise_after`` consecutive ``drift`` verdicts;
resolve after ``clear_after`` consecutive verdicts below ``drift`` (``watch`` is reported and
feeds ``drift_cusum`` but is not drift). An evaluation without enough samples changes nothing.

Identity (``model_change``): raise on the first evaluation with a finding (a model swap is a
discrete event); resolve after ``identity_clear_after`` consecutive clean evaluations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sibyl_schemas.values import DriftVerdict

from .config import DriftConfig


class Action(StrEnum):
    NONE = "none"
    RAISE = "raise"  # open a new alert (or re-open one inside its cooldown)
    REFRESH = "refresh"  # the live alert stays open; update its evidence
    RESOLVE = "resolve"


@dataclass(frozen=True)
class Streaks:
    drift: int = 0
    clear: int = 0
    identity_clear: int = 0


def behaviour(
    streaks: Streaks, verdict: DriftVerdict, raised: bool, cfg: DriftConfig, *, evaluated: bool
) -> tuple[Streaks, Action]:
    if not evaluated:
        return streaks, Action.NONE
    if verdict is DriftVerdict.DRIFT:
        nxt = Streaks(streaks.drift + 1, 0, streaks.identity_clear)
        if raised:
            return nxt, Action.REFRESH
        return nxt, Action.RAISE if nxt.drift >= cfg.raise_after else Action.NONE
    nxt = Streaks(0, streaks.clear + 1, streaks.identity_clear)
    if raised and nxt.clear >= cfg.clear_after:
        return nxt, Action.RESOLVE
    return nxt, Action.NONE


def identity(
    streaks: Streaks, changed: bool, raised: bool, cfg: DriftConfig
) -> tuple[Streaks, Action]:
    if changed:
        nxt = Streaks(streaks.drift, streaks.clear, 0)
        return nxt, Action.REFRESH if raised else Action.RAISE
    nxt = Streaks(streaks.drift, streaks.clear, streaks.identity_clear + 1)
    if raised and nxt.identity_clear >= cfg.identity_clear_after:
        return nxt, Action.RESOLVE
    return nxt, Action.NONE
