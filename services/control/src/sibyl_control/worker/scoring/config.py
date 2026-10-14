"""Per-tenant engine configuration (ML.md §3.2-§3.4, rules/v1).

Two sources, both per tenant and both immutable for a tick:

* the active ``scoring_config.config`` (caps, band edges, dead-band, hysteresis ticks, severity
  curves, floors, flap, provisional, trend parameters), and
* the tenant's ``alert_rule`` copies (R18): thresholds, per-tier hysteresis and cooldown,
  ``min_samples``, ``enabled``, severity, ``what_to_do`` template.

A tier missing from a tenant row falls back to the seed rows (``sibyl.rules_seed()``), so an
operator who edits one tier never silently disables the others. Caps always come from
``scoring_config`` (the score composition), never from the alert rule copy.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from sibyl_control.migrate.rules_seed import RulesSeed

BANDS: tuple[str, ...] = ("healthy", "watch", "degraded", "failed")
BAND_RANK: Mapping[str, int] = MappingProxyType({b: i for i, b in enumerate(BANDS)})
TIERS: tuple[int, ...] = (1, 2, 3)

_EMPTY: Mapping[str, Any] = MappingProxyType({})


def worse(a: str, b: str) -> str:
    return a if BAND_RANK[a] >= BAND_RANK[b] else b


def better(a: str, b: str) -> str:
    return a if BAND_RANK[a] <= BAND_RANK[b] else b


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(v) for v in value)
    return value


@dataclass(frozen=True)
class RuleSpec:
    """One rule as the engine sees it for this tenant."""

    code: str
    kind: str
    scope: str
    severity: str
    window_s: int
    min_samples: int
    caps: Mapping[int, float]
    tiers: Mapping[int, Mapping[str, Any]]
    params: Mapping[str, Any] = field(default_factory=lambda: _EMPTY)
    rule_id: UUID | None = None
    short_code: str | None = None
    collapses_to_provider: bool = False
    escalate_after_fires: int = 3
    escalate_window_s: int = 3600
    what_to_do: str = ""

    def _tier(self, tier: int, key: str, default: Any = None) -> Any:
        return self.tiers.get(tier, _EMPTY).get(key, default)

    def cap(self, tier: int) -> float:
        return float(self.caps.get(tier, 0))

    def threshold(self, tier: int) -> float | None:
        value = self._tier(tier, "threshold")
        return None if value is None else float(value)

    def h_in(self, tier: int) -> int:
        return int(self._tier(tier, "hysteresis_in", 1))

    def h_out(self, tier: int) -> int:
        return int(self._tier(tier, "hysteresis_out", 1))

    def cooldown(self, tier: int) -> int:
        return int(self._tier(tier, "cooldown_s", 600))

    def tier_value(self, tier: int, key: str, default: Any = None) -> Any:
        return self._tier(tier, key, default)

    @property
    def score_only(self) -> bool:
        return bool(self.params.get("score_only", False))

    @property
    def threshold_by_model_class(self) -> Mapping[str, float]:
        return self.params.get("threshold_by_model_class", _EMPTY)  # type: ignore[no-any-return]

    @property
    def sli_family(self) -> str:
        return str(self.params.get("sli_family", ""))


def _row_tiers(row: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
    thresholds = row.get("thresholds") or {}
    raw = thresholds.get("tiers") or {}
    return {int(k): dict(v) for k, v in raw.items() if str(k).isdigit()}


def _row_params(row: Mapping[str, Any]) -> dict[str, Any]:
    thresholds = row.get("thresholds") or {}
    return {k: v for k, v in thresholds.items() if k != "tiers"}


def _merge_rule(
    row: Mapping[str, Any], default: Mapping[str, Any] | None, caps: Mapping[str, Any]
) -> RuleSpec:
    base = default or {}
    tiers = {t: {**_row_tiers(base).get(t, {}), **_row_tiers(row).get(t, {})} for t in TIERS}
    params = {**_row_params(base), **_row_params(row)}
    code = str(row["code"])
    rule_caps = caps.get(code) or {}
    raw_id = row.get("id")
    return RuleSpec(
        code=code,
        kind=str(row.get("kind") or base.get("kind") or "detected"),
        scope=str(row.get("scope") or base.get("scope") or "agent"),
        severity=str(row.get("severity") or base.get("severity") or "warning"),
        window_s=int(row.get("window_s") or base.get("window_s") or 300),
        min_samples=int(row.get("min_samples", base.get("min_samples", 0)) or 0),
        caps=_freeze({t: float(rule_caps.get(str(t), 0)) for t in TIERS}),
        tiers=_freeze(tiers),
        params=_freeze(params),
        rule_id=raw_id if isinstance(raw_id, UUID) else (UUID(str(raw_id)) if raw_id else None),
        short_code=row.get("short_code") or base.get("short_code"),
        collapses_to_provider=bool(
            row.get("collapses_to_provider", base.get("collapses_to_provider", False))
        ),
        escalate_after_fires=int(row.get("escalate_after_fires") or 3),
        escalate_window_s=int(row.get("escalate_window_s") or 3600),
        what_to_do=str(
            row.get("what_to_do_template") or row.get("what_to_do") or base.get("what_to_do") or ""
        ),
    )


@dataclass(frozen=True)
class EngineConfig:
    """Everything the pure engine needs from the tenant's configuration."""

    scoring: Mapping[str, Any]
    rules: Mapping[str, RuleSpec]
    scoring_config_id: UUID | None = None

    @classmethod
    def from_rows(
        cls,
        scoring: Mapping[str, Any],
        rows: Sequence[Mapping[str, Any]],
        *,
        scoring_config_id: UUID | None,
        defaults: Sequence[Mapping[str, Any]] = (),
    ) -> EngineConfig:
        by_code = {str(d["code"]): d for d in defaults}
        caps = scoring.get("caps") or {}
        rules: dict[str, RuleSpec] = {}
        for row in rows:
            code = str(row["code"])
            if code not in by_code or not row.get("enabled", True):
                continue
            rules[code] = _merge_rule(row, by_code[code], caps)
        return cls(_freeze(dict(scoring)), MappingProxyType(rules), scoring_config_id)

    @classmethod
    def from_seed(cls, seed: RulesSeed) -> EngineConfig:
        import json

        scoring = json.loads(seed.scoring_canonical)
        return cls.from_rows(scoring, seed.rules, scoring_config_id=None, defaults=seed.rules)

    def has_rule(self, code: str) -> bool:
        return code in self.rules

    def rule(self, code: str) -> RuleSpec:
        return self.rules[code]

    # ------------------------------------------------------------------ scoring knobs

    def band_edges(self, tier: int) -> Mapping[str, float]:
        return self.scoring["bands"][str(tier)]  # type: ignore[no-any-return]

    @property
    def dead_band(self) -> float:
        return float(self.scoring.get("dead_band", 4))

    def hysteresis_ticks(self, kind: str, tier: int) -> int:
        return int(self.scoring["hysteresis_ticks"][kind][tier - 1])

    def curve(self, key: str, default: float) -> float:
        return float(self.scoring.get("severity_curves", _EMPTY).get(key, default))

    def provider_status_ordinal(self, status: str | None) -> float:
        table = self.scoring.get("severity_curves", _EMPTY).get("provider_status_ordinal", _EMPTY)
        return float(table.get(status or "unknown", 0))

    @property
    def tick_s(self) -> int:
        return int(self.scoring.get("tick_s", 10))

    def section(self, name: str) -> Mapping[str, Any]:
        return self.scoring.get(name, _EMPTY)  # type: ignore[no-any-return]


def band_for_score(cfg: EngineConfig, tier: int, score: float, current: str | None = None) -> str:
    """Band for ``score`` with the upward dead-band relative to ``current`` (R51).

    Worsening is immediate at the edge; improving into a better band needs edge + dead-band.
    """
    edges = cfg.band_edges(tier)

    def plain(lift: float) -> str:
        if score >= float(edges["healthy"]) + lift:
            return "healthy"
        if score >= float(edges["watch"]) + lift:
            return "watch"
        if score >= float(edges["degraded"]) + lift:
            return "degraded"
        return "failed"

    raw = plain(0)
    if current is None or BAND_RANK[raw] >= BAND_RANK[current]:
        return raw
    lifted = plain(cfg.dead_band)
    return lifted if BAND_RANK[lifted] < BAND_RANK[current] else current
