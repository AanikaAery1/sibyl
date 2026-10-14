"""Compile ``rules/v1/defaults.yaml`` into the ``sibyl.rules_seed()`` migration.

The database cannot read YAML, so the seed reaches ``tenant_create()`` through a generated
SQL function. ``render_sql`` is deterministic; CI regenerates it and fails on drift.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sibyl_schemas.canonical import canonicalize

TIERS = (1, 2, 3)
PER_TIER_KEYS = frozenset(
    {"cap", "threshold", "hysteresis_in", "hysteresis_out", "cooldown_s", "drill_overdue_days"}
)
COLUMN_KEYS = frozenset(
    {
        "code",
        "short_code",
        "kind",
        "scope",
        "metric",
        "comparator",
        "window_s",
        "min_samples",
        "trend_windows",
        "horizon_s",
        "severity",
        "collapses_to_provider",
        "what_to_do",
    }
)
REQUIRED_RULE_KEYS = frozenset(
    {
        "code",
        "kind",
        "metric",
        "comparator",
        "window_s",
        "min_samples",
        "cap",
        "hysteresis_in",
        "hysteresis_out",
        "cooldown_s",
        "what_to_do",
    }
)
DISPLAY_TIER = 2  # scalar alert_rule columns show the tier-2 value; per-tier truth is in thresholds


class RulesSeedError(ValueError):
    """The YAML violates the seed contract."""


@dataclass(frozen=True)
class RulesSeed:
    rules_source: str
    seed_version: str
    feature_set: str
    yaml_sha256: str
    rules: tuple[Mapping[str, Any], ...]
    scoring_canonical: str


def default_yaml_path() -> Path:
    """Repo path of rules/v1/defaults.yaml (workspace layout)."""
    return Path(__file__).resolve().parents[5] / "rules" / "v1" / "defaults.yaml"


def _tier_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _tier_keys(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_tier_keys(v) for v in value]
    return value


def _per_tier(code: str, key: str, value: Any) -> list[Any]:
    if not isinstance(value, list) or len(value) != len(TIERS):
        raise RulesSeedError(f"rule {code}: {key} must be a list of three per-tier values")
    return value


def _rule_row(rule: Mapping[str, Any]) -> dict[str, Any]:
    code = str(rule.get("code", "?"))
    missing = REQUIRED_RULE_KEYS - rule.keys()
    if missing:
        raise RulesSeedError(f"rule {code}: missing {sorted(missing)}")
    tiers: dict[str, dict[str, Any]] = {str(t): {} for t in TIERS}
    extra: dict[str, Any] = {}
    for key, value in rule.items():
        if key in PER_TIER_KEYS:
            for tier, tier_value in zip(TIERS, _per_tier(code, key, value), strict=True):
                tiers[str(tier)][key] = tier_value
        elif key not in COLUMN_KEYS:
            extra[key] = _tier_keys(value)
    caps = [tiers[str(t)]["cap"] for t in TIERS]
    applicable = [t for t in TIERS if caps[t - 1] > 0] or list(TIERS)
    display = tiers[str(DISPLAY_TIER)]
    return {
        "code": code,
        "short_code": rule.get("short_code"),
        "kind": rule["kind"],
        "scope": rule.get("scope", "agent"),
        "metric": rule["metric"],
        "comparator": rule["comparator"],
        "thresholds": {**extra, "tiers": tiers},
        "window_s": rule["window_s"],
        "min_samples": rule["min_samples"],
        "trend_windows": rule.get("trend_windows"),
        "hysteresis_in": display["hysteresis_in"],
        "hysteresis_out": display["hysteresis_out"],
        "cooldown_s": display["cooldown_s"],
        "severity": rule.get("severity", "warning"),
        "penalty": display["cap"],
        "horizon_s": rule.get("horizon_s", 0),
        "tier_applicability": applicable,
        "collapses_to_provider": bool(rule.get("collapses_to_provider", False)),
        "what_to_do": rule["what_to_do"],
    }


def load(path: Path | None = None) -> RulesSeed:
    """Parse and validate the YAML, returning the compiled seed."""
    source = path or default_yaml_path()
    raw = source.read_bytes()
    doc = yaml.safe_load(raw)
    if doc.get("schema") != "sibyl-rules/1":
        raise RulesSeedError("schema must be sibyl-rules/1")
    rows = tuple(_rule_row(r) for r in doc["rules"])
    codes = [r["code"] for r in rows]
    if len(set(codes)) != len(codes):
        raise RulesSeedError("duplicate rule codes")
    scoring = {
        "rules_source": doc["rules_source"],
        "feature_set": doc["feature_set"],
        "seed_version": str(doc["seed_version"]),
        **_tier_keys(doc["scoring"]),
        "caps": {
            r["code"]: {t: r["thresholds"]["tiers"][t]["cap"] for t in ("1", "2", "3")}
            for r in rows
        },
    }
    return RulesSeed(
        rules_source=doc["rules_source"],
        seed_version=str(doc["seed_version"]),
        feature_set=doc["feature_set"],
        yaml_sha256=hashlib.sha256(raw).hexdigest(),
        rules=rows,
        scoring_canonical=canonicalize(scoring).decode(),
    )


def render_sql(seed: RulesSeed) -> str:
    """Render the migration body that defines ``sibyl.rules_seed()``."""
    rules_json = json.dumps(list(seed.rules), ensure_ascii=False, sort_keys=True, indent=1)
    for tag in ("$rules$", "$scoring$", "$fn$"):
        if tag in rules_json or tag in seed.scoring_canonical:
            raise RulesSeedError(f"dollar-quote tag {tag} appears in the seed")
    return (
        "-- 0013 rules/v1 seed. GENERATED from rules/v1/defaults.yaml by\n"
        "--   python -m sibyl_control.migrate rules-seed --write\n"
        "-- Do not edit. A YAML change ships as a new migration that redefines this function\n"
        "-- (applied migrations are immutable); tenants then re-seed origin='seed' AND\n"
        "-- overridden=false rows.\n"
        "CREATE OR REPLACE FUNCTION sibyl.rules_seed()\n"
        "RETURNS TABLE (rules_source text, seed_version text, feature_set text, yaml_sha256 "
        "bytea,\n"
        "               rules jsonb, scoring_canonical text)\n"
        "LANGUAGE sql IMMUTABLE AS $fn$\n"
        f"  SELECT '{seed.rules_source}'::text, '{seed.seed_version}'::text, "
        f"'{seed.feature_set}'::text,\n"
        f"         decode('{seed.yaml_sha256}', 'hex'),\n"
        f"         $rules${rules_json}$rules$::jsonb,\n"
        f"         $scoring${seed.scoring_canonical}$scoring$::text\n"
        "$fn$;\n"
        "GRANT EXECUTE ON FUNCTION sibyl.rules_seed() TO sibyl_app, sibyl_worker;\n"
    )


def latest_seed_migration(migrations_dir: Path) -> Path | None:
    """The newest migration that (re)defines sibyl.rules_seed()."""
    candidates = sorted(migrations_dir.glob("[0-9][0-9][0-9][0-9]_rules_*seed*.sql"))
    return candidates[-1] if candidates else None
