"""The scenario catalogue: one YAML per scenario under `scenarios/catalog/` (ML §8.2)."""

from __future__ import annotations

from pathlib import Path

import yaml

from .model import Scenario, ScenarioError, parse_scenario

CATALOG_DIR = Path(__file__).parent / "catalog"


def load_file(path: Path) -> Scenario:
    try:
        raw = yaml.safe_load(path.read_text("utf-8"))
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{path.name}: invalid YAML: {exc}") from None
    try:
        return parse_scenario(raw)
    except ScenarioError as exc:
        raise ScenarioError(f"{path.name}: {exc}") from None


def load_catalog(directory: Path = CATALOG_DIR) -> dict[str, Scenario]:
    out: dict[str, Scenario] = {}
    for path in sorted(directory.glob("S-*.yaml")):
        scenario = load_file(path)
        if not path.name.startswith(scenario.id + "-") and path.stem != scenario.id:
            raise ScenarioError(f"{path.name}: file name does not match id {scenario.id}")
        if scenario.id in out:
            raise ScenarioError(f"duplicate scenario id {scenario.id}")
        out[scenario.id] = scenario
    return dict(sorted(out.items(), key=lambda kv: int(kv[0][2:])))


def load(scenario_id: str, directory: Path = CATALOG_DIR) -> Scenario:
    catalog = load_catalog(directory)
    try:
        return catalog[scenario_id.upper()]
    except KeyError:
        raise ScenarioError(
            f"unknown scenario {scenario_id}; known: {', '.join(catalog)}"
        ) from None


def smoke(directory: Path = CATALOG_DIR) -> list[Scenario]:
    return [s for s in load_catalog(directory).values() if s.smoke]
