"""Shared fixtures for the W0-INF lane tests (compose, CI scripts, ops scripts)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"
DOCKER_DIR = REPO_ROOT / "deploy" / "docker"
CI_DIR = REPO_ROOT / "ci"
OPS_DIR = REPO_ROOT / "ops"


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def compose() -> dict[str, Any]:
    with COMPOSE_FILE.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="session")
def services(compose: dict[str, Any]) -> dict[str, dict[str, Any]]:
    svc = compose["services"]
    assert isinstance(svc, dict)
    return svc


@pytest.fixture(scope="session")
def licences() -> ModuleType:
    return load_module("sibyl_ci_licences", CI_DIR / "licences.py")


@pytest.fixture(scope="session")
def skip_guard() -> ModuleType:
    return load_module("sibyl_ci_skip_guard", CI_DIR / "skip_guard.py")
