"""Every image in compose and every Dockerfile base is on the D15 allow-list."""

from __future__ import annotations

import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

DOCKER_DIR = Path(__file__).resolve().parents[2] / "deploy" / "docker"
DOCKERFILES = sorted(DOCKER_DIR.glob("*.Dockerfile"))
FROM = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)
COPY_FROM = re.compile(r"^COPY\s+--from=(\S+)", re.I | re.M)
ARG_DEFAULT = re.compile(r"^ARG\s+([A-Z0-9_]+)=(\S+)", re.I | re.M)


def _resolve(ref: str, args: dict[str, str]) -> str:
    return re.sub(r"\$\{?([A-Z0-9_]+)\}?", lambda m: args.get(m.group(1), m.group(0)), ref)


def _external_refs(text: str) -> list[str]:
    args = dict(ARG_DEFAULT.findall(text))
    stages = {m.group(2) for m in FROM.finditer(text) if m.group(2)}
    refs = [_resolve(m.group(1), args) for m in FROM.finditer(text)]
    refs += [_resolve(r, args) for r in COPY_FROM.findall(text)]
    return [r for r in refs if r not in stages]


def test_expected_dockerfiles_exist() -> None:
    names = {p.name for p in DOCKERFILES}
    assert {"control.Dockerfile", "gateway.Dockerfile", "sim.Dockerfile"} <= names


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.name)
def test_dockerfile_bases_are_allowed(path: Path, licences: ModuleType) -> None:
    refs = _external_refs(path.read_text(encoding="utf-8"))
    assert refs, f"{path.name} has no FROM"
    for ref in refs:
        assert licences.image_verdict(ref).allowed, f"{path.name}: {ref} not allowed"


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.name)
def test_dockerfile_is_multistage_uv_and_non_root(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert len(FROM.findall(text)) >= 2, "multi-stage build expected"
    assert "uv sync" in text and "--frozen" in text and "--no-dev" in text
    user_lines = [ln for ln in text.splitlines() if ln.strip().upper().startswith("USER ")]
    assert user_lines and user_lines[-1].split()[1] not in ("root", "0"), "runtime must be non-root"


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.name)
def test_dockerfile_has_its_own_dockerignore(path: Path) -> None:
    ignore = path.with_name(path.name + ".dockerignore")
    assert ignore.is_file(), f"{ignore.name} missing (root .dockerignore is steward-owned)"
    assert ".venv" in ignore.read_text(encoding="utf-8")


def test_compose_images_are_allowed(services: dict[str, Any], licences: ModuleType) -> None:
    for name, svc in services.items():
        image = svc.get("image")
        assert image, f"{name} has no image tag"
        assert licences.image_verdict(image).allowed, f"{name}: {image}"


@pytest.mark.parametrize(
    "image",
    [
        "minio/minio:latest",
        "quay.io/minio/minio:RELEASE.2025-01-01",
        "redis:7.4",
        "redis:8-alpine",
        "ghcr.io/zitadel/zitadel:v2",
        "timescale/timescaledb:latest-pg17",
        "grafana/grafana:11.0.0",
        "dxflrs/garage:v1.0.0",
        "someone/unknown:1.0",
    ],
)
def test_denied_or_unknown_images_are_rejected(image: str, licences: ModuleType) -> None:
    assert not licences.image_verdict(image).allowed


@pytest.mark.parametrize("image", ["redis:7.2.5", "valkey/valkey:8.0"])
def test_permissive_cache_images_are_allowed(image: str, licences: ModuleType) -> None:
    assert licences.image_verdict(image).allowed


def test_console_image_bases_are_allowed_and_pinned_by_compose(
    services: dict[str, Any], licences: ModuleType
) -> None:
    """console/Dockerfile is lane C's; compose pins its base by digest through the build arg."""
    build = services["console"]["build"]
    text = (DOCKER_DIR.parents[1] / "console" / build["dockerfile"]).read_text(encoding="utf-8")
    args = {**dict(ARG_DEFAULT.findall(text)), **build["args"]}
    stages = {m.group(2) for m in FROM.finditer(text) if m.group(2)}
    refs = [_resolve(m.group(1), args) for m in FROM.finditer(text)]
    refs = [r for r in refs if r not in stages]
    assert refs, "console/Dockerfile has no external FROM"
    for ref in refs:
        assert licences.image_verdict(ref).allowed, ref
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), f"{ref} is not pinned by digest (L10)"
