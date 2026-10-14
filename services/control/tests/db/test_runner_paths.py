"""Migration discovery edge cases found by the live compose run (no database needed)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sibyl_control.migrate import runner
from sibyl_control.migrate.runner import MigrationError, default_migrations_dir, discover


def test_empty_directory_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(MigrationError, match="no migrations found"):
        discover(tmp_path)


def test_missing_directory_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(MigrationError, match="not found"):
        discover(tmp_path / "absent")


def test_env_override_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIBYL_MIGRATIONS_DIR", str(tmp_path))
    assert default_migrations_dir() == tmp_path


def test_source_tree_is_used_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIBYL_MIGRATIONS_DIR", raising=False)
    resolved = default_migrations_dir()
    assert resolved.name == "migrations" and (resolved / "0000_bootstrap.sql").is_file()


def test_installed_package_falls_back_to_container_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("SIBYL_MIGRATIONS_DIR", raising=False)
    fake_module = tmp_path / "site-packages" / "sibyl_control" / "migrate" / "runner.py"
    fake_module.parent.mkdir(parents=True)
    fake_module.write_text("")
    monkeypatch.setattr(runner, "__file__", str(fake_module))
    assert default_migrations_dir() == runner.CONTAINER_MIGRATIONS_DIR
