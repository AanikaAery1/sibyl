"""The DB suite may skip on a laptop without PostgreSQL, never in CI (G0-tests F1)."""

from __future__ import annotations

import pytest

from . import conftest


@pytest.mark.parametrize(
    ("env", "required"),
    [
        ({}, False),
        ({"CI": "1"}, True),
        ({"CI": "true"}, True),
        ({"SIBYL_REQUIRE_PG": "1"}, True),
        ({"CI": "0", "SIBYL_REQUIRE_PG": ""}, False),
    ],
)
def test_pg_required_reads_ci_and_the_explicit_switch(env: dict[str, str], required: bool) -> None:
    assert conftest.pg_required(env) is required


def test_unavailable_fails_under_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIBYL_REQUIRE_PG", "1")
    with pytest.raises(pytest.fail.Exception, match="required"):
        conftest.unavailable("no database")


def test_unavailable_skips_on_a_laptop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIBYL_REQUIRE_PG", raising=False)
    monkeypatch.delenv("CI", raising=False)
    with pytest.raises(pytest.skip.Exception):
        conftest.unavailable("no database")
