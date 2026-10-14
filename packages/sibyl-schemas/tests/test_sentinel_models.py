"""D52 Sibyl Sentinel: API bodies, structured-output schemas and registry entries."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sibyl_schemas import values as v
from sibyl_schemas.models.sentinel import (
    DEFAULT_ANTHROPIC_MODEL,
    OUTPUT_MODELS,
    SentinelConfigPut,
    SentinelExplainBody,
    SentinelFeedbackBody,
    output_schema,
)

BASE = {"enabled": True, "provider": "anthropic", "daily_budget_usd": "5", "sampling_rate": 0.1}


def test_config_put_defaults_and_secret_handling() -> None:
    body = SentinelConfigPut.model_validate({**BASE, "api_key": "sk-ant-0123456789"})
    assert body.resolved_model() == DEFAULT_ANTHROPIC_MODEL == "claude-fable-5-1"
    assert set(body.tasks) == set(v.SentinelTask)
    assert "sk-ant-0123456789" not in repr(body)


@pytest.mark.parametrize(
    "change",
    [
        {"provider": "gemini"},  # explicit model required
        {"daily_budget_usd": "10001"},
        {"daily_budget_usd": "abc"},
        {"api_key": "has space in it"},
        {"api_key": "short"},
        {"tasks": ["fleet_summary", "fleet_summary"]},
        {"price_in_usd_per_mtok": "1"},
        {"model": "a/b"},
        {"extra": True},
    ],
)
def test_config_put_rejects(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SentinelConfigPut.model_validate({**BASE, **change})


def test_small_bodies() -> None:
    assert (
        SentinelFeedbackBody.model_validate({"feedback": "wrong"}).feedback
        is v.SentinelFeedback.WRONG
    )
    with pytest.raises(ValidationError):
        SentinelExplainBody.model_validate({"subject_kind": "fleet", "subject_id": "x"})


@pytest.mark.parametrize("task", list(v.SentinelTask))
def test_output_schemas_are_closed_and_fully_required(task: v.SentinelTask) -> None:
    schema = output_schema(task)
    assert schema["additionalProperties"] is False
    assert (
        set(schema["required"])
        == set(schema["properties"])
        == set(OUTPUT_MODELS[task].model_fields)
    )


def test_registry_entries() -> None:
    assert {v.Scope.SENTINEL_READ, v.Scope.SENTINEL_ADMIN} <= set(v.SCOPE_CATALOGUE)
    assert v.Role.VIEWER not in v.SCOPE_CATALOGUE[v.Scope.SENTINEL_READ].grants
    names = {n for n in v.AUDIT_ACTIONS if n.startswith("sentinel.")}
    assert names == {
        "sentinel.config_changed",
        "sentinel.config_tested",
        "sentinel.finding_created",
        "sentinel.feedback_recorded",
        "sentinel.budget_exhausted",
    }
