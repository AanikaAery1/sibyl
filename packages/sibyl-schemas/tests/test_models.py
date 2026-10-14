"""Pydantic models mirror the hand-written JSON Schemas exactly.

For every golden fixture three verdicts must agree: the hand-written schema, the pydantic
model, and the JSON Schema the model exports (validated with the same format checker).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, TypeAdapter, ValidationError
from sibyl_schemas import jsonschema as sj
from sibyl_schemas import models as m
from sibyl_schemas.golden import GoldenCase, golden_cases

CASES = golden_cases()

ADAPTERS: dict[tuple[str, str | None], TypeAdapter[Any]] = {
    ("sibyl-event/1", None): TypeAdapter(m.Event),
    ("sibyl-event-wire/1", None): TypeAdapter(m.WireEvent),
    ("sibyl-event-wire/1", "/$defs/batch"): TypeAdapter(m.EventBatch),
    ("sibyl-checkpoint/1", None): TypeAdapter(m.Checkpoint),
    ("sibyl-handoff/1", None): TypeAdapter(m.HandoffPacket),
    ("sibyl-health/1", None): TypeAdapter(m.HealthDocument),
    ("sibyl-feature-snapshot/1", None): TypeAdapter(m.FeatureSnapshot),
    ("sibyl-label/1", None): TypeAdapter(m.Label),
    ("sibyl-ingest-response/1", None): TypeAdapter(m.IngestResponse),
    ("sibyl.policy_snapshot/1", None): TypeAdapter(m.PolicySnapshot),
    ("sibyl.policy_snapshot/1", "/$defs/envelope"): TypeAdapter(m.SignedPolicySnapshot),
    ("sibyl.policy_snapshot/1", "/$defs/key_set"): TypeAdapter(m.SigningKeySet),
    ("sibyl-action-policy/1", None): TypeAdapter(m.ActionPolicy),
}


def _adapter(case: GoldenCase) -> TypeAdapter[Any]:
    return ADAPTERS[(case.schema, case.pointer)]


def _model_accepts(case: GoldenCase, doc: Any) -> bool:
    try:
        _adapter(case).validate_python(doc)
    except ValidationError:
        return False
    return True


def test_every_schema_has_a_model() -> None:
    assert {name for name, _ in ADAPTERS} == set(sj.schema_names())
    for case in CASES:
        assert (case.schema, case.pointer) in ADAPTERS, case.id


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_model_verdict_matches_hand_written_schema(case: GoldenCase) -> None:
    doc = case.load()
    assert sj.is_valid(case.schema, doc, pointer=case.pointer) is case.valid
    assert _model_accepts(case, doc) is case.valid


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_model_exported_json_schema_matches_verdict(case: GoldenCase) -> None:
    exported = _adapter(case).json_schema()
    Draft202012Validator.check_schema(exported)
    checker = Draft202012Validator(exported, format_checker=sj.FORMAT_CHECKER)
    assert checker.is_valid(case.load()) is case.valid


@pytest.mark.parametrize("case", [c for c in CASES if c.valid], ids=lambda c: c.id)
def test_valid_fixture_round_trips_through_model(case: GoldenCase) -> None:
    doc = case.load()
    adapter = _adapter(case)
    dumped = adapter.dump_python(adapter.validate_python(doc), mode="json", by_alias=True)
    assert dumped == doc
    assert json.loads(adapter.dump_json(adapter.validate_python(doc), by_alias=True)) == doc


def test_models_are_frozen() -> None:
    doc = next(c for c in CASES if c.schema == "sibyl-health/1" and c.valid).load()
    health = m.HealthDocument.model_validate(doc)
    with pytest.raises(ValidationError):
        health.score = 1


def test_event_union_dispatches_on_type() -> None:
    adapter: TypeAdapter[m.Event] = TypeAdapter(m.Event)
    for case in CASES:
        if case.schema != "sibyl-event/1" or not case.valid:
            continue
        event = adapter.validate_python(case.load())
        assert isinstance(event, BaseModel)
        assert event.type == case.load()["type"]


def test_models_accept_python_field_names_for_aliased_fields() -> None:
    doc = next(c for c in CASES if c.file == "valid/health_degraded.json").load()
    health = m.HealthDocument.model_validate(doc)
    rebuilt = m.HealthDocument.model_validate(
        {**health.model_dump(by_alias=False), "schema_": "sibyl-health/1"}
    )
    assert rebuilt == health
    assert health.horizons.m15.probability_band.value == "0.60"
