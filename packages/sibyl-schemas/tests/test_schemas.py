"""JSON Schema documents: meta-validation, enum provenance, drift, golden fixture verdicts."""

from __future__ import annotations

import enum
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from sibyl_schemas import jsonschema as sj
from sibyl_schemas import values as v
from sibyl_schemas.golden import AREAS, GoldenCase, fixtures_root, golden_cases

FIXTURES = fixtures_root()
CASES = golden_cases()

SCHEMA_DIR = Path(sj.__file__).parent


@pytest.mark.parametrize("name", sj.schema_names())
def test_schema_is_valid_draft_2020_12_with_matching_id(name: str) -> None:
    schema = sj.load_schema(name)
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == sj.schema_id(name) == f"https://sibyl.dev/schemas/{name}"


def test_every_schema_file_is_registered() -> None:
    on_disk = {p.name for p in SCHEMA_DIR.glob("*.json")}
    assert on_disk == set(sj.SCHEMA_FILES.values())


def test_no_legacy_identifiers_remain() -> None:
    for path in [*SCHEMA_DIR.glob("*.json"), *FIXTURES.rglob("*.json")]:
        if "legacy_schema_name" in path.name:
            continue  # negative fixtures proving the D19 rename is enforced
        assert "vigil" not in path.read_text("utf-8"), path


def _enum_nodes(node: Any, path: str = "") -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(node, dict):
        if "enum" in node:
            found.append((path, node))
        for key, child in node.items():
            found.extend(_enum_nodes(child, f"{path}/{key}"))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            found.extend(_enum_nodes(child, f"{path}/{index}"))
    return found


@pytest.mark.parametrize("name", sj.schema_names())
def test_every_enum_resolves_to_one_value_set(name: str) -> None:
    for path, node in _enum_nodes(sj.load_schema(name)):
        class_name = node.get("x-sibyl-enum")
        assert class_name, f"{name}{path}: enum without x-sibyl-enum"
        value_set = getattr(v, class_name)
        assert isinstance(value_set, type) and issubclass(value_set, enum.Enum)
        declared = {item for item in node["enum"] if item is not None}
        expected = {member.value for member in value_set}
        if node.get("x-sibyl-enum-subset"):
            assert declared < expected, f"{name}{path}"
        else:
            assert declared == expected, f"{name}{path}: {declared ^ expected}"


def test_wire_schema_is_derived_from_canonical_event_schema() -> None:
    derived = sj.build_wire_schema(sj.load_schema("sibyl-event/1"))
    assert derived == sj.load_schema("sibyl-event-wire/1")
    assert "observed_at" not in derived["required"]
    assert "ingest" not in derived["properties"]


def test_handoff_step_defs_are_identical_to_checkpoint_defs() -> None:
    checkpoint = sj.load_schema("sibyl-checkpoint/1")["$defs"]
    handoff = sj.load_schema("sibyl-handoff/1")["$defs"]
    for name in ("output_ref", "completed_step", "pending_step", "side_effect", "uuid", "uuidv7"):
        assert checkpoint[name] == handoff[name], name


def test_agent_id_nullable_only_for_platform_events() -> None:
    schema = sj.load_schema("sibyl-event/1")
    rule = schema["allOf"][0]
    platform = set(rule["if"]["properties"]["type"]["not"]["enum"])
    assert platform == {t.value for t in v.AGENT_OPTIONAL_EVENT_TYPES}


def test_manifests_list_every_fixture_file() -> None:
    for area in AREAS:
        listed = {case.file for case in CASES if case.area == area}
        on_disk = {str(p.relative_to(FIXTURES / area)) for p in (FIXTURES / area).glob("*/*.json")}
        assert listed == on_disk, area


def test_each_event_type_has_valid_and_negative_fixture() -> None:
    valid: set[str] = set()
    invalid: set[str] = set()
    for case in CASES:
        if case.schema != "sibyl-event/1":
            continue
        event_type = case.load()["type"]
        (valid if case.valid else invalid).add(event_type)
    every = {t.value for t in v.EventType}
    assert valid == every
    assert every <= invalid


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_fixture_verdict(case: GoldenCase) -> None:
    issues = sj.iter_errors(case.schema, case.load(), pointer=case.pointer)
    if case.valid:
        assert issues == [], issues[:3]
    else:
        assert issues, f"{case.id} should fail: {case.why}"
        pointers = {issue.pointer for issue in issues}
        assert case.error_pointer in pointers, (case.error_pointer, issues[:5])


def test_validate_raises_with_located_issues() -> None:
    bad = json.loads(
        (FIXTURES / "ingest/invalid/event_tool_call_unknown_tool_type.json").read_text()
    )
    with pytest.raises(sj.SchemaValidationError) as excinfo:
        sj.validate("sibyl-event/1", bad)
    assert excinfo.value.schema_name == "sibyl-event/1"
    assert any(i.pointer == "/attrs/tool_type" for i in excinfo.value.issues)
    assert "/attrs/tool_type" in str(excinfo.value)


def test_loader_rejects_unknown_names_and_bad_pointers() -> None:
    with pytest.raises(KeyError, match="unknown schema"):
        sj.load_schema("vigil-event/1")
    with pytest.raises(ValueError, match="pointer"):
        sj.validator("sibyl-event-wire/1", "$defs/batch")


def test_load_schema_returns_private_copy() -> None:
    first = sj.load_schema("sibyl-health/1")
    first["title"] = "mutated"
    assert sj.load_schema("sibyl-health/1")["title"] != "mutated"


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("2026-10-09T09:14:32.418Z", True),
        ("2026-10-09T09:14:32Z", True),
        ("2026-10-09T09:14:32.123456789+05:30", True),
        ("2026-10-09t09:14:32Z", False),
        ("2026-10-09T09:14:32", False),
        ("2026-13-09T09:14:32Z", False),
        ("2026-10-09T23:59:60Z", False),
        ("2026-10-09", False),
    ],
)
def test_date_time_format_is_strict_rfc3339(value: str, ok: bool) -> None:
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "format": "date-time"}
    checker = Draft202012Validator(schema, format_checker=sj.FORMAT_CHECKER)
    assert checker.is_valid(value) is ok
