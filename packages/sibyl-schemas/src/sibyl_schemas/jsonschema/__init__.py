"""Loader and validator API for the frozen Sibyl document schemas (JSON Schema 2020-12).

    from sibyl_schemas.jsonschema import validate, iter_errors, is_valid
    validate("sibyl-event/1", event)                       # raises SchemaValidationError
    is_valid("sibyl-event-wire/1", body, pointer="/$defs/batch")
    is_valid("sibyl.policy_snapshot/1", envelope, pointer="/$defs/envelope")

All schemas live in one `referencing.Registry`, so cross-document `$ref`s resolve offline.
`format: date-time` is asserted (strict RFC 3339) rather than treated as an annotation.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any, Final

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from sibyl_schemas._formats import is_rfc3339
from sibyl_schemas.jsonschema._wire import build_wire_schema

__all__ = [
    "BASE_URI",
    "FORMAT_CHECKER",
    "SCHEMA_FILES",
    "SchemaValidationError",
    "ValidationIssue",
    "build_wire_schema",
    "is_valid",
    "iter_errors",
    "load_schema",
    "registry",
    "schema_id",
    "schema_names",
    "validate",
    "validator",
]

BASE_URI: Final = "https://sibyl.dev/schemas/"

SCHEMA_FILES: Final = {
    "sibyl-event/1": "sibyl-event-1.json",
    "sibyl-event-wire/1": "sibyl-event-wire-1.json",
    "sibyl-checkpoint/1": "sibyl-checkpoint-1.json",
    "sibyl-handoff/1": "sibyl-handoff-1.json",
    "sibyl-health/1": "sibyl-health-1.json",
    "sibyl-feature-snapshot/1": "sibyl-feature-snapshot-1.json",
    "sibyl-label/1": "sibyl-label-1.json",
    "sibyl-ingest-response/1": "sibyl-ingest-response-1.json",
    "sibyl.policy_snapshot/1": "sibyl.policy_snapshot-1.json",
    "sibyl-action-policy/1": "sibyl-action-policy-1.json",
}

FORMAT_CHECKER: Final = FormatChecker(formats=())
FORMAT_CHECKER.checks("date-time")(is_rfc3339)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One schema violation, located by JSON Pointer into the instance."""

    pointer: str
    keyword: str
    message: str


class SchemaValidationError(ValueError):
    def __init__(self, name: str, issues: list[ValidationIssue]) -> None:
        self.schema_name = name
        self.issues = issues
        first = issues[0]
        super().__init__(f"{name}: {first.pointer or '/'}: {first.message}")


def schema_names() -> tuple[str, ...]:
    return tuple(SCHEMA_FILES)


def schema_id(name: str) -> str:
    _check_name(name)
    return BASE_URI + name


@cache
def _raw(name: str) -> dict[str, Any]:
    _check_name(name)
    text = resources.files(__name__).joinpath(SCHEMA_FILES[name]).read_text("utf-8")
    document: dict[str, Any] = json.loads(text)
    return document


def load_schema(name: str) -> dict[str, Any]:
    """A private deep copy of the named schema document."""
    return copy.deepcopy(_raw(name))


@cache
def registry() -> Registry[Any]:
    resources_ = [
        (schema_id(name), Resource.from_contents(_raw(name), default_specification=DRAFT202012))
        for name in SCHEMA_FILES
    ]
    return Registry().with_resources(resources_)


@cache
def validator(name: str, pointer: str | None = None) -> Draft202012Validator:
    """Cached validator for a schema, or for a sub-schema at a JSON Pointer within it."""
    if pointer is None:
        schema: dict[str, Any] = _raw(name)
    else:
        if not pointer.startswith("/"):
            raise ValueError(f"pointer must start with '/': {pointer!r}")
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"{schema_id(name)}#{pointer}",
        }
    return Draft202012Validator(schema, registry=registry(), format_checker=FORMAT_CHECKER)


def iter_errors(name: str, document: Any, *, pointer: str | None = None) -> list[ValidationIssue]:
    issues = [
        ValidationIssue(
            pointer="".join(f"/{part}" for part in error.absolute_path),
            keyword=str(error.validator),
            message=error.message,
        )
        for error in validator(name, pointer).iter_errors(document)
    ]
    return sorted(issues, key=lambda issue: (issue.pointer, issue.keyword, issue.message))


def is_valid(name: str, document: Any, *, pointer: str | None = None) -> bool:
    return bool(validator(name, pointer).is_valid(document))


def validate(name: str, document: Any, *, pointer: str | None = None) -> None:
    issues = iter_errors(name, document, pointer=pointer)
    if issues:
        raise SchemaValidationError(name, issues)


def _check_name(name: str) -> None:
    if name not in SCHEMA_FILES:
        known = ", ".join(SCHEMA_FILES)
        raise KeyError(f"unknown schema {name!r}; known: {known}")
