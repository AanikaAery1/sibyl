"""`sibyl-action-policy/1`: the signed Action Gate policy (D48, ACTION-GATE.md §1).

A policy is an ordered rule list for one agent (or group, or tenant) plus the tool lists the
evaluator needs. Predicates are a JSON AST with one operator per node; nothing is ever
evaluated as code. The models accept exactly what the hand-written JSON Schema does, with two
semantic checks the schema cannot express: rule ids are unique within a policy, and a
`matches` pattern must pass the safe-regex admission (`sibyl_schemas._action_regex`).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import (
    MISSING,
    AfterValidator,
    BeforeValidator,
    ConfigDict,
    Field,
    RootModel,
    StringConstraints,
    model_validator,
)

from sibyl_schemas._action_regex import MAX_PATTERN_LENGTH, check_pattern
from sibyl_schemas._enums_action import ActionEffect
from sibyl_schemas.models._base import Lax, PosInt, Uuid, WireModel
from sibyl_schemas.pii import PII_DETECTOR_IDS

POLICY_SCHEMA_ID = "sibyl-action-policy/1"
POINTER_PATTERN = r"^(/([^~/]|~[01])*)*$"
TOOL_GLOB_PATTERN = r"^[A-Za-z0-9_.:/@*?\[\]-]{1,128}$"
RULE_ID_PATTERN = r"^[a-z0-9][a-z0-9_.-]{0,63}$"
PII_ID_PATTERN = "^(" + "|".join(PII_DETECTOR_IDS) + ")$"
MAX_PREDICATE_DEPTH = 16
MAX_PREDICATE_NODES = 256
MAX_RULES = 256
MAX_TOOL_LIST = 1024
MAX_SET_ITEMS = 1000
MAX_WINDOW_S = 31 * 86400

Pointer = Annotated[str, StringConstraints(pattern=POINTER_PATTERN, max_length=256)]
ToolGlob = Annotated[str, StringConstraints(pattern=TOOL_GLOB_PATTERN)]
Text = Annotated[str, Field(max_length=1024)]
Finite = Annotated[float, Field(allow_inf_nan=False)]
Number = int | Finite
Scalar = bool | int | Finite | Text | None
ScalarSet = Annotated[list[Scalar], Field(min_length=1, max_length=MAX_SET_ITEMS)]


def _check_regex(pattern: str) -> str:
    return check_pattern(pattern)  # UnsafePattern is a ValueError -> ValidationError


Regex = Annotated[
    str,
    Field(min_length=1, max_length=MAX_PATTERN_LENGTH),
    AfterValidator(_check_regex),
]


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


type Pair[A, B] = Annotated[tuple[A, B], BeforeValidator(_as_tuple)]


class EqOp(WireModel):
    eq: Pair[Pointer, Scalar]


class NeOp(WireModel):
    ne: Pair[Pointer, Scalar]


class LtOp(WireModel):
    lt: Pair[Pointer, Number]


class LeOp(WireModel):
    le: Pair[Pointer, Number]


class GtOp(WireModel):
    gt: Pair[Pointer, Number]


class GeOp(WireModel):
    ge: Pair[Pointer, Number]


class InOp(WireModel):
    in_: Pair[Pointer, ScalarSet] = Field(alias="in")


class NotInOp(WireModel):
    not_in: Pair[Pointer, ScalarSet]


class MatchesOp(WireModel):
    matches: Pair[Pointer, Regex]


class ExistsOp(WireModel):
    exists: Pointer


class AllOp(WireModel):
    all: Annotated[list[Predicate], Field(min_length=1, max_length=64)]


class AnyOp(WireModel):
    any: Annotated[list[Predicate], Field(min_length=1, max_length=64)]


class NotOp(WireModel):
    not_: Predicate = Field(alias="not")


Operator = (
    EqOp
    | NeOp
    | LtOp
    | LeOp
    | GtOp
    | GeOp
    | InOp
    | NotInOp
    | MatchesOp
    | ExistsOp
    | AllOp
    | AnyOp
    | NotOp
)


class Predicate(RootModel[Operator]):
    """One AST node: `{"<operator>": operand}`. Comparisons take `[pointer, value]`."""

    model_config = ConfigDict(strict=True, frozen=True)


AllOp.model_rebuild()
AnyOp.model_rebuild()
NotOp.model_rebuild()


def children(node: Predicate) -> list[Predicate]:
    op = node.root
    if isinstance(op, AllOp):
        return list(op.all)
    if isinstance(op, AnyOp):
        return list(op.any)
    if isinstance(op, NotOp):
        return [op.not_]
    return []


def pointer_of(node: Predicate) -> str | None:
    op = node.root
    if isinstance(op, ExistsOp):
        return op.exists
    for name in ("eq", "ne", "lt", "le", "gt", "ge", "in_", "not_in", "matches"):
        pair = getattr(op, name, None)
        if pair is not None:
            return str(pair[0])
    return None


def predicate_paths(node: Predicate) -> tuple[str, ...]:
    """Every pointer the predicate reads, in first-seen order."""
    seen: dict[str, None] = {}
    stack = [node]
    while stack:
        current = stack.pop()
        path = pointer_of(current)
        if path is not None:
            seen.setdefault(path, None)
        stack.extend(reversed(children(current)))
    return tuple(seen)


def _shape(node: Predicate) -> tuple[int, int]:
    """(depth, node count) without recursion."""
    depth, count = 0, 0
    stack = [(node, 1)]
    while stack:
        current, level = stack.pop()
        count += 1
        depth = max(depth, level)
        stack.extend((child, level + 1) for child in children(current))
    return depth, count


class CumulativeCap(WireModel):
    """A cap over a window, per agent (and per argument value when `per` is set). Exactly one
    of `sum` (a pointer to a non-negative amount) or `count: true` is given."""

    model_config = ConfigDict(
        json_schema_extra={"oneOf": [{"required": ["sum"]}, {"required": ["count"]}]}
    )

    sum: Pointer | MISSING = MISSING
    count: Literal[True] | MISSING = MISSING
    max: Annotated[Number, Field(ge=0)]
    window_s: Annotated[int, Field(ge=1, le=MAX_WINDOW_S)]
    per: Pointer | MISSING = MISSING
    on_exceed: Literal["escalate", "block"] | MISSING = MISSING

    @model_validator(mode="after")
    def _one_measure(self) -> Self:
        if (self.sum is MISSING) == (self.count is MISSING):
            raise ValueError("exactly one of sum or count is required")
        return self

    @property
    def exceed_effect(self) -> ActionEffect:
        return ActionEffect.BLOCK if self.on_exceed == "block" else ActionEffect.ESCALATE


PiiId = Annotated[str, StringConstraints(pattern=PII_ID_PATTERN)]


class DataClassRule(WireModel):
    """Matches when the tool is external and an argument scrubs as a secret (`secrets`) or
    hits one of the named `pii_standard` detectors."""

    secrets: bool
    pii: Annotated[
        list[PiiId],
        Field(max_length=len(PII_DETECTOR_IDS), json_schema_extra={"uniqueItems": True}),
    ]

    @model_validator(mode="after")
    def _unique(self) -> Self:
        if len(set(self.pii)) != len(self.pii):
            raise ValueError("pii detectors must be unique")
        return self


class ActionRule(WireModel):
    rule_id: Annotated[str, StringConstraints(pattern=RULE_ID_PATTERN)]
    tool: ToolGlob
    when: Predicate | MISSING = MISSING
    cumulative: CumulativeCap | MISSING = MISSING
    data_class: DataClassRule | MISSING = MISSING
    effect: Lax[ActionEffect]
    reason: Annotated[str, Field(min_length=1, max_length=500)]

    @model_validator(mode="after")
    def _bounded(self) -> Self:
        if self.when is not MISSING:
            depth, count = _shape(self.when)
            if depth > MAX_PREDICATE_DEPTH:
                raise ValueError(f"predicate deeper than {MAX_PREDICATE_DEPTH}")
            if count > MAX_PREDICATE_NODES:
                raise ValueError(f"predicate has more than {MAX_PREDICATE_NODES} nodes")
        return self


ToolList = Annotated[list[ToolGlob], Field(max_length=MAX_TOOL_LIST)]


class ActionPolicy(WireModel):
    """Evaluation: allowlist (when enforced) -> rules in order, first match wins ->
    `default_effect`, tightened to `escalate` for `sensitive_tools`."""

    model_config = ConfigDict(
        json_schema_extra={
            "if": {
                "properties": {"tool_allowlist_enforced": {"const": True}},
                "required": ["tool_allowlist_enforced"],
            },
            "then": {"properties": {"tool_allowlist": {"type": "array"}}},
        }
    )

    schema_: Literal["sibyl-action-policy/1"] = Field(alias="schema")
    policy_id: Uuid
    version: PosInt
    default_effect: Literal["allow", "escalate"]
    tool_allowlist_enforced: bool
    tool_allowlist: ToolList | None
    sensitive_tools: ToolList
    external_tools: ToolList
    hold_timeout_s: Annotated[int, Field(ge=10, le=86400)]
    rules: Annotated[list[ActionRule], Field(max_length=MAX_RULES)]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.tool_allowlist_enforced and self.tool_allowlist is None:
            raise ValueError("tool_allowlist_enforced needs a tool_allowlist")
        ids = [r.rule_id for r in self.rules]
        if len(set(ids)) != len(ids):
            raise ValueError("rule_id values must be unique within a policy")
        return self
