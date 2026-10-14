"""Action Gate: the one pure evaluator every enforcement point shares (D48, ACTION-GATE.md).

    from sibyl_schemas.action_gate import parse_policy, evaluate
    policy = parse_policy(raw_json)                       # strict parse + model validation
    decision = evaluate(policy, "payments.transfer", {"amount": 25000})
    decision.effect, decision.rule_id, decision.reason, decision.matched_paths

Order: tool allowlist (when enforced) -> rules in order, first match wins -> `default_effect`
(tightened to `escalate` for `sensitive_tools`). `evaluate` is deterministic, never raises
(an internal error is a `block` with `ERROR_RULE_ID`) and never executes policy content.

Predicates are three-valued. A value of the wrong type (a string where a number is compared,
an oversize subject for `matches`) is *indeterminate*: it matches a rule whose effect is
`block`/`escalate` and never an `allow` rule, so type confusion cannot turn a block into an
allow. A path that is absent makes every comparison false; use `exists` to require it.

Cumulative caps: the matched rule's counter is read from `counters` (current total in the
window, before this call). The decision then carries `needs_counter`, the authoritative
check-and-increment for `POST /api/v1/action-decisions`; with no local counter the effect is
the cap's `on_exceed` until `apply_counter` resolves it. Several policies (agent, group,
tenant) combine through `evaluate_all`: the most restrictive decision wins.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from typing import Annotated, Any, Final, Literal

from pydantic import MISSING, BaseModel, ConfigDict, Field

from sibyl_schemas._action_regex import MAX_MATCH_SUBJECT, MAX_PATTERN_LENGTH, compiled
from sibyl_schemas._enums_action import ActionEffect
from sibyl_schemas.canonical import canonicalize, parse_json_strict
from sibyl_schemas.models._base import OpenWireModel, PosInt, Sha256Hex, Timestamp, Uuid, WireModel
from sibyl_schemas.models.action_policy import (
    MAX_PREDICATE_DEPTH,
    POLICY_SCHEMA_ID,
    ActionPolicy,
    ActionRule,
    AllOp,
    AnyOp,
    CumulativeCap,
    DataClassRule,
    EqOp,
    ExistsOp,
    GeOp,
    GtOp,
    InOp,
    LeOp,
    LtOp,
    MatchesOp,
    NeOp,
    NotInOp,
    NotOp,
    Predicate,
    predicate_paths,
)
from sibyl_schemas.pii import find_pii
from sibyl_schemas.scrub import ScrubField, SecretsScrubber

__all__ = [
    "ALLOWLIST_RULE_ID",
    "DEFAULT_RULE_ID",
    "ERROR_RULE_ID",
    "MAX_MATCH_SUBJECT",
    "MAX_PATTERN_LENGTH",
    "MAX_PREDICATE_DEPTH",
    "MAX_SCAN_CHARS",
    "POLICY_SCHEMA_ID",
    "ActionDecisionRequest",
    "ActionDecisionResult",
    "ActionPolicy",
    "ActionRule",
    "CounterNeed",
    "CumulativeCap",
    "DataClassRule",
    "Decision",
    "Effect",
    "HeldActionRequest",
    "HeldActionStatus",
    "OnBehalfOf",
    "OnBehalfOfExternal",
    "OnBehalfOfUser",
    "Predicate",
    "apply_counter",
    "args_digest",
    "counter_key",
    "evaluate",
    "evaluate_all",
    "most_restrictive",
    "on_behalf_of_from_header",
    "on_behalf_of_of",
    "parse_policy",
]

Effect = ActionEffect
"""allow | escalate | block (`sibyl_schemas.values.ActionEffect`)."""

ALLOWLIST_RULE_ID: Final = "sibyl:tool_allowlist"
DEFAULT_RULE_ID: Final = None
ERROR_RULE_ID: Final = "sibyl:evaluator_error"
NO_POLICY_REASON: Final = "no action policy applies"
MAX_SCAN_CHARS: Final = 256 * 1024
MAX_SCAN_NODES: Final = 10_000
MAX_SCAN_DEPTH: Final = 64
MAX_TOOL_NAME: Final = 256
_RANK: Final = {ActionEffect.ALLOW: 0, ActionEffect.ESCALATE: 1, ActionEffect.BLOCK: 2}
_DECIMAL = re.compile(r"^[+-]?[0-9]{1,30}(\.[0-9]{1,18})?$")
_INDEX = re.compile(r"^(0|[1-9][0-9]{0,9})$")
_DETECT_SALT: Final = b"sibyl-action-gate-detect/1"

type Verdict = bool | None
"""Three-valued: True, False, or None (indeterminate)."""


class CounterNeed(BaseModel):
    """The authoritative check-and-increment a cumulative rule needs
    (`POST /api/v1/action-decisions`, idempotent per `call_id`)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    counter_key: str
    rule_id: str
    increment: str
    max: str
    window_s: int
    within_effect: ActionEffect
    exceed_effect: ActionEffect


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    effect: ActionEffect
    rule_id: str | None
    reason: str
    matched_paths: tuple[str, ...] = ()
    needs_counter: CounterNeed | None = None
    policy_id: str | None = None
    policy_version: int | None = None
    sensitive: bool = False
    hold_timeout_s: int | None = None


# ------------------------------------------------------------------------------- parsing


def parse_policy(raw: str | bytes | bytearray | Mapping[str, Any] | ActionPolicy) -> ActionPolicy:
    """Strictly parse JSON text (duplicate members, NaN and over-deep input refused) or
    validate an already-decoded mapping. Raises `ValueError` (pydantic `ValidationError` or
    `CanonicalizationError`)."""
    if isinstance(raw, ActionPolicy):
        return raw
    if isinstance(raw, str | bytes | bytearray):
        raw = parse_json_strict(bytes(raw) if isinstance(raw, bytearray) else raw)
    return ActionPolicy.model_validate(raw)


# ------------------------------------------------------------------------------- values


def _number(value: Any) -> Decimal | None:
    """A finite number: JSON numbers (never booleans) and plain decimal strings."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(repr(value)) if value == value and abs(value) != float("inf") else None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    if isinstance(value, str) and _DECIMAL.match(value):
        try:
            return Decimal(value)
        except InvalidOperation:  # pragma: no cover - the pattern admits only valid text
            return None
    return None


def _json_eq(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    a, b = _number(left), _number(right)
    return a is not None and b is not None and a == b


def _fmt(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    return "0" if text in ("-0", "") else text


def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def resolve(args: Any, pointer: str) -> tuple[bool, Any]:
    """RFC 6901 lookup: (found, value). Array indices must be canonical integers."""
    if pointer == "":
        return True, args
    node = args
    for raw in pointer[1:].split("/"):
        token = _unescape(raw)
        if isinstance(node, Mapping):
            if token not in node:
                return False, None
            node = node[token]
        elif isinstance(node, list | tuple):
            if not _INDEX.match(token) or int(token) >= len(node):
                return False, None
            node = node[int(token)]
        else:
            return False, None
    return True, node


# ------------------------------------------------------------------------------- predicates


def _compare(op: Any, args: Any) -> Verdict:
    for name, test in (
        ("lt", Decimal.__lt__),
        ("le", Decimal.__le__),
        ("gt", Decimal.__gt__),
        ("ge", Decimal.__ge__),
    ):
        pair = getattr(op, name, None)
        if pair is None:
            continue
        found, value = resolve(args, pair[0])
        if not found:
            return False
        number = _number(value)
        if number is None:
            return None
        bound = _number(pair[1])
        return None if bound is None else bool(test(number, bound))
    raise TypeError(f"not a comparison: {type(op).__name__}")


def _matches(op: MatchesOp, args: Any) -> Verdict:
    path, pattern = op.matches
    found, value = resolve(args, path)
    if not found:
        return False
    if not isinstance(value, str) or len(value) > MAX_MATCH_SUBJECT:
        return None
    return compiled(pattern).fullmatch(value) is not None


def _kleene_all(results: Iterable[Verdict]) -> Verdict:
    unknown = False
    for result in results:
        if result is False:
            return False
        unknown = unknown or result is None
    return None if unknown else True


def _kleene_any(results: Iterable[Verdict]) -> Verdict:
    unknown = False
    for result in results:
        if result is True:
            return True
        unknown = unknown or result is None
    return None if unknown else False


def holds(node: Predicate, args: Any) -> Verdict:
    """Evaluate one predicate against the arguments (depth is bounded by the model)."""
    op = node.root
    if isinstance(op, ExistsOp):
        return resolve(args, op.exists)[0]
    if isinstance(op, EqOp | NeOp):
        path, want = op.eq if isinstance(op, EqOp) else op.ne
        found, value = resolve(args, path)
        if not found:
            return False
        return _json_eq(value, want) is isinstance(op, EqOp)
    if isinstance(op, InOp | NotInOp):
        path, options = op.in_ if isinstance(op, InOp) else op.not_in
        found, value = resolve(args, path)
        if not found:
            return False
        member = any(_json_eq(value, option) for option in options)
        return member is isinstance(op, InOp)
    if isinstance(op, LtOp | LeOp | GtOp | GeOp):
        return _compare(op, args)
    if isinstance(op, MatchesOp):
        return _matches(op, args)
    if isinstance(op, AllOp):
        return _kleene_all(holds(child, args) for child in op.all)
    if isinstance(op, AnyOp):
        return _kleene_any(holds(child, args) for child in op.any)
    if isinstance(op, NotOp):
        inner = holds(op.not_, args)
        return None if inner is None else not inner
    raise TypeError(f"unknown predicate {type(op).__name__}")  # pragma: no cover


# ------------------------------------------------------------------------------- tools


@lru_cache(maxsize=4096)
def _glob(pattern: str) -> re.Pattern[str]:
    parts = (".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern)
    return re.compile("".join(parts), re.DOTALL)


def tool_matches(pattern: str, tool: str) -> bool:
    """`*` is any run of characters (dots included), `?` one character; all else literal."""
    return _glob(pattern).fullmatch(tool) is not None


def normalise_tool(tool: Any) -> str:
    """NFKC and surrounding whitespace removed, so a look-alike spelling cannot dodge a rule."""
    if not isinstance(tool, str):
        return ""
    name = unicodedata.normalize("NFKC", tool).strip()
    return name if len(name) <= MAX_TOOL_NAME else name[:MAX_TOOL_NAME]


def _any_tool(patterns: Sequence[str] | None, tool: str) -> bool:
    return bool(patterns) and any(tool_matches(p, tool) for p in patterns or ())


# ------------------------------------------------------------------------------- data class


@lru_cache(maxsize=1)
def _detector() -> SecretsScrubber:
    return SecretsScrubber(salt=_DETECT_SALT)


def _pointer(parts: tuple[str, ...]) -> str:
    return "".join("/" + p.replace("~", "~0").replace("/", "~1") for p in parts)


def _leaves(args: Any) -> tuple[list[tuple[str, str]], bool]:
    """(path, text) for every string leaf, string key and integer leaf; False when a scan
    budget (nodes, depth, characters) was exceeded."""
    out: list[tuple[str, str]] = []
    chars, nodes = 0, 0
    stack: list[tuple[Any, tuple[str, ...]]] = [(args, ())]
    while stack:
        node, parts = stack.pop()
        nodes += 1
        if nodes > MAX_SCAN_NODES or len(parts) > MAX_SCAN_DEPTH:
            return out, False
        if isinstance(node, str):
            chars += len(node)
            out.append((_pointer(parts), node))
        elif isinstance(node, int) and not isinstance(node, bool):
            out.append((_pointer(parts), str(node)))
        elif isinstance(node, Mapping):
            for key, value in node.items():
                if isinstance(key, str):
                    chars += len(key)
                    out.append((_pointer((*parts, key)), key))
                stack.append((value, (*parts, str(key))))
        elif isinstance(node, list | tuple):
            stack.extend((value, (*parts, str(i))) for i, value in enumerate(node))
        if chars > MAX_SCAN_CHARS:
            return out, False
    return out, True


def _data_class(rule: DataClassRule, args: Any) -> tuple[Verdict, tuple[str, ...]]:
    leaves, complete = _leaves(args)
    hits: dict[str, None] = {}
    for path, text in leaves:
        if rule.pii and find_pii(text, rule.pii):
            hits.setdefault(path, None)
        elif rule.secrets and _detector().scrub(text, ScrubField.TOOL_ARGS).findings:
            hits.setdefault(path, None)
    if hits:
        return True, tuple(hits)
    return (False if complete else None), ()


# ------------------------------------------------------------------------------- cumulative


def counter_key(policy: ActionPolicy, rule: ActionRule, args: Any) -> str:
    """`<policy_id>/<rule_id>[/<sha256(JCS(per value))[:32]>]`; the control plane keys it per
    agent. A `per` value that is absent gets its own bucket (`~`)."""
    base = f"{policy.policy_id}/{rule.rule_id}"
    cap = rule.cumulative
    if cap is MISSING or cap.per is MISSING:
        return base
    found, value = resolve(args, cap.per)
    if not found:
        return f"{base}/~"
    try:
        material = canonicalize(value)
    except (ValueError, TypeError):
        material = repr(value).encode("utf-8", "surrogatepass")
    return f"{base}/{hashlib.sha256(material).hexdigest()[:32]}"


def _cumulative(
    policy: ActionPolicy,
    rule: ActionRule,
    cap: CumulativeCap,
    args: Any,
    counters: Mapping[str, Any] | None,
    base: dict[str, Any],
) -> Decision:
    exceed = cap.exceed_effect
    if cap.count is not MISSING:
        increment: Decimal | None = Decimal(1)
    else:
        found, value = resolve(args, str(cap.sum))
        increment = _number(value) if found else None
    if increment is None or increment < 0:
        reason = f"{rule.reason} (cumulative amount unreadable)"
        return Decision(effect=exceed, rule_id=rule.rule_id, reason=reason, **base)
    key = counter_key(policy, rule, args)
    limit = Decimal(str(cap.max))
    need = CounterNeed(
        counter_key=key,
        rule_id=rule.rule_id,
        increment=_fmt(increment),
        max=_fmt(limit),
        window_s=cap.window_s,
        within_effect=rule.effect,
        exceed_effect=exceed,
    )
    current = _number(counters.get(key)) if counters is not None else None
    if current is None:
        reason = f"{rule.reason} (cumulative counter pending)"
        return Decision(
            effect=exceed, rule_id=rule.rule_id, reason=reason, needs_counter=need, **base
        )
    if current + increment > limit:
        reason = f"{rule.reason} (cap {_fmt(limit)} per {cap.window_s}s exceeded)"
        return Decision(effect=exceed, rule_id=rule.rule_id, reason=reason, **base)
    return Decision(
        effect=rule.effect, rule_id=rule.rule_id, reason=rule.reason, needs_counter=need, **base
    )


def apply_counter(decision: Decision, *, within_cap: bool) -> Decision:
    """Resolve a decision with the authoritative counter answer; others pass unchanged."""
    need = decision.needs_counter
    if need is None:
        return decision
    effect = need.within_effect if within_cap else need.exceed_effect
    note = "within cap" if within_cap else f"cap {need.max} per {need.window_s}s exceeded"
    reason = decision.reason.split(" (cumulative", 1)[0].split(" (cap ", 1)[0]
    return decision.model_copy(
        update={"effect": effect, "reason": f"{reason} ({note})", "needs_counter": None}
    )


# ------------------------------------------------------------------------------- evaluate


def most_restrictive(left: ActionEffect, right: ActionEffect) -> ActionEffect:
    return left if _RANK[left] >= _RANK[right] else right


def _rule(
    policy: ActionPolicy,
    rule: ActionRule,
    tool: str,
    args: Any,
    counters: Mapping[str, Any] | None,
    base: dict[str, Any],
) -> Decision | None:
    verdict: Verdict = True if rule.when is MISSING else holds(rule.when, args)
    paths = predicate_paths(rule.when) if rule.when is not MISSING else ()
    if verdict is not False and rule.data_class is not MISSING:
        if not _any_tool(policy.external_tools, tool):
            return None
        hit, hit_paths = _data_class(rule.data_class, args)
        verdict = _kleene_all((verdict, hit))
        paths = (*paths, *(p for p in hit_paths if p not in paths))
    if verdict is False:
        return None
    base = {**base, "matched_paths": paths}
    cap = rule.cumulative
    if verdict is None:
        effect = rule.effect if cap is MISSING else most_restrictive(rule.effect, cap.exceed_effect)
        if effect is ActionEffect.ALLOW:
            return None
        reason = f"{rule.reason} (arguments indeterminate)"
        return Decision(effect=effect, rule_id=rule.rule_id, reason=reason, **base)
    if cap is not MISSING:
        return _cumulative(policy, rule, cap, args, counters, base)
    return Decision(effect=rule.effect, rule_id=rule.rule_id, reason=rule.reason, **base)


def _evaluate(
    policy: ActionPolicy, tool: Any, args: Any, counters: Mapping[str, Any] | None
) -> Decision:
    name = normalise_tool(tool)
    sensitive = _any_tool(policy.sensitive_tools, name)
    base: dict[str, Any] = {
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "sensitive": sensitive,
        "hold_timeout_s": policy.hold_timeout_s,
    }
    if policy.tool_allowlist_enforced and not _any_tool(policy.tool_allowlist, name):
        reason = f"tool {name[:80]!r} is not in the agent's tool allowlist"
        return Decision(effect=ActionEffect.BLOCK, rule_id=ALLOWLIST_RULE_ID, reason=reason, **base)
    for rule in policy.rules:
        if tool_matches(rule.tool, name):
            decided = _rule(policy, rule, name, args, counters, base)
            if decided is not None:
                return decided
    effect = ActionEffect(policy.default_effect)
    if sensitive:
        effect = most_restrictive(effect, ActionEffect.ESCALATE)
    reason = f"no rule matched; default {effect.value}" + (" (sensitive tool)" if sensitive else "")
    return Decision(effect=effect, rule_id=DEFAULT_RULE_ID, reason=reason, **base)


def evaluate(
    policy: ActionPolicy, tool: str, args: Any, counters: Mapping[str, Any] | None = None
) -> Decision:
    """Decide one proposed tool call. Pure, deterministic and total: any internal failure is a
    `block` with rule id `ERROR_RULE_ID` (fail closed)."""
    try:
        return _evaluate(policy, tool, args, counters)
    except Exception as exc:  # the evaluator must never raise into an enforcement point
        return Decision(
            effect=ActionEffect.BLOCK,
            rule_id=ERROR_RULE_ID,
            reason=f"action gate evaluation failed ({type(exc).__name__}); failing closed",
            policy_id=getattr(policy, "policy_id", None),
            policy_version=getattr(policy, "version", None),
        )


def evaluate_all(
    policies: Sequence[ActionPolicy],
    tool: str,
    args: Any,
    counters: Mapping[str, Any] | None = None,
) -> Decision:
    """Every applicable policy (agent, group, tenant): the most restrictive decision wins;
    ties keep the earlier policy. No policy at all allows."""
    best: Decision | None = None
    for policy in policies:
        decision = evaluate(policy, tool, args, counters)
        if best is None or _RANK[decision.effect] > _RANK[best.effect]:
            best = decision
    if best is None:
        return Decision(effect=ActionEffect.ALLOW, rule_id=None, reason=NO_POLICY_REASON)
    return best


def args_digest(args: Any) -> str:
    """sha256 hex of JCS(args); falls back to sorted-key JSON for values JCS refuses."""
    try:
        material = canonicalize(args)
    except (ValueError, TypeError):
        material = json.dumps(args, sort_keys=True, default=repr).encode("utf-8", "surrogatepass")
    return hashlib.sha256(material).hexdigest()


# ------------------------------------------------------------------------------- wire contracts
# Request and response bodies the SDK and gateway exchange with the control plane (AG-CORE).

CallId = Annotated[str, Field(pattern=r"^[A-Za-z0-9._:-]{1,160}$")]
HeldState = Literal["pending", "approved", "denied", "expired", "cancelled"]


ON_BEHALF_OF_HEADER: Final = "X-Sibyl-On-Behalf-Of"
MAX_ON_BEHALF_OF_REF: Final = 128
MAX_ON_BEHALF_OF_HEADER: Final = 512  # the gateway's cap on X-Sibyl-On-Behalf-Of (trimmed)
_UUID_TEXT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class OnBehalfOfUser(WireModel):
    """The agent acted for a person of this tenant (`app_user.id`). That person never approves
    the hold (409 `self_approval`)."""

    kind: Literal["user"]
    id: Uuid


class OnBehalfOfExternal(WireModel):
    """The agent acted for someone outside the tenant's users (a customer, a ticket requester):
    an opaque reference, at most 128 printable characters."""

    kind: Literal["external"]
    ref: Annotated[
        str, Field(min_length=1, max_length=MAX_ON_BEHALF_OF_REF, pattern=r"^[^\x00-\x1f\x7f]+$")
    ]


OnBehalfOf = Annotated[OnBehalfOfUser | OnBehalfOfExternal, Field(discriminator="kind")]
"""Frozen cross-lane shape (WAVE3.md): `{"kind":"user","id":<uuid>}` or
`{"kind":"external","ref":<string <= 128>}`."""


def on_behalf_of_from_header(value: str) -> OnBehalfOfUser | OnBehalfOfExternal:
    """`X-Sibyl-On-Behalf-Of` (B28): `user:<uuid>`, `external:<ref>` or the frozen JSON shape
    (`{"kind":"user","id":<uuid>}` / `{"kind":"external","ref":<string>}`), parsed as strictly
    as the gateway (`sibyl_gateway.proxy.obo`): at most 512 characters after trimming, strict
    I-JSON (no duplicate members) with exactly the shape's members, and an external ref of 1-128
    characters that are all printable (`str.isprintable`: no control, format, separator or
    unassigned characters). Raises `ValueError` naming `on_behalf_of` for anything else."""
    text = value.strip()
    if text and len(text) <= MAX_ON_BEHALF_OF_HEADER:
        kind, ident = _header_parts(text)
        try:
            if kind == "user" and isinstance(ident, str) and _UUID_TEXT.match(ident.lower()):
                return OnBehalfOfUser(kind="user", id=ident.lower())
            if kind == "external" and isinstance(ident, str) and ident.isprintable():
                return OnBehalfOfExternal(kind="external", ref=ident)
        except ValueError:
            pass
    raise ValueError(
        "on_behalf_of: expected user:<uuid>, external:<ref of 1-128 printable characters> or"
        ' {"kind":"user","id":<uuid>} / {"kind":"external","ref":<ref>}'
    )


def _header_parts(text: str) -> tuple[Any, Any]:
    """(kind, id-or-ref) of a header value; (None, None) when the JSON form is malformed."""
    if not text.startswith("{"):
        kind, sep, rest = text.partition(":")
        return (kind, rest) if sep else (None, None)
    try:
        doc = parse_json_strict(text)
    except ValueError:
        return None, None
    if not isinstance(doc, dict):
        return None, None
    shape = doc.get("kind")
    member = {"user": "id", "external": "ref"}.get(shape) if isinstance(shape, str) else None
    if member is None or set(doc) != {"kind", member}:
        return None, None
    return shape, doc[member]


def on_behalf_of_of(request: HeldActionRequest) -> OnBehalfOfUser | OnBehalfOfExternal | None:
    """The request's on-behalf-of principal; absent and `null` are both None."""
    value = request.on_behalf_of
    return None if value is MISSING or value is None else value


class HeldActionRequest(WireModel):
    """`POST /api/v1/held-actions` (scope `actions:hold`; `Idempotency-Key: <call_id>`).
    `args` are secrets-scrubbed by the enforcement point; `args_sha256` is over the raw
    arguments so an approval can be bound to exactly what was proposed."""

    call_id: CallId
    agent_id: Uuid
    source: Literal["sdk", "gateway"]
    tool: Annotated[str, Field(min_length=1, max_length=MAX_TOOL_NAME)]
    args: Any
    args_sha256: Sha256Hex
    policy_id: Uuid | None
    policy_version: PosInt | None
    rule_id: str | None
    reason: Annotated[str, Field(max_length=500)]
    hold_timeout_s: Annotated[int, Field(ge=1, le=86400)]
    task_id: str | MISSING = MISSING
    on_behalf_of: OnBehalfOf | MISSING | None = MISSING


class HeldActionStatus(OpenWireModel):
    """`201` from the create and `GET /api/v1/held-actions/{id}`; unknown members are kept."""

    held_action_id: Uuid
    state: HeldState
    expires_at: Timestamp | MISSING = MISSING
    decided_at: Timestamp | MISSING | None = MISSING  # null while pending (B-09)
    reason: str | MISSING | None = MISSING


class ActionDecisionRequest(WireModel):
    """`POST /api/v1/action-decisions`: atomic check-and-increment of one cumulative counter,
    idempotent per `call_id` (a replay returns the first answer and increments nothing)."""

    call_id: CallId
    agent_id: Uuid
    source: Literal["sdk", "gateway"]
    policy_id: Uuid
    policy_version: PosInt
    rule_id: str
    tool: Annotated[str, Field(min_length=1, max_length=MAX_TOOL_NAME)]
    counter_key: Annotated[str, Field(min_length=1, max_length=200)]
    increment: Annotated[str, Field(pattern=r"^[0-9]{1,30}(\.[0-9]{1,18})?$")]
    max: Annotated[str, Field(pattern=r"^[0-9]{1,30}(\.[0-9]{1,18})?$")]
    window_s: PosInt
    args_sha256: Sha256Hex


class ActionDecisionResult(OpenWireModel):
    """`200`: `within_cap` is the authoritative answer; the counter was incremented only when
    it is true."""

    call_id: CallId
    within_cap: bool
    counter_value: str | MISSING = MISSING
