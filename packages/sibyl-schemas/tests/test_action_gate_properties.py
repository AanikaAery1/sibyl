"""Property tests for the Action Gate evaluator (hypothesis).

Over arbitrary JSON arguments and generated policies: `evaluate` is total (always a Decision,
never an exception), deterministic, and monotone under appending rules: a `block` (or
`escalate`) decided by a rule never becomes `allow` when unrelated rules are appended after it.
Policies round-trip through their JSON form, and indeterminate arguments never allow.
"""

from __future__ import annotations

import json
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sibyl_schemas import action_gate as ag

SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])

json_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**15), max_value=10**15)
    | st.floats(allow_nan=False, allow_infinity=False, width=64)
    | st.text(max_size=40)
)
json_values = st.recursive(
    json_scalars,
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=25,
)
keys = st.sampled_from(["amount", "currency", "to", "customer_id", "a", "b"])
arg_docs = st.dictionaries(keys, json_values, max_size=6) | json_values
pointers = keys.map(lambda k: f"/{k}") | st.sampled_from(["", "/to/0", "/a/b", "/x~1y"])
numbers = st.integers(min_value=-(10**6), max_value=10**6) | st.floats(
    min_value=-1e6, max_value=1e6, allow_nan=False
)
scalars = st.none() | st.booleans() | numbers | st.text(max_size=12)
tools = st.sampled_from(
    ["payments.transfer", "payments.refund", "email.send", "http.post", "search.web", "shell.exec"]
)
globs = tools | st.sampled_from(["*", "payments.*", "email.*", "?ttp.post", "search.*"])
effects = st.sampled_from(["allow", "escalate", "block"])


def leaf() -> st.SearchStrategy[dict[str, Any]]:
    return st.one_of(
        st.tuples(st.sampled_from(["eq", "ne"]), pointers, scalars).map(
            lambda t: {t[0]: [t[1], t[2]]}
        ),
        st.tuples(st.sampled_from(["lt", "le", "gt", "ge"]), pointers, numbers).map(
            lambda t: {t[0]: [t[1], t[2]]}
        ),
        st.tuples(
            st.sampled_from(["in", "not_in"]), pointers, st.lists(scalars, min_size=1, max_size=4)
        ).map(lambda t: {t[0]: [t[1], t[2]]}),
        st.tuples(pointers, st.sampled_from(["[a-z]+", "\\d{3}-\\d{4}", "INR|USD", "x.*y"])).map(
            lambda t: {"matches": [t[0], t[1]]}
        ),
        pointers.map(lambda p: {"exists": p}),
    )


predicates = st.recursive(
    leaf(),
    lambda inner: st.one_of(
        st.lists(inner, min_size=1, max_size=3).map(lambda xs: {"all": xs}),
        st.lists(inner, min_size=1, max_size=3).map(lambda xs: {"any": xs}),
        inner.map(lambda x: {"not": x}),
    ),
    max_leaves=6,
)
caps = st.one_of(
    st.builds(
        lambda p, m, w, per, ex: {
            "sum": p,
            "max": m,
            "window_s": w,
            **({"per": per} if per else {}),
            **({"on_exceed": ex} if ex else {}),
        },
        pointers,
        st.integers(min_value=0, max_value=10**6),
        st.integers(min_value=1, max_value=86400),
        st.none() | pointers,
        st.none() | st.sampled_from(["escalate", "block"]),
    ),
    st.builds(
        lambda m, w: {"count": True, "max": m, "window_s": w},
        st.integers(min_value=0, max_value=50),
        st.integers(min_value=1, max_value=3600),
    ),
)


@st.composite
def rules(draw: st.DrawFn, prefix: str) -> list[dict[str, Any]]:
    out = []
    for i in range(draw(st.integers(min_value=0, max_value=5))):
        r: dict[str, Any] = {
            "rule_id": f"{prefix}{i}",
            "tool": draw(globs),
            "effect": draw(effects),
            "reason": "generated",
        }
        if draw(st.booleans()):
            r["when"] = draw(predicates)
        if draw(st.integers(min_value=0, max_value=4)) == 0:
            r["cumulative"] = draw(caps)
        if draw(st.integers(min_value=0, max_value=5)) == 0:
            r["data_class"] = {"secrets": draw(st.booleans()), "pii": ["email", "credit_card"]}
        out.append(r)
    return out


@st.composite
def policies(draw: st.DrawFn) -> dict[str, Any]:
    enforced = draw(st.booleans())
    return {
        "schema": ag.POLICY_SCHEMA_ID,
        "policy_id": "0192767f-0000-7000-8000-0000000ac0ff",
        "version": 1,
        "default_effect": draw(st.sampled_from(["allow", "escalate"])),
        "tool_allowlist_enforced": enforced,
        "tool_allowlist": draw(st.lists(globs, max_size=3)) if enforced else None,
        "sensitive_tools": draw(st.lists(globs, max_size=2)),
        "external_tools": draw(st.lists(globs, max_size=2)),
        "hold_timeout_s": 60,
        "rules": draw(rules("r")),
    }


def counters_for(policy: ag.ActionPolicy, args: Any, value: int | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return {ag.counter_key(policy, r, args): value for r in policy.rules}


@SETTINGS
@given(doc=policies(), tool=tools, args=arg_docs, counter=st.none() | st.integers(0, 10**6))
def test_total_and_deterministic(
    doc: dict[str, Any], tool: str, args: Any, counter: int | None
) -> None:
    policy = ag.parse_policy(doc)
    counters = counters_for(policy, args, counter)
    first = ag.evaluate(policy, tool, args, counters)
    again = ag.evaluate(
        ag.parse_policy(json.dumps(doc)), tool, json.loads(json.dumps(args)), counters
    )
    assert isinstance(first, ag.Decision)
    assert first.rule_id != ag.ERROR_RULE_ID, first.reason
    assert first == again


@SETTINGS
@given(
    doc=policies(),
    extra=rules("z"),
    tool=tools,
    args=arg_docs,
    counter=st.none() | st.integers(0, 10**6),
)
def test_appending_rules_never_relaxes_a_rule_decision(
    doc: dict[str, Any], extra: list[dict[str, Any]], tool: str, args: Any, counter: int | None
) -> None:
    policy = ag.parse_policy(doc)
    counters = counters_for(policy, args, counter)
    before = ag.evaluate(policy, tool, args, counters)
    if before.rule_id is None:  # decided by the default: appended rules may legitimately match
        return
    extended = ag.parse_policy({**doc, "rules": doc["rules"] + extra})
    after = ag.evaluate(extended, tool, args, counters_for(extended, args, counter))
    assert (after.effect, after.rule_id) == (before.effect, before.rule_id)
    if before.effect is ag.Effect.BLOCK:
        assert after.effect is ag.Effect.BLOCK


@SETTINGS
@given(doc=policies(), tool=tools, args=arg_docs)
def test_policy_json_round_trip(doc: dict[str, Any], tool: str, args: Any) -> None:
    policy = ag.parse_policy(doc)
    again = ag.parse_policy(json.dumps(policy.model_dump(mode="json", by_alias=True)))
    assert again == policy
    assert ag.evaluate(again, tool, args) == ag.evaluate(policy, tool, args)


@SETTINGS
@given(
    bound=st.integers(min_value=0, max_value=10**6),
    junk=st.text(max_size=20).filter(lambda s: ag._number(s) is None)
    | st.lists(st.integers(), max_size=2)
    | st.booleans()
    | st.dictionaries(st.text(max_size=3), st.integers(), max_size=2),
)
def test_type_confusion_never_allows(bound: int, junk: Any) -> None:
    """An allow-if-small rule never matches a value that is not a number."""
    doc = {
        "schema": ag.POLICY_SCHEMA_ID,
        "policy_id": "0192767f-0000-7000-8000-0000000ac0fe",
        "version": 1,
        "default_effect": "escalate",
        "tool_allowlist_enforced": False,
        "tool_allowlist": None,
        "sensitive_tools": [],
        "external_tools": [],
        "hold_timeout_s": 60,
        "rules": [
            {
                "rule_id": "small",
                "tool": "*",
                "when": {"le": ["/amount", bound]},
                "effect": "allow",
                "reason": "ok",
            }
        ],
    }
    decision = ag.evaluate(ag.parse_policy(doc), "payments.transfer", {"amount": junk})
    assert decision.effect is ag.Effect.ESCALATE


@SETTINGS
@given(doc=policies(), tool=st.text(max_size=300), args=arg_docs)
def test_arbitrary_tool_names_are_total(doc: dict[str, Any], tool: str, args: Any) -> None:
    decision = ag.evaluate(ag.parse_policy(doc), tool, args)
    assert decision.rule_id != ag.ERROR_RULE_ID, decision.reason
