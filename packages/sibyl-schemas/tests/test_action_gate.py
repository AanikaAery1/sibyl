"""Action Gate policy model and evaluator (`sibyl_schemas.action_gate`, D48).

Golden vectors pin the decisions every enforcement point (SDK, gateway, control-plane simulate)
must reproduce; the unit tests below pin the semantics the vectors rely on: first match wins,
three-valued predicates (type confusion is never a bypass), anchored length-capped regexes,
glob tool matching, cumulative caps against supplied counters, and data-class rules.
"""

from __future__ import annotations

import copy
import json
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError
from sibyl_schemas import action_gate as ag
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.golden import golden_cases, load_fixture

POLICY_ID = "0192767f-0000-7000-8000-0000000ac001"


def policy(*rules: dict[str, Any], **changes: Any) -> ag.ActionPolicy:
    doc: dict[str, Any] = {
        "schema": "sibyl-action-policy/1",
        "policy_id": POLICY_ID,
        "version": 1,
        "default_effect": "allow",
        "tool_allowlist_enforced": False,
        "tool_allowlist": None,
        "sensitive_tools": [],
        "external_tools": [],
        "hold_timeout_s": 900,
        "rules": list(rules),
    }
    doc.update(changes)
    return ag.parse_policy(doc)


def rule(rule_id: str, tool: str, effect: str, **extra: Any) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "tool": tool,
        "effect": effect,
        "reason": f"{rule_id} fired",
        **extra,
    }


TRANSFER = policy(
    rule("big", "payments.transfer", "block", when={"gt": ["/amount", 10000]}),
    rule("ok", "payments.transfer", "allow", when={"le": ["/amount", 10000]}),
    default_effect="escalate",
)


# ----------------------------------------------------------------------- interface


def test_public_interface_names() -> None:
    assert ag.POLICY_SCHEMA_ID == "sibyl-action-policy/1"
    assert {e.value for e in ag.Effect} == {"allow", "block", "escalate"}
    for name in ("ActionPolicy", "ActionRule", "Predicate", "CumulativeCap", "Decision"):
        assert hasattr(ag, name), name
    decision = ag.evaluate(TRANSFER, "payments.transfer", {"amount": 5})
    assert set(ag.Decision.model_fields) >= {
        "effect",
        "rule_id",
        "reason",
        "matched_paths",
        "needs_counter",
    }
    assert decision.effect is ag.Effect.ALLOW and decision.rule_id == "ok"


def test_parse_policy_accepts_json_text_bytes_and_mapping() -> None:
    doc = TRANSFER.model_dump(mode="json", by_alias=True)
    for form in (doc, json.dumps(doc), json.dumps(doc).encode()):
        assert ag.parse_policy(form) == TRANSFER


def test_parse_policy_refuses_duplicate_members() -> None:
    text = json.dumps(TRANSFER.model_dump(mode="json", by_alias=True))
    with pytest.raises(ValueError, match="duplicate"):
        ag.parse_policy(text[:-1] + ', "version": 2}')


# ----------------------------------------------------------------------- semantics


@pytest.mark.parametrize(
    ("args", "effect", "rule_id"),
    [
        ({"amount": 100_000}, "block", "big"),
        ({"amount": 10_000}, "allow", "ok"),
        ({"amount": 9_999.5}, "allow", "ok"),
        ({"amount": "20000"}, "block", "big"),  # decimal strings compare as numbers
        ({"amount": "20000.00"}, "block", "big"),
        ({"amount": "lots"}, "block", "big"),  # indeterminate: restrictive rule matches
        ({"amount": True}, "block", "big"),  # a boolean is not a number
        ({"amount": [1]}, "block", "big"),
        ({}, "escalate", None),  # absent: no rule matches, default applies
    ],
)
def test_comparisons_are_three_valued(args: dict[str, Any], effect: str, rule_id: str) -> None:
    decision = ag.evaluate(TRANSFER, "payments.transfer", args)
    assert (decision.effect.value, decision.rule_id) == (effect, rule_id)


def test_indeterminate_never_matches_an_allow_rule() -> None:
    allow_only = policy(
        rule("ok", "*", "allow", when={"le": ["/amount", 10]}), default_effect="escalate"
    )
    assert ag.evaluate(allow_only, "x", {"amount": "NaN"}).effect is ag.Effect.ESCALATE
    assert ag.evaluate(allow_only, "x", {"amount": 5}).effect is ag.Effect.ALLOW


def test_first_match_wins() -> None:
    p = policy(rule("a", "t", "allow"), rule("b", "t", "block"))
    assert ag.evaluate(p, "t", {}).rule_id == "a"


@pytest.mark.parametrize(
    ("glob", "tool", "hit"),
    [
        ("email.*", "email.send", True),
        ("email.*", "email", False),
        ("email.*", "emailx.send", False),
        ("*", "anything.at.all", True),
        ("pay?ents.transfer", "payments.transfer", True),
        ("payments.transfer", "payments.transfer", True),
        ("payments.transfer", "payments.transferx", False),
        ("db.[ab]", "db.[ab]", True),  # brackets are literal, not a character class
        ("db.[ab]", "db.a", False),
    ],
)
def test_glob_tool_matching(glob: str, tool: str, hit: bool) -> None:
    p = policy(rule("r", glob, "block"))
    assert (ag.evaluate(p, tool, {}).rule_id == "r") is hit


def test_tool_name_is_normalised_before_matching() -> None:
    p = policy(rule("r", "payments.transfer", "block"))
    fullwidth_p = chr(0xFF50) + "ayments.transfer"
    for spelled in (" payments.transfer", "payments.transfer\n", fullwidth_p):
        assert ag.evaluate(p, spelled, {}).effect is ag.Effect.BLOCK, spelled


def test_allowlist_blocks_unknown_tools_before_any_rule() -> None:
    p = policy(
        rule("everything", "*", "allow"),
        tool_allowlist_enforced=True,
        tool_allowlist=["search.*", "payments.transfer"],
    )
    assert ag.evaluate(p, "search.web", {}).effect is ag.Effect.ALLOW
    blocked = ag.evaluate(p, "shell.exec", {"cmd": "rm -rf /"})
    assert blocked.effect is ag.Effect.BLOCK and blocked.rule_id == ag.ALLOWLIST_RULE_ID


def test_enforced_allowlist_needs_a_list() -> None:
    with pytest.raises(ValidationError):
        policy(tool_allowlist_enforced=True, tool_allowlist=None)


def test_sensitive_tools_default_to_escalate() -> None:
    p = policy(sensitive_tools=["payments.*"])
    sensitive = ag.evaluate(p, "payments.refund", {})
    assert sensitive.effect is ag.Effect.ESCALATE and sensitive.sensitive
    assert ag.evaluate(p, "search", {}).effect is ag.Effect.ALLOW


def test_predicates_combinators_and_exists() -> None:
    p = policy(
        rule(
            "r",
            "t",
            "block",
            when={
                "all": [
                    {"exists": "/to"},
                    {"not": {"in": ["/currency", ["INR", "USD"]]}},
                    {"any": [{"eq": ["/to/0/domain", "evil.test"]}, {"ne": ["/kind", "internal"]}]},
                ]
            },
        )
    )
    hit = {"to": [{"domain": "evil.test"}], "currency": "EUR", "kind": "internal"}
    assert ag.evaluate(p, "t", hit).effect is ag.Effect.BLOCK
    assert ag.evaluate(p, "t", {**hit, "currency": "INR"}).effect is ag.Effect.ALLOW
    assert ag.evaluate(p, "t", {"currency": "EUR"}).effect is ag.Effect.ALLOW


def test_matched_paths_name_the_predicate_paths() -> None:
    decision = ag.evaluate(TRANSFER, "payments.transfer", {"amount": 50_000})
    assert decision.matched_paths == ("/amount",)


def test_json_pointer_escapes_and_array_indices() -> None:
    p = policy(
        rule("a", "t", "block", when={"eq": ["/a~1b/m~0n", 1]}),
        rule("b", "t", "block", when={"eq": ["/list/1", "x"]}),
    )
    assert ag.evaluate(p, "t", {"a/b": {"m~n": 1}}).rule_id == "a"
    assert ag.evaluate(p, "t", {"list": ["w", "x"]}).rule_id == "b"
    assert ag.evaluate(p, "t", {"list": {"1": "x"}}).rule_id == "b"
    assert ag.evaluate(p, "t", {"list": ["x"]}).rule_id is None
    assert ag.evaluate(p, "t", {"list": {"01": "x"}}).rule_id is None


def test_matches_is_anchored() -> None:
    p = policy(rule("r", "t", "block", when={"matches": ["/to", "[a-z]+@corp\\.example"]}))
    assert ag.evaluate(p, "t", {"to": "ana@corp.example"}).effect is ag.Effect.BLOCK
    assert ag.evaluate(p, "t", {"to": "ana@corp.example.evil"}).effect is ag.Effect.ALLOW
    assert ag.evaluate(p, "t", {"to": "x ana@corp.example"}).effect is ag.Effect.ALLOW


def test_matches_on_oversize_subject_is_indeterminate() -> None:
    p = policy(rule("r", "t", "block", when={"matches": ["/s", "a+"]}))
    assert ag.evaluate(p, "t", {"s": "a" * (ag.MAX_MATCH_SUBJECT + 1)}).effect is ag.Effect.BLOCK


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+",
        "(a*)*b",
        "(ab|a)*c",
        "(x+x+)+y",
        "(?=a)a",
        "(a)\\1",
        "a" * (ag.MAX_PATTERN_LENGTH + 1),
        "[",
        "a*b*c*d*",
    ],
)
def test_unsafe_regexes_are_refused(pattern: str) -> None:
    with pytest.raises(ValidationError):
        policy(rule("r", "t", "block", when={"matches": ["/s", pattern]}))


@pytest.mark.parametrize("pattern", ["[a-z]+@corp\\.example", "\\d{3}-\\d{4}", "IN|US", "x{2,5}y*"])
def test_safe_regexes_are_accepted(pattern: str) -> None:
    policy(rule("r", "t", "block", when={"matches": ["/s", pattern]}))


@pytest.mark.parametrize(
    "when",
    [
        {"le": ["amount", 1]},  # not a JSON pointer
        {"le": ["/amount", "1"]},  # ordered comparisons take numbers
        {"le": ["/amount", True]},
        {"eq": ["/a"]},
        {"eq": ["/a", 1, 2]},
        {"in": ["/a", []]},
        {"all": []},
        {"eq": ["/a", 1], "ne": ["/a", 2]},  # one operator per node
        {"nope": ["/a", 1]},
        {"exists": 3},
    ],
)
def test_malformed_predicates_are_refused(when: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        policy(rule("r", "t", "block", when=when))


def test_predicate_depth_is_capped() -> None:
    node: dict[str, Any] = {"exists": "/a"}
    for _ in range(ag.MAX_PREDICATE_DEPTH + 1):
        node = {"not": node}
    with pytest.raises(ValidationError):
        policy(rule("r", "t", "block", when=node))


def test_duplicate_rule_ids_are_refused() -> None:
    with pytest.raises(ValidationError):
        policy(rule("r", "a", "block"), rule("r", "b", "block"))


# ----------------------------------------------------------------------- cumulative caps

DAILY = policy(
    rule(
        "daily",
        "payments.transfer",
        "allow",
        when={"le": ["/amount", 10000]},
        cumulative={"sum": "/amount", "max": 50000, "window_s": 86400},
    ),
    default_effect="escalate",
)


def test_cumulative_unknown_counter_needs_one_and_is_provisionally_restrictive() -> None:
    decision = ag.evaluate(DAILY, "payments.transfer", {"amount": 9000})
    need = decision.needs_counter
    assert need is not None
    assert decision.effect is ag.Effect.ESCALATE  # provisional: the cap's on_exceed
    assert need.rule_id == "daily" and need.increment == "9000" and need.max == "50000"
    assert need.window_s == 86400 and need.within_effect is ag.Effect.ALLOW
    assert need.counter_key == ag.counter_key(DAILY, DAILY.rules[0], {"amount": 9000})


def test_cumulative_with_counters_under_and_over_the_cap() -> None:
    key = ag.counter_key(DAILY, DAILY.rules[0], {"amount": 1})
    under = ag.evaluate(DAILY, "payments.transfer", {"amount": 9000}, {key: 41000})
    over = ag.evaluate(DAILY, "payments.transfer", {"amount": 9000}, {key: Decimal("41000.01")})
    assert under.effect is ag.Effect.ALLOW and under.needs_counter is not None
    assert over.effect is ag.Effect.ESCALATE and over.needs_counter is None


def test_apply_counter_resolves_the_authoritative_answer() -> None:
    decision = ag.evaluate(DAILY, "payments.transfer", {"amount": 9000})
    assert ag.apply_counter(decision, within_cap=True).effect is ag.Effect.ALLOW
    assert ag.apply_counter(decision, within_cap=False).effect is ag.Effect.ESCALATE
    plain = ag.evaluate(TRANSFER, "payments.transfer", {"amount": 1})
    assert ag.apply_counter(plain, within_cap=False) == plain


def test_cumulative_on_exceed_block_and_count_caps() -> None:
    p = policy(
        rule(
            "burst",
            "email.*",
            "allow",
            cumulative={"count": True, "max": 2, "window_s": 60, "on_exceed": "block"},
        )
    )
    key = ag.counter_key(p, p.rules[0], {})
    assert ag.evaluate(p, "email.send", {}, {key: 1}).effect is ag.Effect.ALLOW
    blocked = ag.evaluate(p, "email.send", {}, {key: 2})
    assert blocked.effect is ag.Effect.BLOCK and blocked.rule_id == "burst"


@pytest.mark.parametrize("amount", [-5000, "-1", "abc", None, [1], 1e400])
def test_unreadable_or_negative_cumulative_amount_takes_on_exceed(amount: Any) -> None:
    decision = ag.evaluate(DAILY, "payments.transfer", {"amount": amount}, {})
    assert decision.effect is ag.Effect.ESCALATE
    assert decision.needs_counter is None


def test_counter_key_is_per_argument_value_when_asked() -> None:
    p = policy(
        rule(
            "per",
            "t",
            "allow",
            cumulative={"count": True, "max": 1, "window_s": 60, "per": "/customer_id"},
        )
    )
    r = p.rules[0]
    a = ag.counter_key(p, r, {"customer_id": "c-1"})
    assert a == ag.counter_key(p, r, {"customer_id": "c-1"})
    assert a != ag.counter_key(p, r, {"customer_id": "c-2"})
    assert a != ag.counter_key(p, r, {})
    assert a.startswith(f"{POLICY_ID}/per/")


def test_cumulative_requires_exactly_one_measure() -> None:
    for cap in (
        {"max": 1, "window_s": 60},
        {"sum": "/a", "count": True, "max": 1, "window_s": 60},
    ):
        with pytest.raises(ValidationError):
            policy(rule("r", "t", "allow", cumulative=cap))


# ----------------------------------------------------------------------- data class

EXFIL = policy(
    rule(
        "no-pii-out",
        "*",
        "block",
        data_class={"secrets": True, "pii": ["email", "credit_card", "national_id"]},
    ),
    external_tools=["http.post", "email.send"],
)


def test_pii_to_an_external_tool_is_blocked() -> None:
    decision = ag.evaluate(EXFIL, "http.post", {"body": {"notes": "card 4111 1111 1111 1111"}})
    assert decision.effect is ag.Effect.BLOCK and decision.rule_id == "no-pii-out"
    assert decision.matched_paths == ("/body/notes",)


def test_secret_to_an_external_tool_is_blocked() -> None:
    key = "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0" * 3
    assert ag.evaluate(EXFIL, "email.send", {"text": f"use {key}"}).effect is ag.Effect.BLOCK


def test_pii_to_an_internal_tool_or_clean_args_pass() -> None:
    assert ag.evaluate(EXFIL, "crm.update", {"email": "ana@example.com"}).effect is ag.Effect.ALLOW
    assert ag.evaluate(EXFIL, "http.post", {"q": "weather in Pune"}).effect is ag.Effect.ALLOW


def test_pii_in_a_key_is_found() -> None:
    assert ag.evaluate(EXFIL, "http.post", {"ana@example.com": 1}).effect is ag.Effect.BLOCK


def test_data_class_over_budget_is_indeterminate() -> None:
    huge = {"items": ["x" * 1000] * (ag.MAX_SCAN_CHARS // 1000 + 2)}
    assert ag.evaluate(EXFIL, "http.post", huge).effect is ag.Effect.BLOCK


def test_unknown_pii_detector_is_refused() -> None:
    with pytest.raises(ValidationError):
        policy(rule("r", "*", "block", data_class={"secrets": False, "pii": ["shoe_size"]}))


# ----------------------------------------------------------------------- robustness


@pytest.mark.parametrize(
    "args",
    [None, 3, "text", [1, 2], {"a": float("nan")}, {"a": {"b": {"c": [None] * 5}}}, {1: 2}],
)
def test_evaluate_is_total_on_odd_arguments(args: Any) -> None:
    for p in (TRANSFER, DAILY, EXFIL):
        decision = ag.evaluate(p, "payments.transfer", args)
        assert isinstance(decision, ag.Decision)


def test_deep_arguments_do_not_raise() -> None:
    deep: Any = "x"
    for _ in range(5000):
        deep = [deep]
    for p in (TRANSFER, EXFIL):
        assert isinstance(ag.evaluate(p, "http.post", {"a": deep}), ag.Decision)


def test_internal_errors_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(ag, "_evaluate", boom)
    decision = ag.evaluate(TRANSFER, "payments.transfer", {"amount": 1})
    assert decision.effect is ag.Effect.BLOCK and decision.rule_id == ag.ERROR_RULE_ID


def test_non_string_tool_name_is_handled() -> None:
    p = policy(tool_allowlist_enforced=True, tool_allowlist=["a"])
    assert ag.evaluate(p, None, {}).effect is ag.Effect.BLOCK  # type: ignore[arg-type]


# ----------------------------------------------------------------------- several policies


def test_evaluate_all_takes_the_most_restrictive_policy() -> None:
    lenient = policy(rule("any", "*", "allow"))
    strict = policy(
        rule("stop", "payments.*", "block"), policy_id="0192767f-0000-7000-8000-0000000ac002"
    )
    assert ag.evaluate_all([lenient, strict], "payments.x", {}).rule_id == "stop"
    assert ag.evaluate_all([lenient, strict], "search", {}).effect is ag.Effect.ALLOW
    none = ag.evaluate_all([], "payments.x", {})
    assert none.effect is ag.Effect.ALLOW and none.rule_id is None


# ----------------------------------------------------------------------- golden vectors

VECTORS: dict[str, Any] = load_fixture("action_gate", "vectors.json")
POLICIES = {name: ag.parse_policy(doc) for name, doc in VECTORS["policies"].items()}


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_golden_vector(case: dict[str, Any]) -> None:
    decision = ag.evaluate(
        POLICIES[case["policy"]], case["tool"], copy.deepcopy(case["args"]), case.get("counters")
    )
    expected = case["expected"]
    assert decision.effect.value == expected["effect"]
    assert decision.rule_id == expected["rule_id"]
    if "matched_paths" in expected:
        assert list(decision.matched_paths) == expected["matched_paths"]
    assert (decision.needs_counter is not None) is expected.get("needs_counter", False)


def test_vectors_cover_every_spec_scenario() -> None:
    tags = {tag for case in VECTORS["cases"] for tag in case.get("scenarios", [])}
    assert tags >= {
        "over_limit_blocked",
        "under_limit_allowed",
        "cumulative_escalates",
        "pii_external_blocked",
        "injection_allowlist_blocked",
    }


def test_action_gate_golden_policies_validate_three_ways() -> None:
    cases = golden_cases("action_gate")
    assert any(c.valid for c in cases) and any(not c.valid for c in cases)
    for case in cases:
        assert sj.is_valid(case.schema, case.load(), pointer=case.pointer) is case.valid, case.id


def test_hand_written_schema_tracks_the_pii_registry_and_limits() -> None:
    from sibyl_schemas.models import action_policy as ap

    schema = sj.load_schema(ag.POLICY_SCHEMA_ID)
    pii = schema["$defs"]["data_class"]["properties"]["pii"]
    assert pii["items"]["pattern"] == ap.PII_ID_PATTERN
    assert pii["maxItems"] == len(ap.PII_DETECTOR_IDS)
    assert schema["$defs"]["pointer"]["pattern"] == ap.POINTER_PATTERN
    assert schema["$defs"]["tool_glob"]["pattern"] == ap.TOOL_GLOB_PATTERN
    assert schema["$defs"]["rule"]["properties"]["rule_id"]["pattern"] == ap.RULE_ID_PATTERN


def test_wire_contract_models_for_the_control_plane() -> None:
    request = ag.HeldActionRequest.model_validate(
        {
            "call_id": "0192f0d1-0000-7000-8000-000000000001:call_1",
            "agent_id": "0192767f-0000-7000-8000-00000000c011",
            "source": "gateway",
            "tool": "payments.transfer",
            "args": {"amount": 25000},
            "args_sha256": ag.args_digest({"amount": 25000}),
            "policy_id": POLICY_ID,
            "policy_version": 1,
            "rule_id": "big",
            "reason": "over limit",
            "hold_timeout_s": 900,
        }
    )
    assert request.args == {"amount": 25000}
    status = ag.HeldActionStatus.model_validate(
        {"held_action_id": POLICY_ID, "state": "pending", "queue_position": 3}
    )
    assert status.state == "pending"
    result = ag.ActionDecisionResult.model_validate({"call_id": "c-1", "within_cap": True})
    assert result.within_cap is True
    assert ag.args_digest({"b": 1, "a": 2}) == ag.args_digest({"a": 2, "b": 1})
    assert len(ag.args_digest({"x": float("nan")})) == 64
