"""G0 fix pass for the secrets scrubber: ReDoS (security H4), keys and bytes (M7),
lookalike tokens (L4), detector gaps (L5) and the metamorphic corpus (G0 tests F7).

Timing budgets are process CPU time (best of two) per MiB of adversarial input on one core.
Every pattern is linear, the input each pattern sees is windowed with overlap, and the
decoded views (JSON, percent, format characters) are each linear, so the budgets hold with
a wide margin.
"""

from __future__ import annotations

import base64
import json
import time
from difflib import SequenceMatcher
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sibyl_schemas import scrub
from sibyl_schemas.golden import scrub_corpus
from sibyl_schemas.scrub import (
    MAX_SCRUB_CHARS,
    WINDOW_CHARS,
    WINDOW_OVERLAP_CHARS,
    ScrubField,
    ScrubInputTooLarge,
    SecretsScrubber,
)
from sibyl_schemas.scrub._scrubber import detector_spans

SALT = b"test-salt-not-a-platform-secret!"
SCRUBBER = SecretsScrubber(SALT)
MIB = 1024 * 1024
DETECTOR_BUDGET_S = 0.2
"""Each detector, all of its patterns, on 1 MiB of adversarial input (security H4)."""
SCRUB_BUDGET_S = 6.0
"""A whole `scrub()` call on 1 MiB: every detector over up to 8 live decoded views (the
worst case is text that is JSON-escaped, percent-encoded and has format characters at once)."""

# The security review's inputs, plus a trigger for every other pattern family.
FRAGMENTS = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\\n",
    '"private_key": "-----BEGIN PRIVATE KEY-----',
    '"private_key_id": "',
    "Private-Lines: 1\n",
    "a.",
    "postgres://",
    "postgres://a:",
    "mongodb+srv://u:p",
    "https://u:",
    "x://",
    "?password=",
    "&",
    "@",
    "/",
    ":",
    "password=",
    "token: ",
    "aws_secret_access_key=",
    "AccountKey=",
    "SharedAccessSignature=",
    "Bearer ",
    "Basic ",
    "eyJhbGciOiJIUzI1NiJ9.",
    "sk-",
    "sk-ant-",
    "sbl_live_",
    "AIza",
    "glpat-",
    "hf_",
    "hooks.slack.com/services/",
    "xoxb-",
    "ghp_",
    "AKIA",
    "%3D",
    "%2",
    '\\"',
    "\\\\n",
    "\\u00",
    "\u200b",
    "\uff53\uff4b",
    "QUFB",
    "A" * 31,
    " ",
    "\n",
)

ADVERSARIAL: dict[str, str] = {
    "pem_begin_repeated": "-----BEGIN OPENSSH PRIVATE KEY-----" * 30_000,
    "a_dot": "a." * (MIB // 2),
    "postgres_scheme": "postgres://" * (MIB // 11),
    "pem_header_then_base64": "-----BEGIN RSA PRIVATE KEY-----\n" + "QUFB" * (MIB // 4),
    "userinfo_colons": "https://u:" + ":" * MIB,
    "dsn_query": "postgres://h/?" + "a=b&" * (MIB // 4),
    "kv_repeated": "password=" * (MIB // 9),
    "json_escapes": '\\"' * (MIB // 2),
    "percent_escapes": "%3D" * (MIB // 3),
    "zero_width": "a\u200b" * (MIB // 2),
    "base64_text": (base64.b64encode(("token: " + "x" * 64 + " ").encode() * 300).decode() + " ")
    * (MIB // 28_801),
    "entropy_run": ("q8ZrT2mVx9LkP4nW7bYc1JdF6hGs3AeU0oRi5tMwQz" * (MIB // 42)),
    "mixed_fragments": "".join(FRAGMENTS) * (MIB // len("".join(FRAGMENTS))),
}


def _time(fn: Any, runs: int = 2) -> float:
    """Best-of-`runs` process CPU time: other processes competing for the machine (a parallel
    suite, CI neighbours) do not count, so the budgets stay tight without flaking."""
    best = float("inf")
    for _ in range(runs):
        started = time.process_time()
        fn()
        best = min(best, time.process_time() - started)
    return best


@pytest.mark.parametrize("name", list(ADVERSARIAL))
@pytest.mark.parametrize("detector", scrub.DETECTORS, ids=[d.id for d in scrub.DETECTORS])
def test_each_detector_is_linear_on_adversarial_input(detector: scrub.Detector, name: str) -> None:
    text = ADVERSARIAL[name]
    elapsed = _time(lambda: detector_spans(text, detector))
    assert elapsed < DETECTOR_BUDGET_S * len(text) / MIB + 0.02, (detector.id, name, elapsed)


@pytest.mark.serial  # timing budget: run alone (ci/run.sh)
@pytest.mark.parametrize("field", [ScrubField.INPUT_MESSAGES, ScrubField.TOOL_ARGS])
@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_whole_scrub_is_bounded_on_adversarial_input(name: str, field: ScrubField) -> None:
    text = ADVERSARIAL[name]
    elapsed = _time(lambda: SCRUBBER.scrub(text, field=field), runs=1)
    assert elapsed < SCRUB_BUDGET_S * len(text) / MIB + 0.05, (name, field, elapsed)


@pytest.mark.serial  # timing budget: run alone (ci/run.sh)
@settings(max_examples=25, deadline=None)
@given(st.lists(st.sampled_from(FRAGMENTS), min_size=1, max_size=40))
def test_generated_adversarial_inputs_stay_linear(parts: list[str]) -> None:
    unit = "".join(parts)
    text = unit * max(1, (256 * 1024) // len(unit))
    for detector in scrub.DETECTORS:
        elapsed = _time(lambda d=detector: detector_spans(text, d))
        assert elapsed < DETECTOR_BUDGET_S * len(text) / MIB + 0.02, (detector.id, parts)
    assert _time(lambda: SCRUBBER.scrub(text, field=ScrubField.TOOL_ARGS)) < (
        SCRUB_BUDGET_S * len(text) / MIB + 0.05
    )


def test_exported_patterns_use_no_backtracking_hazards() -> None:
    """Bounded runs only where a run is followed by more pattern; no nested unbounded
    quantifiers; nothing ECMAScript lacks (possessive, atomic, named groups, \\Z)."""
    for detector in scrub.export_registry()["detectors"]:
        for pattern in detector["patterns"]:
            regex = pattern["regex"]
            for token in ("*+", "++", "?+", "(?>", "(?P<", "\\Z", "[\\s\\S]*", ".*"):
                assert token not in regex, (detector["id"], token)


# --- windowing ---------------------------------------------------------------------------


@pytest.mark.parametrize("offset", [-30, -10, -1, 0, 1, 25])
def test_secret_straddling_a_window_boundary_is_found(offset: int) -> None:
    key = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0" * 2
    start = WINDOW_CHARS + offset
    text = "x " * (start // 2) + " " * (start % 2) + key + " tail"
    assert text.index(key) == start
    result = SCRUBBER.scrub(text)
    assert key not in result.text
    assert [f.detector_id for f in result.findings] == ["github_token"]


def test_pem_spanning_the_overlap_is_found_once() -> None:
    body = "\n".join("QUFB" * 16 for _ in range(60))
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    assert len(pem) < WINDOW_OVERLAP_CHARS
    text = "y" * (WINDOW_CHARS - 100) + "\n" + pem + "\n"
    result = SCRUBBER.scrub(text, field=ScrubField.TOOL_RESULT)
    assert "QUFBQUFB" not in result.text
    assert [f.detector_id for f in result.findings] == ["pem_block"]


def test_input_over_the_cap_is_refused_not_passed_through() -> None:
    small = SecretsScrubber(SALT, max_chars=1000)
    with pytest.raises(ScrubInputTooLarge):
        small.scrub("a" * 1001)
    assert small.scrub("a" * 1000).text == "a" * 1000
    assert MAX_SCRUB_CHARS >= 8 * MIB
    assert issubclass(ScrubInputTooLarge, ValueError)


# --- metamorphic corpus (G0 tests F7) ----------------------------------------------------

SECRET_VARIANTS = scrub_corpus("secrets", variants=True)
BENIGN_VARIANTS = scrub_corpus("false_positives", variants=True)


def test_widened_corpus_has_ten_rows_per_detector() -> None:
    per_detector: dict[str, int] = {}
    for row in SECRET_VARIANTS:
        per_detector[row["detector"]] = per_detector.get(row["detector"], 0) + 1
    assert set(per_detector) == {d.id for d in scrub.DETECTORS}
    assert min(per_detector.values()) >= 10, per_detector
    base = {d.id: 0 for d in scrub.DETECTORS}
    for row in scrub_corpus("secrets"):
        base[row["detector"]] += 1
    assert min(base.values()) >= 5, base


@pytest.mark.parametrize("row", SECRET_VARIANTS, ids=[r["id"] for r in SECRET_VARIANTS])
def test_every_variant_secret_is_scrubbed(row: dict[str, Any]) -> None:
    assert row["secret"] in row["text"]
    result = SCRUBBER.scrub(row["text"], field=ScrubField(row["field"]))
    assert row["secret"] not in result.text
    assert f"secrets.{row['detector']}" in result.rules_fired, result.rules_fired
    again = SCRUBBER.scrub(result.text, field=ScrubField(row["field"]))
    assert again.text == result.text and again.findings == ()


def _longest_common(secret: str, text: str) -> int:
    matcher = SequenceMatcher(None, secret, text, autojunk=False)
    return matcher.find_longest_match(0, len(secret), 0, len(text)).size


@pytest.mark.parametrize("row", SECRET_VARIANTS, ids=[r["id"] for r in SECRET_VARIANTS])
def test_no_eight_character_fragment_of_a_secret_survives(row: dict[str, Any]) -> None:
    out = SCRUBBER.scrub(row["text"], field=ScrubField(row["field"])).text
    assert _longest_common(row["secret"], out) < 8


@pytest.mark.parametrize("row", BENIGN_VARIANTS, ids=[r["id"] for r in BENIGN_VARIANTS])
def test_benign_variants_are_untouched(row: dict[str, Any]) -> None:
    result = SCRUBBER.scrub(row["text"], field=ScrubField(row["field"]))
    assert result.findings == (), [(f.detector_id, f.via) for f in result.findings]
    assert result.text == row["text"]


@pytest.mark.parametrize(
    "row",
    [r for r in SECRET_VARIANTS if r.get("transform") in ("json_escaped", "double_json")],
    ids=lambda r: r["id"],
)
def test_scrubbing_escaped_json_keeps_it_valid_json(row: dict[str, Any]) -> None:
    out = SCRUBBER.scrub(row["text"], field=ScrubField(row["field"])).text
    decoded = json.loads(out)
    if row["transform"] == "double_json":
        json.loads(decoded)


def test_same_secret_gets_the_same_token_in_every_encoding() -> None:
    key = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0" * 2
    raw = SCRUBBER.scrub(f"token {key}").findings[0].replacement
    escaped = SCRUBBER.scrub(json.dumps({"k": f"token {key}"})).findings[0].replacement
    encoded = SCRUBBER.scrub(f"token%20{key}").findings[0].replacement
    assert raw == escaped == encoded


# --- reviewer bypass cases the detector contract deliberately excludes -------------------


@pytest.mark.xfail(
    strict=True,
    reason="quoted multi-word passphrases are indistinguishable from UI copy such as "
    '"password": "Enter your password"; excluded from detectors/v1 (G0 tests F7)',
)
def test_passphrase_with_spaces_is_not_detected() -> None:
    text = 'password = "correct horse battery staple"'
    assert "correct horse battery staple" not in SCRUBBER.scrub(text, field="state").text


# --- lookalike tokens (security L4) ------------------------------------------------------


def test_lookalike_token_does_not_shield_the_rest_of_the_candidate() -> None:
    result = SCRUBBER.scrub("password=hunter2hunter2X[SECRET:00000000]", field="state")
    assert "hunter2hunter2X" not in result.text
    assert result.text.endswith("[SECRET:00000000]")
    assert SCRUBBER.scrub(result.text, field="state").findings == ()


# --- dictionary keys and bytes (security M7) ---------------------------------------------

ANTHROPIC = "sk-ant-api03-" + "QAFIrEEUc5d1BI11bAx_D8Kv5xjY64Y7gxOO6E" + "AA"
SIBYL = "sbl_live_woQZcU1qvzuw_GwvY6aLP4vySLMnlhkIOYLh6XrYf1xBiQN1AZ3mOb__"


def test_scrub_json_scrubs_keys_bytes_and_bytearrays() -> None:
    doc: dict[Any, Any] = {
        ANTHROPIC: 1,
        "nested": {SIBYL: "v", 7: "int key kept"},
        "b": ANTHROPIC.encode(),
        "ba": bytearray(b"key=" + ANTHROPIC.encode()),
        "clean": b"\x89PNG\r\n\x1a\n\x00\xff",
    }
    cleaned, findings = SCRUBBER.scrub_json(doc, field=ScrubField.STATE)
    dumped = repr(cleaned)
    assert ANTHROPIC not in dumped and SIBYL not in dumped
    assert len(findings) == 4
    assert isinstance(cleaned["b"], bytes) and isinstance(cleaned["ba"], bytearray)
    assert cleaned["ba"].startswith(b"key=[SECRET:")
    assert cleaned["clean"] == doc["clean"]  # non-UTF-8 bytes round-trip unchanged
    assert cleaned["nested"][7] == "int key kept"
    assert doc["b"] == ANTHROPIC.encode()  # input not mutated


def test_scrubbed_key_collisions_get_a_suffix() -> None:
    other = "sk-ant-api03-" + "ZZZZrEEUc5d1BI11bAx_D8Kv5xjY64Y7gxOO6E" + "AA"
    salt_twin = SecretsScrubber(SALT)
    token = salt_twin.token("SECRET", ANTHROPIC)
    doc = {ANTHROPIC: 1, token: 2, other: 3}
    cleaned, _ = SCRUBBER.scrub_json(doc)
    assert len(cleaned) == 3
    assert sorted(cleaned.values()) == [1, 2, 3]
    assert any(key.startswith(token + "#") for key in cleaned)


def test_scrub_accepts_bytes_directly() -> None:
    result = SCRUBBER.scrub_bytes(b"key " + ANTHROPIC.encode() + b" \xff")
    assert ANTHROPIC.encode() not in result
    assert result.endswith(b" \xff")
