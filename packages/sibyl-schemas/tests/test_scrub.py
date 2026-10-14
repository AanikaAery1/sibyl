"""Unconditional secrets scrubber (D12, API §10.3, security-auditor §5)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from sibyl_schemas import scrub
from sibyl_schemas.canonical import canonical_sha256
from sibyl_schemas.golden import scrub_corpus
from sibyl_schemas.scrub import (
    DETECTORS,
    PROFILE_HASH,
    REPLACEMENT_PATTERN,
    ScrubField,
    SecretsScrubber,
)

SALT = b"test-salt-not-a-platform-secret!"
SECRETS = scrub_corpus("secrets")
FALSE_POSITIVES = scrub_corpus("false_positives")
SCRUBBER = SecretsScrubber(SALT)


def test_registry_has_the_contract_detectors_in_priority_order() -> None:
    assert [d.id for d in DETECTORS] == [
        "sibyl_key",
        "anthropic_key",
        "openai_key",
        "stripe_key",
        "github_token",
        "gitlab_token",
        "huggingface_token",
        "slack_token",
        "slack_webhook",
        "google_api_key",
        "aws_access_key",
        "aws_secret_key",
        "gcp_sa_key",
        "azure_conn_string",
        "jwt",
        "ssh_key",
        "pem_block",
        "dsn",
        "basic_auth_url",
        "bearer_header",
        "basic_auth_header",
        "generic_secret_kv",
        "high_entropy",
    ]
    assert {d.kind for d in DETECTORS} == {"SECRET", "TOKEN", "PRIVATE_KEY", "ENTROPY"}


def test_corpus_sizes_meet_the_gate() -> None:
    assert len(SECRETS) >= 130
    assert len(FALSE_POSITIVES) >= 60
    covered = {row["detector"] for row in SECRETS}
    assert covered == {d.id for d in DETECTORS}
    assert len({row["id"] for row in SECRETS}) == len(SECRETS)


@pytest.mark.parametrize("row", SECRETS, ids=[r["id"] for r in SECRETS])
def test_every_corpus_secret_is_detected(row: dict[str, Any]) -> None:
    assert row["secret"] in row["text"]
    result = SCRUBBER.scrub(row["text"], field=ScrubField(row["field"]))
    assert row["secret"] not in result.text
    assert f"secrets.{row['detector']}" in result.rules_fired, result.rules_fired
    assert result.secrets_scrubbed >= 1
    assert REPLACEMENT_PATTERN.search(result.text)


@pytest.mark.parametrize("row", FALSE_POSITIVES, ids=[r["id"] for r in FALSE_POSITIVES])
def test_false_positive_corpus_is_untouched(row: dict[str, Any]) -> None:
    result = SCRUBBER.scrub(row["text"], field=ScrubField(row["field"]))
    assert result.findings == (), [f.detector_id for f in result.findings]
    assert result.text == row["text"]


def test_detection_rate_and_false_positive_rate() -> None:
    detected = sum(
        row["secret"] not in SCRUBBER.scrub(row["text"], field=ScrubField(row["field"])).text
        for row in SECRETS
    )
    flagged = sum(
        bool(SCRUBBER.scrub(row["text"], field=ScrubField(row["field"])).findings)
        for row in FALSE_POSITIVES
    )
    assert (detected, flagged) == (len(SECRETS), 0)


@pytest.mark.parametrize("row", SECRETS, ids=[r["id"] for r in SECRETS])
def test_scrubbing_is_idempotent(row: dict[str, Any]) -> None:
    once = SCRUBBER.scrub(row["text"], field=ScrubField(row["field"]))
    twice = SCRUBBER.scrub(once.text, field=ScrubField(row["field"]))
    assert twice.text == once.text
    assert twice.findings == ()


def test_replacement_is_salted_hash8_of_the_match() -> None:
    key = "sk-proj-" + "Ab3" * 15
    result = SCRUBBER.scrub(f"key={key}")
    hash8 = hashlib.sha256(SALT + key.encode()).hexdigest()[:8]
    assert result.text == f"key=[SECRET:{hash8}]"
    other = SecretsScrubber(b"another-salt-of-sixteen+").scrub(f"key={key}")
    assert other.text != result.text


def test_same_secret_maps_to_same_token_and_findings_hide_the_secret() -> None:
    key = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0" * 2
    result = SCRUBBER.scrub(f"first {key} then again {key}")
    tokens = REPLACEMENT_PATTERN.findall(result.text)
    assert len(tokens) == 2 and tokens[0] == tokens[1]
    for finding in result.findings:
        assert key not in repr(finding)


def test_value_only_detectors_keep_the_key_name() -> None:
    result = SCRUBBER.scrub('DB_PASSWORD="Tr0ub4dor&3xyzzy"', field=ScrubField.STATE)
    assert result.text.startswith('DB_PASSWORD="[SECRET:')
    bearer = SCRUBBER.scrub("Authorization: Bearer abcdEFGH1234ijklMNOP5678", field="header")
    assert bearer.text.startswith("Authorization: Bearer [TOKEN:")


def test_high_entropy_only_in_headers_tool_args_and_state() -> None:
    blob = "q8ZrT2mVx9LkP4nW7bYc1JdF6hGs3AeU0oRi5tMwQz"
    assert SCRUBBER.scrub(f"x-session: {blob}", field=ScrubField.HEADER).findings
    assert SCRUBBER.scrub(json.dumps({"blob": blob}), field=ScrubField.TOOL_ARGS).findings
    assert not SCRUBBER.scrub(
        f"The reference is {blob}.", field=ScrubField.OUTPUT_MESSAGES
    ).findings


def test_scrub_json_walks_every_string_leaf() -> None:
    doc: dict[str, Any] = {"a": ["ok", {"k": "token: 9f8e7d6c5b4a39281706"}], "n": 3, "b": None}
    cleaned, findings = SCRUBBER.scrub_json(doc, field=ScrubField.STATE)
    assert cleaned["a"][0] == "ok" and cleaned["n"] == 3 and cleaned["b"] is None
    assert "9f8e7d6c5b4a39281706" not in json.dumps(cleaned)
    assert [f.detector_id for f in findings] == ["generic_secret_kv"]
    assert doc["a"][1]["k"] == "token: 9f8e7d6c5b4a39281706"  # input not mutated


def test_salt_must_be_long_enough() -> None:
    with pytest.raises(ValueError, match="salt"):
        SecretsScrubber(b"short")


def test_profile_hash_is_jcs_of_detectors_pipeline_and_replacement_format() -> None:
    document = scrub.profile_document()
    assert set(document) == {"detectors", "pipeline", "replacement_format"}
    assert document["replacement_format"] == "[{kind}:{hash8}]"
    assert canonical_sha256(document) == PROFILE_HASH
    assert re.fullmatch(r"[0-9a-f]{64}", PROFILE_HASH)


def test_exported_registry_matches_code() -> None:
    exported = json.loads((Path(scrub.__file__).parent / "detectors.v1.json").read_text("utf-8"))
    assert exported == scrub.export_registry()
    assert exported["content_hash"] == PROFILE_HASH
    assert exported["registry"] == "detectors/v1"


def test_exported_patterns_are_portable_to_ecmascript() -> None:
    for detector in scrub.export_registry()["detectors"]:
        for pattern in detector["patterns"]:
            assert "(?i)" not in pattern["regex"] and "(?s)" not in pattern["regex"]
            assert set(pattern["flags"]) <= {"i", "s"}
            assert "\\Z" not in pattern["regex"] and "(?P<" not in pattern["regex"]


def test_scrub_result_summary_fields() -> None:
    result = SCRUBBER.scrub("AKIAQ7XKJ2M4N6P8R0TB and AKIAZ1Y2X3W4V5U6T7SR")
    assert result.secrets_scrubbed == 2
    assert result.rules_fired == ("secrets.aws_access_key",)
    assert [f.start for f in result.findings] == sorted(f.start for f in result.findings)
