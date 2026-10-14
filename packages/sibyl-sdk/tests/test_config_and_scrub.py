"""`init()` configuration resolution and the scrub pipeline (floor → hooks → capture gate)."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from sibyl._config import ExporterConfig, PolicyConfig, parse_key, resolve, scrub_salt
from sibyl._errors import SibylConfigError
from sibyl._scrub import ScrubContext, ScrubPipeline
from sibyl._types import most_restrictive
from sibyl.testing import TEST_KEY
from sibyl_schemas.golden import fixtures_root
from sibyl_schemas.scrub import ScrubInputTooLarge

SALT = b"0123456789abcdef0123456789abcdef"
CTX = ScrubContext(part="input_messages", agent_id=None, task_id=None, call_id=None)


def _resolve(**overrides: Any) -> Any:
    args: dict[str, Any] = {
        "api_key": TEST_KEY,
        "endpoint": "http://127.0.0.1:8445",
        "agent_id": "quote-assistant",
        "capture_mode": None,
        "env": None,
        "fail_mode": None,
        "instrument": "auto",
        "exporter": None,
        "policy": None,
        "resource_attributes": None,
    }
    args.update(overrides)
    return resolve(**args)


def test_explicit_args_resolve() -> None:
    settings = _resolve()
    assert settings.env == "test" and settings.capture_mode == "full"
    assert settings.api_endpoint == "http://127.0.0.1:8445"
    assert settings.instrument == (
        "openai",
        "anthropic",
        "google",
        "langchain",
        "openai_agents",
        "crewai",
        "mcp",
        "httpx",
    )
    assert TEST_KEY not in repr(settings)


def test_env_var_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIBYL_API_KEY", TEST_KEY)
    monkeypatch.setenv("SIBYL_ENDPOINT", "https://ingest.example/")
    monkeypatch.setenv("SIBYL_AGENT_ID", "agent-x")
    monkeypatch.setenv("SIBYL_CAPTURE_MODE", "metadata")
    monkeypatch.setenv("SIBYL_API_URL", "https://api.example")
    settings = _resolve(api_key=None, endpoint=None, agent_id=None)
    assert settings.endpoint == "https://ingest.example"
    assert settings.api_endpoint == "https://api.example"
    assert settings.agent_ref == "agent-x" and settings.capture_mode == "metadata"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"api_key": None}, "no API key"),
        ({"api_key": "sk-not-a-sibyl-key"}, "sbl_"),
        ({"endpoint": None}, "no ingest endpoint"),
        ({"endpoint": "ftp://x"}, "http"),
        ({"endpoint": "https://user:pw@x"}, "credentials"),
        ({"capture_mode": "everything"}, "capture_mode"),
        ({"env": "live"}, "does not match"),
        ({"env": "prod"}, "env must be"),
        ({"fail_mode": "maybe"}, "fail_mode"),
        ({"instrument": ["openai", "llamaindex"]}, "cannot instrument"),
        ({"instrument": "openai"}, "auto"),
    ],
)
def test_config_errors(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(SibylConfigError, match=message):
        _resolve(**overrides)


def test_config_objects_validate() -> None:
    with pytest.raises(SibylConfigError):
        ExporterConfig(batch_size=0)
    with pytest.raises(SibylConfigError):
        ExporterConfig(schedule_delay=timedelta(0))
    with pytest.raises(SibylConfigError):
        PolicyConfig(poll_interval=timedelta(0))


def test_salt_prefers_platform_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    key = parse_key(TEST_KEY)
    derived = scrub_salt(key)
    assert len(derived) == 32 and key.secret.encode() not in derived
    monkeypatch.setenv("SIBYL_SCRUB_SALT", "s" * 32)
    assert scrub_salt(key) == b"s" * 32


def test_most_restrictive() -> None:
    assert most_restrictive("full", "metadata") == "metadata"
    assert most_restrictive("full", "redacted") == "redacted"


def _secrets() -> list[str]:
    path = fixtures_root() / "scrub" / "secrets.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [
        row.get("text") or row.get("input")
        for row in rows
        if row.get("field", "input_messages") in ("input_messages", None)
    ][:20]


def test_secrets_floor_runs_before_hooks() -> None:
    seen: list[str] = []

    def hook(text: str, ctx: ScrubContext) -> str:
        seen.append(text)
        return text

    secret = "key: sk-proj-" + "a1B2c3D4e5F6g7H8i9J0" * 3
    result = ScrubPipeline(SALT, [hook]).run(secret, CTX, "full")
    assert "sk-proj-" not in seen[0]  # the hook only ever saw scrubbed text
    assert result.secrets_scrubbed >= 1
    assert result.text is not None and "sk-proj-a1B2" not in result.text
    assert "sdk.hook:hook" in result.rules
    assert any(rule.startswith("secrets.") for rule in result.rules)


def test_corpus_samples_are_scrubbed() -> None:
    pipeline = ScrubPipeline(SALT)
    samples = [s for s in _secrets() if s]
    assert samples
    for sample in samples:
        assert pipeline.run(sample, CTX, "full").secrets_scrubbed >= 1, sample


def test_hooks_run_in_order() -> None:
    def first(text: str, ctx: ScrubContext) -> str:
        return text.replace("ACME", "[CUST]")

    def second(text: str, ctx: ScrubContext) -> str:
        return text.replace("[CUST]", "[CUSTOMER]")

    result = ScrubPipeline(SALT, [first, second]).run("order for ACME", CTX, "full")
    assert result.text == "order for [CUSTOMER]"
    assert result.rules[-2:] == ("sdk.hook:first", "sdk.hook:second")


@pytest.mark.parametrize("bad", ["raise", "non_string"])
def test_hook_failure_downgrades_part_to_metadata(bad: str) -> None:
    def broken(text: str, ctx: ScrubContext) -> str:
        if bad == "raise":
            raise RuntimeError("boom")
        return 42  # type: ignore[return-value]

    pipeline = ScrubPipeline(SALT, [broken])
    result = pipeline.run("customer ACME", CTX, "full")
    assert result.text is None and result.mode == "metadata" and result.hook_failed
    assert len(result.sha256) == 64
    if bad == "raise":
        assert pipeline.hook_errors == 1


def test_metadata_mode_ships_hash_and_length_only() -> None:
    result = ScrubPipeline(SALT).run("hello world", CTX, "metadata")
    assert result.text is None and result.chars == 11 and len(result.sha256) == 64


def test_oversize_input_is_refused_not_passed_through() -> None:
    with pytest.raises(ScrubInputTooLarge):
        ScrubPipeline(SALT).run("x" * (16 * 1024 * 1024 + 1), CTX, "full")
