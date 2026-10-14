"""examples/monitors: every module imports without keys or agent SDKs; pure logic is tested."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from sibyl.monitor import AsyncClient, Client
from sibyl_schemas.webhook_signature import signature_header

ROOT = Path(__file__).resolve().parents[3] / "examples" / "monitors"
MODULES = [
    "rules_monitor.py",
    "webhook_receiver.py",
    "gemini_monitor.py",
    "openai_agents_monitor.py",
    "claude_mcp/agent_sdk_monitor.py",
]
KEY = "sbl_test_ABCDEFGHIJKL_" + "e" * 43
SECRET = "whsec_" + "w" * 43
A = "0190f1c2-0000-7000-8000-0000000000aa"
B = "0190f1c2-0000-7000-8000-0000000000bb"
ENV_VARS = (
    "SIBYL_API_URL",
    "SIBYL_MONITOR_KEY",
    "SIBYL_WEBHOOK_SECRET",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
)


def _load(rel: str) -> ModuleType:
    path = ROOT / rel
    name = "example_" + rel.replace("/", "_").removesuffix(".py")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("rel", MODULES)
def test_example_imports_without_keys(rel: str) -> None:
    module = _load(rel)
    assert callable(module.main)


def test_config_snippets_are_json() -> None:
    for name in ("claude_desktop_config.json", "mcp.json"):
        doc = json.loads((ROOT / "claude_mcp" / name).read_text())
        assert doc["mcpServers"]["sibyl"]["command"] == "sibyl-mcp"
    assert "sbl_" not in (ROOT / "claude_mcp" / "claude_desktop_config.json").read_text()


def test_claude_example_uses_the_model_and_all_tools() -> None:
    module = _load("claude_mcp/agent_sdk_monitor.py")
    from sibyl_mcp.server import TOOL_NAMES

    assert module.MODEL == "claude-fable-5-1"
    assert sorted(module.SIBYL_TOOLS) == sorted(TOOL_NAMES)
    assert module.sibyl_server()["command"] == "sibyl-mcp"


def test_rules_evaluate() -> None:
    rules = _load("rules_monitor.py")
    runs = [{"agent_id": A}] * 5 + [{"agent_id": B}] * 2 + [{"agent_id": None}]
    drafts = rules.evaluate(
        [{"id": A, "name": "pay"}], [{"id": B, "slug": "quote"}], runs, threshold=5
    )
    assert [(d.rule, d.agent_id, d.severity, d.raise_alert) for d in drafts] == [
        ("band_failed", A, "critical", None),
        ("band_degraded", B, "warning", False),
        ("failed_runs", A, "warning", True),
    ]
    now = datetime(2026, 10, 14, 9, 30, tzinfo=UTC)
    assert drafts[0].idempotency_key(now) == f"rules:band_failed:{A}:20261014T09"


def test_rules_run_once_submits_with_stable_keys() -> None:
    rules = _load("rules_monitor.py")
    posted: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posted.append(request)
            return httpx.Response(201, json={"id": B})
        band = request.url.params.get("band")
        data = [{"id": A, "name": "pay"}] if band == "failed" else []
        return httpx.Response(200, json={"data": data, "next_cursor": None, "has_more": False})

    client = Client("https://s.example", KEY, transport=httpx.MockTransport(respond))
    now = datetime(2026, 10, 14, 9, 30, tzinfo=UTC)
    assert rules.run_once(client, now=now, threshold=3) == 1
    body = json.loads(posted[0].content)
    assert body["severity"] == "critical" and body["body"]["rule"] == "band_failed"
    assert posted[0].headers["idempotency-key"] == f"rules:band_failed:{A}:20261014T09"


def test_gemini_concerns_are_filtered() -> None:
    gemini = _load("gemini_monitor.py")
    text = json.dumps(
        {
            "concerns": [
                {"agent_id": A, "severity": "warning", "summary": "s", "recommendation": "r"},
                {
                    "agent_id": "made-up",
                    "severity": "critical",
                    "summary": "s",
                    "recommendation": "r",
                },
                {"agent_id": A, "severity": "urgent", "summary": "s", "recommendation": "r"},
            ]
        }
    )
    assert [c["agent_id"] for c in gemini.concerns_from(text, {A})] == [A]


def test_openai_example_passes_only_sibyl_env(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load("openai_agents_monitor.py")
    monkeypatch.setenv("SIBYL_MONITOR_KEY", KEY)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-for-the-subprocess")
    env = module.server_env()
    assert env["SIBYL_MONITOR_KEY"] == KEY and "OPENAI_API_KEY" not in env


def _receiver() -> tuple[Any, list[httpx.Request]]:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    receiver = _load("webhook_receiver.py")
    posted: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        posted.append(request)
        return httpx.Response(201, json={"id": B})

    client = AsyncClient("https://s.example", KEY, transport=httpx.MockTransport(respond))
    app = receiver.create_app(SECRET, client, frozenset({"transfer_funds"}))
    return TestClient(app), posted


def _post(http: Any, event: dict[str, Any], *, secret: str = SECRET, ts: int | None = None) -> Any:
    raw = json.dumps(event).encode()
    headers = {
        "Sibyl-Signature": signature_header(secret, raw, timestamp=ts),
        "Sibyl-Event-Id": str(event["id"]),
        "Content-Type": "application/json",
    }
    return http.post("/sibyl/webhook", content=raw, headers=headers)


def test_webhook_receiver_flow() -> None:
    http, posted = _receiver()
    run_failed = {"id": "e1", "type": "run.failed", "data": {"run_id": A}}
    assert _post(http, run_failed).json() == {"status": "finding"}
    assert _post(http, run_failed).json() == {"status": "duplicate"}
    body = json.loads(posted[0].content)
    assert body["subject_kind"] == "run" and body["subject_id"] == A
    assert posted[0].headers["idempotency-key"] == "webhook:e1"
    held = {
        "id": "e2",
        "type": "action.held",
        "data": {"held_action_id": B, "tool": "transfer_funds"},
    }
    assert _post(http, held).json() == {"status": "advice"}
    assert json.loads(posted[1].content)["advice"] == "needs_more_info"
    other = {"id": "e3", "type": "action.held", "data": {"held_action_id": B, "tool": "search"}}
    assert _post(http, other).json() == {"status": "ignored"}
    assert _post(http, {"id": "e4", "type": "ping", "data": {}}).json() == {"status": "ignored"}
    assert len(posted) == 2


def test_webhook_receiver_rejects_bad_signatures() -> None:
    http, posted = _receiver()
    event = {"id": "e9", "type": "run.failed", "data": {"run_id": A}}
    assert _post(http, event, secret="whsec_" + "x" * 43).status_code == 400
    assert _post(http, event, ts=1).status_code == 400
    assert http.post("/sibyl/webhook", content=b"{}").status_code == 400
    assert posted == []


def test_webhook_receiver_needs_a_secret() -> None:
    receiver = _load("webhook_receiver.py")
    with pytest.raises(RuntimeError, match="SIBYL_WEBHOOK_SECRET"):
        receiver.create_app()


def test_seen_events_is_bounded() -> None:
    receiver = _load("webhook_receiver.py")
    seen = receiver.SeenEvents(maximum=2)
    assert seen.add("a") and seen.add("b") and seen.add("c")
    assert seen.add("a")  # forgotten (oldest)
    assert not seen.add("c")
