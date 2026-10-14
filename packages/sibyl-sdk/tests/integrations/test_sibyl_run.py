"""`sibyl-run` / `python -m sibyl.run`: env-configured zero-code monitoring that never stops
the target from starting, plus the framework gate helpers it relies on."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import sibyl
from sibyl import _gate, _obo
from sibyl import run as sibyl_run
from sibyl.testing import TEST_KEY

USER = "0192767f-0000-7000-8000-0000000000aa"

APP = """
import json, sys
import sibyl
from sibyl import _obo
client = sibyl.get_client() if sibyl._state.get() else None
print(json.dumps({
    "argv": sys.argv,
    "name": __name__,
    "initialised": client is not None,
    "obo": _obo.header_value(),
}))
"""


@pytest.fixture
def app(tmp_path: Path) -> Path:
    script = tmp_path / "app.py"
    script.write_text(APP)
    return script


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIBYL_API_KEY", TEST_KEY)
    monkeypatch.setenv("SIBYL_ENDPOINT", "http://127.0.0.1:9")
    monkeypatch.setenv("SIBYL_AGENT_ID", "quote-assistant")
    monkeypatch.setenv("SIBYL_INSTRUMENT", "none")
    monkeypatch.setenv("SIBYL_ON_BEHALF_OF", f"user:{USER}")
    for name in ("SIBYL_DISABLED", "SIBYL_SENSITIVE_TOOLS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sys, "argv", list(sys.argv))
    monkeypatch.setattr(sys, "path", list(sys.path))


def _last_json(out: str) -> dict[str, Any]:
    import json

    return dict(json.loads(out.strip().splitlines()[-1]))


def test_runs_a_script_with_monitoring_and_its_arguments(
    env: None, app: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert sibyl_run.main([str(app), "--flag", "v"]) == 0
    seen = _last_json(capsys.readouterr().out)
    assert seen["argv"] == [str(app), "--flag", "v"] and seen["name"] == "__main__"
    assert seen["initialised"] is True and seen["obo"] == f"user:{USER}"
    assert sibyl.get_client().settings.agent_ref == "quote-assistant"


def test_runs_a_module(
    env: None, app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.syspath_prepend(str(app.parent))
    monkeypatch.delitem(sys.modules, "app", raising=False)
    assert sibyl_run.main(["-m", "app", "x"]) == 0
    seen = _last_json(capsys.readouterr().out)
    assert seen["argv"][1:] == ["x"] and seen["initialised"] is True


def test_bad_configuration_still_runs_the_target_and_never_prints_the_key(
    env: None, app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SIBYL_API_KEY", "sbl_test_short")
    assert sibyl_run.main([str(app)]) == 0
    out, err = capsys.readouterr()
    assert "monitoring disabled" in err and "sbl_test_short" not in err
    assert _last_json(out)["initialised"] is False


def test_disabled_and_unexpected_failures_run_uninstrumented(
    env: None, app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SIBYL_DISABLED", "true")
    assert sibyl_run.setup() == []
    monkeypatch.delenv("SIBYL_DISABLED")

    def boom(**_: Any) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(sibyl, "init", boom)
    assert sibyl_run.setup() == []
    assert "RuntimeError" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "message"),
    [([], "usage"), (["-h"], "usage"), (["-m"], "usage"), (["missing.py"], "no such file")],
)
def test_usage_errors(argv: list[str], message: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert sibyl_run.main(argv) == 2
    assert message in capsys.readouterr().err


def test_instrument_setting_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    for raw, expected in (
        ("", "auto"),
        ("AUTO", "auto"),
        ("off", ()),
        ("openai, langchain", ("openai", "langchain")),
    ):
        monkeypatch.setenv("SIBYL_INSTRUMENT", raw)
        assert sibyl_run._instrument_setting() == expected
    assert sibyl_run._on_behalf_of("external:crm:9") == {"kind": "external", "ref": "crm:9"}
    assert sibyl_run._on_behalf_of("plain-ref") == {"kind": "external", "ref": "plain-ref"}


def test_python_dash_m_sibyl_run_in_a_subprocess(app: Path, tmp_path: Path) -> None:
    child_env = {k: v for k, v in os.environ.items() if not k.startswith("SIBYL_")} | {
        "SIBYL_API_KEY": TEST_KEY,
        "SIBYL_ENDPOINT": "http://127.0.0.1:9",
        "SIBYL_INSTRUMENT": "auto",
        "SIBYL_SENSITIVE_TOOLS": "payments.*",
    }
    done = subprocess.run(  # noqa: S603 - a fixed interpreter and a test-owned script
        [sys.executable, "-m", "sibyl.run", str(app), "a"],
        capture_output=True,
        text=True,
        env=child_env,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    seen = _last_json(done.stdout)
    assert seen["initialised"] is True and seen["argv"] == [str(app), "a"]


def test_gate_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    _gate.set_sensitive(["refund*", " "])
    monkeypatch.setenv("SIBYL_SENSITIVE_TOOLS", "wire, ")
    assert _gate.is_sensitive("refund_all") and _gate.is_sensitive("wire")
    assert not _gate.is_sensitive("lookup")
    assert _gate.tool_args('{"a": 1}') == {"a": 1}
    assert _gate.tool_args("[1, 2]") == {"input": [1, 2]}
    assert _gate.tool_args("plain") == {"input": "plain"}
    assert _gate.tool_args(None) == {}
    assert _gate._call_id("call_ok-1") == "call_ok-1" and _gate._call_id("bad id") is None
    assert _gate.gate("x", {}) is None  # before init()
    assert _gate.run_gated("x", {}, lambda v: v + 1, 1) == 2
    _obo.set_default(None)
