"""``sibyl-mcp`` entrypoint: configuration errors exit 2 without leaking the key."""

from __future__ import annotations

from typing import Any

import pytest
import sibyl_mcp.__main__ as cli

ANY_HOST = "0.0.0.0"  # noqa: S104 (the warning case)
KEY = "sbl_live_ABCDEFGHIJKL_" + "z" * 43


def test_missing_env_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([], environ={}) == 2
    assert "SIBYL_API_URL" in capsys.readouterr().err
    assert cli.main([], environ={"SIBYL_API_URL": "https://s.example"}) == 2
    assert "SIBYL_MONITOR_KEY" in capsys.readouterr().err


def test_bad_key_is_not_printed(capsys: pytest.CaptureFixture[str]) -> None:
    bad = "sbl_live_short_secretsecret"
    assert (
        cli.main([], environ={"SIBYL_API_URL": "https://s.example", "SIBYL_MONITOR_KEY": bad}) == 2
    )
    assert bad not in capsys.readouterr().err


def test_args() -> None:
    ns = cli.parse_args([])
    assert (ns.transport, ns.host, ns.port) == ("stdio", "127.0.0.1", 8765)
    with pytest.raises(SystemExit):
        cli.parse_args(["--transport", "sse"])


@pytest.mark.parametrize(
    ("argv", "expected", "warns"),
    [
        ([], ("stdio", {}), False),
        (
            ["--transport", "streamable-http", "--port", "9000"],
            ("streamable-http", {"host": "127.0.0.1", "port": 9000}),
            False,
        ),
        (
            ["--transport", "streamable-http", "--host", ANY_HOST],
            ("streamable-http", {"host": ANY_HOST, "port": 8765}),
            True,
        ),
    ],
)
def test_runs_selected_transport(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    expected: tuple[str, dict[str, Any]],
    warns: bool,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class FakeServer:
        def run(self, transport: str, **kw: Any) -> None:
            calls.append((transport, kw))

    monkeypatch.setattr(cli, "build_server", lambda client, close_client: FakeServer())
    env = {"SIBYL_API_URL": "https://s.example", "SIBYL_MONITOR_KEY": KEY}
    assert cli.main(argv, environ=env) == 0
    assert calls == [expected]
    err = capsys.readouterr().err
    assert ("no auth" in err) is warns and KEY not in err
