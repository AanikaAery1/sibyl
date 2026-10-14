"""Contract over real HTTP: a loopback ingest speaking API §4 (recorded response fixtures),
schema conformance of everything the SDK sends, batch replay, and the runnable example."""

from __future__ import annotations

import runpy
import subprocess
import sys
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import sibyl
from pydantic import TypeAdapter
from sibyl._localstub import LocalIngest
from sibyl.testing import TEST_KEY, wait_for
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.models import IngestResponse, WireEvent

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "quickstart.py"


@pytest.fixture
def stub() -> Iterator[LocalIngest]:
    server = LocalIngest().start()
    yield server
    server.stop()


def _init(stub: LocalIngest, tmp_path: Path, **extra: Any) -> sibyl.Client:
    return sibyl.init(
        TEST_KEY,
        endpoint=stub.url,
        agent_id="quote-assistant",
        exporter=sibyl.ExporterConfig(schedule_delay=timedelta(milliseconds=20)),
        policy=sibyl.PolicyConfig(
            public_key=stub.snapshots.signer.pin(),
            cache_dir=str(tmp_path),
            poll_interval=timedelta(hours=1),
        ),
        **extra,
    )


def test_everything_sent_over_http_conforms(stub: LocalIngest, tmp_path: Path) -> None:
    client = _init(stub, tmp_path)
    assert wait_for(lambda: client.snapshot is not None)
    with sibyl.agent(goal="Quote A-1") as run:
        sibyl.checkpoint({"step": 1}, step="s1", pending=["s2"])
        sibyl.feedback(1)
        run.outcome("success")
    assert sibyl.flush(timedelta(seconds=5))
    events = stub.events()
    assert {e["type"] for e in events} >= {"agent.invoke", "checkpoint", "feedback", "task.outcome"}
    adapter = TypeAdapter(WireEvent)
    for event in events:
        assert sj.is_valid("sibyl-event-wire/1", event)
        adapter.validate_python(event)
    headers = next(r["headers"] for r in stub.received if r["path"] == "/v1/events")
    assert headers["X-Sibyl-Schema"] == "sibyl-event/1"
    assert headers["Content-Encoding"] == "gzip"
    assert {s["name"] for s in stub.spans()} == {"invoke_agent quote-assistant"}


def test_ingest_response_fixtures_parse() -> None:
    from sibyl_schemas.golden import load_fixture

    for name in ("response_partial.json", "response_replayed.json"):
        IngestResponse.model_validate(load_fixture("ingest", f"valid/{name}"))


def test_retryable_status_replays_the_same_batch(stub: LocalIngest, tmp_path: Path) -> None:
    stub.fail_next = [503]
    _init(stub, tmp_path)
    with sibyl.agent("a"):
        pass
    assert sibyl.flush(timedelta(seconds=5))
    assert len(stub.events()) == 1  # replay accepted once, never duplicated


def test_example_runs_offline(capsys: pytest.CaptureFixture[str]) -> None:
    module = runpy.run_path(str(EXAMPLE))
    assert module["main"]([]) == 0
    out = capsys.readouterr().out
    assert "flushed=True policy=active" in out
    assert "event  checkpoint" in out and "span   execute_tool lookup_order" in out


def test_example_runs_as_a_script() -> None:
    result = subprocess.run(  # noqa: S603 (fixed argv, our own example)
        [sys.executable, str(EXAMPLE)], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "ingest received" in result.stdout
