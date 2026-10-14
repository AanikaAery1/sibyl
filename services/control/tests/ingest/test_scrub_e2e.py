"""Scrub enforcement (D12, security-auditor §5): no secret from the ``sibyl-schemas`` corpus
reaches the database or a blob, whatever surface it arrives on.

Every corpus secret is sent through ``/v1/events`` (payload bodies by part, ``attrs`` strings,
the agent claim) and OTLP spans (content attributes, plain attributes, span names, the agent
claim). Afterwards the tenant's whole footprint is searched: every row of every table ingest
writes or causes (rendered as text) and every blob under the tenant prefix, decrypted. A
secret counts as leaked if it, its JSON-escaped form, or any 16-character window of it appears.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sibyl_control.core.crypto.sealed import open_payload
from sibyl_control.ingest.flusher import flush_tenant
from sibyl_control.ingest.ids import uuid7
from sibyl_schemas.golden import fixtures_root

from .conftest import FIXTURE_AGENT, World
from .otlp_build import chat_attrs, span, traces
from .test_replay import _batch

CORPUS = [
    json.loads(line)
    for line in (fixtures_root() / "scrub" / "secrets.jsonl").read_text("utf-8").splitlines()
    if line.strip()
]
PARTS = {
    "input_messages",
    "output_messages",
    "system_instructions",
    "tool_definitions",
    "tool_args",
    "tool_result",
    "state",
    "comment",
}
TABLES = (
    "events",
    "events_rejected",
    "payload_refs",
    "call_merge",
    "ingest_batch_seen",
    "checkpoint",
    "agent",
    "audit_events",
)
WINDOW = 16


def _tool_event(row: dict[str, Any], i: int) -> dict[str, Any]:
    part = row["field"] if row["field"] in PARTS - {"state", "comment"} else "tool_args"
    body = json.dumps({part: row["text"]})
    return {
        "schema": "sibyl-event/1",
        "event_id": str(uuid7()),
        "type": "tool.call",
        "tenant_id": str(FIXTURE_AGENT),
        "agent_id": str(FIXTURE_AGENT),
        "ts": "2026-10-10T10:00:00.000000Z",
        "source": "sdk",
        "emitter_id": "sdk:scrub:1",
        "seq": i,
        "capture_mode": "full",
        "redaction_profile": {"id": "secrets_only", "version": 1, "secrets_scrubbed": 0},
        "policy_state": {"state": "fresh"},
        "attrs": {
            "tool_name": "lookup",
            "tool_type": "function",
            "status": "error",
            "error_type": row["text"],
            "latency_ms": 3,
            "payload_inline": {
                "encoding": "base64",
                "data": base64.b64encode(body.encode()).decode(),
                "content_type": "application/json",
                "parts": [part],
            },
        },
    }


def _checkpoint_event(row: dict[str, Any], i: int) -> dict[str, Any]:
    checkpoint_id = str(uuid7())
    doc = {
        "schema": "sibyl-checkpoint/1",
        "checkpoint_id": checkpoint_id,
        "state": {"note": row["text"]},
        "goal": row["text"],
    }
    return {
        "schema": "sibyl-event/1",
        "event_id": str(uuid7()),
        "type": "checkpoint",
        "tenant_id": str(FIXTURE_AGENT),
        "agent_id": str(FIXTURE_AGENT),
        "task_id": str(uuid7()),
        "ts": "2026-10-10T10:00:00.000000Z",
        "source": "sdk",
        "emitter_id": "sdk:scrub:1",
        "seq": i,
        "capture_mode": "full",
        "redaction_profile": {"id": "secrets_only", "version": 1, "secrets_scrubbed": 0},
        "policy_state": {"state": "fresh"},
        "attrs": {
            "checkpoint_id": checkpoint_id,
            "seq": 1,
            "step_index": 0,
            "state_bytes": 10,
            "completed_count": 0,
            "pending_count": 0,
            "step_name": row["text"][:500],
            "payload_inline": {
                "encoding": "utf8",
                "data": json.dumps(doc),
                "content_type": "application/vnd.sibyl.checkpoint+json",
                "parts": ["state"],
            },
        },
    }


def _feedback_event(row: dict[str, Any], i: int) -> dict[str, Any]:
    return {
        "schema": "sibyl-event/1",
        "event_id": str(uuid7()),
        "type": "feedback",
        "tenant_id": str(FIXTURE_AGENT),
        "agent_id": row["text"][:200],
        "ts": "2026-10-10T10:00:00.000000Z",
        "source": "sdk",
        "emitter_id": row["text"],
        "seq": i,
        "capture_mode": "full",
        "redaction_profile": {"id": "secrets_only", "version": 1, "secrets_scrubbed": 0},
        "policy_state": {"state": "fresh"},
        "attrs": {
            "feedback_id": str(uuid7()),
            "target": {"kind": "trace", "id": row["text"]},
            "score": 0,
            "scale": "thumbs",
            "rater": "end_user",
            "tags": [row["text"]],
            "payload_inline": {
                "encoding": "utf8",
                "data": row["text"],
                "content_type": "text/plain",
                "parts": ["comment"],
            },
        },
    }


def _span(row: dict[str, Any]) -> dict[str, Any]:
    attrs = chat_attrs(
        **{
            "gen_ai.input.messages": json.dumps([{"role": "user", "content": row["text"]}]),
            "gen_ai.system_instructions": row["text"],
            "error.type": row["text"],
            "sibyl.agent_id": row["text"],
            "server.address": row["text"],
        }
    )
    return span(attrs, name=row["text"][:300])


async def _footprint(world: World) -> str:
    chunks = []
    for table in TABLES:
        rows = await world.rows(
            f"SELECT t::text AS r FROM sibyl.{table} t WHERE tenant_id = $1",  # noqa: S608
            world.tenant_id,
        )
        chunks.extend(r["r"] for r in rows)
    deks = world.services.service.deks  # type: ignore[union-attr]
    for key in await world.blob.list_prefix(f"tenant/{world.tenant_id}/", limit=100_000):
        object_id = UUID(Path(key).stem)
        chunks.append(
            (await open_payload(world.blob, deks, world.tenant_id, key, object_id)).decode(
                "utf-8", "replace"
            )
        )
    return "\n".join(chunks)


def _leaks(secret: str, haystack: str) -> list[str]:
    forms = {secret, json.dumps(secret)[1:-1]}
    found = [f for f in forms if f in haystack]
    for start in range(0, max(1, len(secret) - WINDOW + 1)):
        window = secret[start : start + WINDOW]
        if len(window) == WINDOW and window.strip() == window and window in haystack:
            found.append(window)
            break
    return found


@pytest.mark.parametrize("surface", ["events", "otlp"])
async def test_no_corpus_secret_reaches_the_database_or_a_blob(world: World, surface: str) -> None:
    if surface == "events":
        events = []
        for i, row in enumerate(CORPUS):
            events += [_tool_event(row, i), _checkpoint_event(row, i), _feedback_event(row, i)]
        for start in range(0, len(events), 300):
            resp = await world.post("/v1/events", _batch(events[start : start + 300]))
            assert resp.status_code == 202, resp.text
    else:
        resp = await world.post("/v1/otlp/traces", traces([_span(row) for row in CORPUS]))
        assert resp.status_code == 200, resp.text
    await flush_tenant(
        world.db, world.tenant_id, world.services.cfg, now=datetime.now(UTC) + timedelta(minutes=1)
    )
    assert (
        await world.val("SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", world.tenant_id)
        > 0
    )
    haystack = await _footprint(world)
    leaked = {row["id"]: _leaks(row["secret"], haystack) for row in CORPUS}
    if any(leaked.values()):
        for chunk in haystack.split("\n"):
            for k, v in leaked.items():
                if v and v[-1] in chunk:
                    i = chunk.index(v[-1])
                    print("LEAK", k, repr(chunk[max(0, i - 300) : i + 80]))
    assert {k: v for k, v in leaked.items() if v} == {}


async def test_late_hits_are_recorded_on_the_canonical_event(world: World) -> None:
    secret = next(r for r in CORPUS if r["detector"] == "openai_key")
    resp = await world.post("/v1/otlp/traces", traces([_span(secret)]))
    assert resp.status_code == 200
    contribution = await world.val(
        "SELECT sdk_contribution::text FROM sibyl.call_merge WHERE tenant_id = $1", world.tenant_id
    )
    record = json.loads(contribution)["event"]["redaction_profile"]
    assert record["late_hits"] >= 1 and record["secrets_scrubbed"] >= 1
    assert any(rule.startswith("secrets.") for rule in record["rules_fired"])
