"""``events.scrub_late_hits`` / ``events.scrub_rules_fired`` (migration 0007, INT-1, D12).

Ingest records its own scrub result on the row: how many secrets it found that the emitter
missed, and the detector ids that fired (the emitter's and its own). The DB CHECK allows at most
64 ids, each ``[A-Za-z0-9_.:-]{1,64}``; ingest dedupes, sorts, replaces non-conforming ids with
a marker and caps the list before the insert, so one bad id never fails the event and no raw
text an emitter put in ``rules_fired`` reaches the database.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from sibyl_control.ingest.flusher import flush_tenant
from sibyl_control.ingest.normalise.scrubbing import (
    RULE_ID_INVALID,
    RULES_TRUNCATED,
    rule_ids,
)
from sibyl_schemas.golden import fixtures_root

from .conftest import World
from .otlp_build import chat_attrs, span, traces
from .test_replay import _batch, _feedback
from .test_scrub_e2e import _tool_event

RULE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
CORPUS = [
    json.loads(line)
    for line in (fixtures_root() / "scrub" / "secrets.jsonl").read_text("utf-8").splitlines()
    if line.strip()
]
SECRET = next(r for r in CORPUS if r["detector"] == "openai_key")["text"]


# --- the sanitiser (pure) ------------------------------------------------------------------


def test_rule_ids_dedupes_and_sorts() -> None:
    assert rule_ids(["secrets.b", "pii.email", "secrets.b"]) == ["pii.email", "secrets.b"]
    assert rule_ids(None) == [] and rule_ids([]) == []


def test_rule_ids_replaces_bad_ids_with_one_marker_and_never_keeps_their_text() -> None:
    out = rule_ids(["secrets.ok", f"leak {SECRET}", "", "x" * 65, "é", 7, None, "a,b"])
    assert out == sorted(["secrets.ok", RULE_ID_INVALID])
    assert all(RULE_ID.fullmatch(i) for i in out)
    assert SECRET not in json.dumps(out)


def test_rule_ids_caps_at_64_with_a_truncation_marker() -> None:
    many = [f"secrets.d{i:03d}" for i in range(100)]
    out = rule_ids([*many, "bad id"])
    assert len(out) == 64 and len(set(out)) == 64 and out == sorted(out)
    assert RULE_ID_INVALID in out and RULES_TRUNCATED in out
    assert all(RULE_ID.fullmatch(i) for i in out)
    assert rule_ids(out) == out  # idempotent: the flusher may run it again on a merge
    exactly = [f"r{i:02d}" for i in range(64)]
    assert rule_ids(exactly) == exactly


# --- end to end on PG17 --------------------------------------------------------------------


async def _row(world: World, event_type: str) -> dict:
    row = await world.admin.fetchrow(
        "SELECT scrub_late_hits, scrub_rules_fired, t::text AS whole FROM sibyl.events t"
        " WHERE tenant_id = $1 AND event_type = $2",
        world.tenant_id,
        event_type,
    )
    assert row is not None
    return dict(row)


async def test_clean_event_records_zero_late_hits_and_the_emitter_rules(world: World) -> None:
    event = _feedback(0)
    event["redaction_profile"] = {
        "id": "secrets_only",
        "version": 1,
        "secrets_scrubbed": 1,
        "rules_fired": ["secrets.aws_access_key", "secrets.aws_access_key"],
    }
    resp = await world.post("/v1/events", _batch([event]))
    assert resp.status_code == 202 and resp.json()["accepted"] == 1, resp.text
    row = await _row(world, "feedback")
    assert row["scrub_late_hits"] == 0
    assert row["scrub_rules_fired"] == ["secrets.aws_access_key"]


async def test_over_64_ids_and_a_bad_id_are_capped_not_rejected(world: World) -> None:
    event = _feedback(0)
    event["redaction_profile"] = {
        "id": "secrets_only",
        "version": 1,
        "secrets_scrubbed": 0,
        "rules_fired": [f"custom.rule_{i:03d}" for i in range(90)] + [f"note {SECRET}", ""],
    }
    resp = await world.post("/v1/events", _batch([event]))
    assert resp.status_code == 202 and resp.json()["accepted"] == 1, resp.text
    row = await _row(world, "feedback")
    rules = row["scrub_rules_fired"]
    assert len(rules) == 64 and rules == sorted(rules)
    assert RULE_ID_INVALID in rules and RULES_TRUNCATED in rules
    assert all(RULE_ID.fullmatch(r) for r in rules)
    assert SECRET not in row["whole"] and SECRET[:16] not in row["whole"]


async def test_late_hits_and_rules_reach_the_merged_gen_ai_row(world: World) -> None:
    attrs = chat_attrs(
        **{"gen_ai.input.messages": json.dumps([{"role": "user", "content": SECRET}])}
    )
    resp = await world.post("/v1/otlp/traces", traces([span(attrs)]))
    assert resp.status_code == 200, resp.text
    await flush_tenant(
        world.db, world.tenant_id, world.services.cfg, now=datetime.now(UTC) + timedelta(minutes=1)
    )
    row = await _row(world, "gen_ai.request")
    assert row["scrub_late_hits"] >= 1
    assert "secrets.openai_key" in row["scrub_rules_fired"]
    assert SECRET not in row["whole"]


async def test_late_hits_on_a_direct_event_row(world: World) -> None:
    row_in = next(r for r in CORPUS if r["detector"] == "openai_key")
    resp = await world.post("/v1/events", _batch([_tool_event(row_in, 0)]))
    assert resp.status_code == 202 and resp.json()["accepted"] == 1, resp.text
    row = await _row(world, "tool.call")
    assert row["scrub_late_hits"] >= 1
    assert "secrets.openai_key" in row["scrub_rules_fired"]
    assert SECRET not in row["whole"]
