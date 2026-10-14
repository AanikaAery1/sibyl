"""Golden ingest fixtures from ``sibyl-schemas`` end to end into PG17.

Every valid fixture lands (``events``, or ``call_merge`` then ``events`` after a flush); every
invalid element is a per-event rejection with a schema reason; invalid batches are problems.
Fixture timestamps are moved to "now" so the test never ages out of retention; nothing else
in the documents changes. Responses validate against ``sibyl-ingest-response/1``.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sibyl_control.ingest.flusher import flush_tenant
from sibyl_control.ingest.normalise.fields import rfc3339
from sibyl_schemas.golden import golden_cases
from sibyl_schemas.jsonschema import is_valid, validate

from .conftest import World

CASES = golden_cases("ingest")
VALID_EVENTS = [c for c in CASES if c.valid and c.schema == "sibyl-event/1"]
VALID_WIRE = [
    c for c in CASES if c.valid and c.schema == "sibyl-event-wire/1" and c.pointer is None
]


def _as_wire(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if k not in ("observed_at", "ingest")}


# A canonical-only violation the wire form legitimately allows (payload_inline) is not an
# ingest rejection; it is excluded here rather than skipped.
INVALID_ELEMENTS = [
    c
    for c in CASES
    if not c.valid
    and c.pointer is None
    and (
        c.schema == "sibyl-event-wire/1"
        or (c.schema == "sibyl-event/1" and not is_valid("sibyl-event-wire/1", _as_wire(c.load())))
    )
]
REASONS = {"schema_invalid", "missing_required", "unknown_type"}


def _now_ts(doc: dict[str, Any]) -> dict[str, Any]:
    doc = copy.deepcopy(doc)
    if isinstance(doc.get("ts"), str):
        doc["ts"] = rfc3339(datetime.now(UTC) - timedelta(minutes=1))
    return doc


def _wire(doc: dict[str, Any]) -> dict[str, Any]:
    doc = _now_ts(doc)
    doc.pop("observed_at", None)
    doc.pop("ingest", None)
    attrs = doc.get("attrs", {})
    if isinstance(attrs, dict) and isinstance(attrs.get("payload"), dict):
        attrs.pop(
            "payload"
        )  # a canonical PayloadRef is ingest-authored; the wire carries bodies inline
    return doc


def _batch(*events: dict[str, Any]) -> bytes:
    return json.dumps({"schema": "sibyl-event/1", "events": list(events)}).encode()


async def _landed(world: World, event_id: str) -> bool:
    count = await world.val(
        "SELECT count(*) FROM sibyl.events WHERE tenant_id = $1 AND event_id = $2::uuid",
        world.tenant_id,
        event_id,
    )
    return bool(count)


@pytest.mark.parametrize("case", VALID_EVENTS + VALID_WIRE, ids=lambda c: c.file)
async def test_valid_fixture_lands(world: World, case: Any) -> None:
    doc = _wire(case.load())
    resp = await world.post("/v1/events", _batch(doc))
    assert resp.status_code == 202, resp.text
    body = resp.json()
    validate("sibyl-ingest-response/1", body)
    assert body["rejected"] == [], body
    assert body["accepted"] == 1
    if doc["type"] == "gen_ai.request":
        staged = await world.val(
            "SELECT count(*) FROM sibyl.call_merge WHERE tenant_id = $1", world.tenant_id
        )
        assert staged == 1
        await flush_tenant(
            world.db,
            world.tenant_id,
            world.services.cfg,
            now=datetime.now(UTC) + timedelta(minutes=1),
        )
        row = await world.admin.fetchrow(
            "SELECT event_id, cost_usd, tokens_in, payload_ref_id FROM sibyl.events WHERE"
            " tenant_id = $1 AND call_id = $2::uuid",
            world.tenant_id,
            doc["call_id"],
        )
        assert row is not None
        if "payload_inline" in case.load()["attrs"]:
            assert row["payload_ref_id"] is not None
    else:
        assert await _landed(world, doc["event_id"])


async def test_batch_fixture_lands_and_replays(world: World) -> None:
    batch = json.loads((golden_case("valid/batch_two_events.json")).load_text())
    batch["events"] = [_wire(e) for e in batch["events"]]
    resp = await world.post("/v1/events", json.dumps(batch).encode())
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 2
    for event in batch["events"]:
        assert await _landed(world, event["event_id"])


@pytest.mark.parametrize("case", INVALID_ELEMENTS, ids=lambda c: c.file)
async def test_invalid_fixture_is_rejected_per_event(world: World, case: Any) -> None:
    doc = case.load()
    if case.schema == "sibyl-event/1":
        doc = _as_wire(doc)
    resp = await world.post("/v1/events", _batch(doc))
    assert resp.status_code == 202, resp.text
    body = resp.json()
    validate("sibyl-ingest-response/1", body)
    assert body["accepted"] == 0, (case.file, body)
    assert body["rejected"][0]["reason"] in REASONS
    count = await world.val(
        "SELECT count(*) FROM sibyl.events WHERE tenant_id = $1", world.tenant_id
    )
    assert count == 0
    stored = await world.val(
        "SELECT count(*) FROM sibyl.events_rejected WHERE tenant_id = $1", world.tenant_id
    )
    assert stored == 1


@pytest.mark.parametrize(
    ("file", "status", "code"),
    [
        ("invalid/batch_wrong_schema.json", 400, "unsupported_schema"),
        ("invalid/batch_empty.json", 422, "validation_failed"),
    ],
)
async def test_invalid_batches_are_problems(
    world: World, file: str, status: int, code: str
) -> None:
    resp = await world.post("/v1/events", json.dumps(golden_case(file).load()).encode())
    assert resp.status_code == status
    assert resp.json()["type"].endswith("/" + code)


class _Case:
    def __init__(self, file: str) -> None:
        self.file = file
        match = next(c for c in CASES if c.file == file)
        self._case = match

    def load(self) -> Any:
        return self._case.load()

    def load_text(self) -> str:
        return json.dumps(self._case.load())


def golden_case(file: str) -> _Case:
    return _Case(file)
