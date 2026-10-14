"""G0 fixes in the outbox and audit writers: H3 (topic bound to event type), M3 (UUIDs, one
canonicalisation, immutable payloads), M4 (one content-key denylist), M1 kernel guard (no astral
keys), G0-6 (every API key is audited as ``api_key``)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sibyl_control.core import audit as audit_mod
from sibyl_control.core import outbox as outbox_mod
from sibyl_control.core.audit import (
    FORBIDDEN_DETAIL_KEYS,
    AuditRecord,
    InMemoryAuditWriter,
    PgAuditWriter,
    audit_actor,
    canonical_detail,
)
from sibyl_control.core.authz import Principal, PrincipalKind, grants_for_api_key
from sibyl_control.core.canonical import canonicalize
from sibyl_control.core.outbox import EVENT_TOPICS, OutboxMessage, PgOutboxWriter
from sibyl_schemas import values as sv

TENANT = UUID("01927000-0000-7000-8000-000000000001")


# --- H3: the topic follows from the event type -------------------------------------------------


def test_a_topic_that_does_not_own_the_event_type_is_refused() -> None:
    with pytest.raises(ValueError, match="belongs to topic 'policy'"):
        OutboxMessage("graph", "policy_changed", "agent", uuid4(), {})


def test_undeclared_event_types_are_refused() -> None:
    with pytest.raises(ValueError, match="undeclared"):
        OutboxMessage("policy", "policy_exploded", "agent", uuid4(), {})


@pytest.mark.parametrize("event_type", sorted(EVENT_TOPICS))
def test_for_event_derives_the_topic_for_every_declared_event(event_type: str) -> None:
    msg = OutboxMessage.for_event(event_type, "agent", uuid4())
    assert msg.topic == EVENT_TOPICS[event_type]
    assert OutboxMessage(msg.topic, event_type, "agent", msg.aggregate_id) == msg


def test_event_topic_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        EVENT_TOPICS["policy_changed"] = "graph"  # type: ignore[index]


# --- M3: one canonicalisation, immutable after validation, jsonb-safe ---------------------------


def test_payload_is_canonicalised_once_and_frozen() -> None:
    ref = uuid4()
    source = {"agent_id": ref, "versions": [1, 2], "nested": {"b": 1, "a": 2}}
    msg = OutboxMessage.for_event("policy_changed", "agent", uuid4(), source)
    assert msg.canonical == canonicalize(source)
    source["agent_id"] = "mutated after construction"
    assert msg.payload["agent_id"] == str(ref)
    with pytest.raises(TypeError):
        msg.payload["x"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        msg.payload["nested"]["a"] = 3  # type: ignore[index]
    assert msg.payload["versions"] == (1, 2)


class FakeConn:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    async def execute(self, sql: str, *args):
        self.calls.append((sql, args))
        return "INSERT 0 1"

    async def fetchrow(self, sql: str, *args):
        self.calls.append((sql, args))
        return {"seq": 1, "hash": b"\x00" * 32, "recorded_at": datetime.now(UTC)}


async def test_pg_outbox_writer_sends_plain_json_types() -> None:
    conn, ref = FakeConn(), uuid4()
    msg = OutboxMessage.for_event("policy_changed", "agent", uuid4(), {"agent_id": ref})
    await PgOutboxWriter().emit(conn, TENANT, msg)
    payload = conn.calls[0][1][5]
    assert payload == {"agent_id": str(ref)}
    assert type(payload) is dict
    json.dumps(payload)  # what asyncpg's jsonb codec does


async def test_pg_audit_writer_sends_plain_json_types() -> None:
    conn, ref = FakeConn(), uuid4()
    record = AuditRecord(
        action="config.changed",
        actor_type="human",
        resource_type="agent",
        actor_id=uuid4(),
        detail={"agent_id": ref, "tags": ["a"]},
    )
    await PgAuditWriter().append(conn, TENANT, record)
    args = conn.calls[0][1]
    assert args[10] == {"agent_id": str(ref), "tags": ["a"]}
    json.dumps(args[10])
    assert args[11] == canonicalize({"agent_id": ref, "tags": ["a"]})


def test_audit_record_detail_is_validated_and_frozen_at_construction() -> None:
    with pytest.raises(ValueError, match="content key"):
        AuditRecord("config.changed", "human", "agent", detail={"x": {"Prompt": "p"}})
    record = AuditRecord("config.changed", "human", "agent", detail={"n": 1})
    with pytest.raises(TypeError):
        record.detail["n"] = 2  # type: ignore[index]
    assert record.canonical == b'{"n":1}'


async def test_in_memory_audit_writer_still_chains() -> None:
    writer = InMemoryAuditWriter()
    record = AuditRecord("config.changed", "human", "agent", detail={"agent_id": uuid4()})
    receipt = await writer.append(None, TENANT, record)
    assert receipt.seq == 1


# --- M4: one denylist, imported from sibyl_schemas ----------------------------------------------


def test_content_key_denylist_is_the_schemas_list() -> None:
    expected = frozenset(k.lower() for k in sv.AUDIT_CONTENT_KEYS)
    assert expected == FORBIDDEN_DETAIL_KEYS
    assert audit_mod.FORBIDDEN_DETAIL_KEYS is outbox_mod.FORBIDDEN_DETAIL_KEYS
    assert {"input_messages", "output_messages", "prompt"} <= FORBIDDEN_DETAIL_KEYS


@pytest.mark.parametrize("key", ["input_messages", "Output_Messages", "PROMPT"])
def test_every_listed_key_is_refused_case_insensitively_and_nested(key: str) -> None:
    with pytest.raises(ValueError, match="content key"):
        canonical_detail({"outer": [{key: "x"}]})
    with pytest.raises(ValueError, match="content key"):
        OutboxMessage.for_event("policy_changed", "agent", uuid4(), {"outer": {key: 1}})


# --- M1 kernel guard: keys whose UTF-16 and code-point orders can differ ------------------------


def test_astral_object_keys_are_refused_before_they_reach_the_chain() -> None:
    with pytest.raises(ValueError, match="outside the Basic Multilingual Plane"):
        canonical_detail({"ﬁ": 1, "\U0001f600": 2})
    with pytest.raises(ValueError, match="outside the Basic Multilingual Plane"):
        OutboxMessage.for_event("policy_changed", "agent", uuid4(), {"x": {"\U0001f600": 1}})
    assert canonical_detail({"label": "\U0001f600 values are fine"})


# --- G0-6: API keys are always ``api_key`` -------------------------------------------------------


def _key(*, scopes: frozenset[str], agent: UUID | None = None) -> Principal:
    return Principal(
        kind=PrincipalKind.API_KEY,
        tenant_id=TENANT,
        id=uuid4(),
        grants=grants_for_api_key(scopes),
        bound_agent_id=agent,
    )


@pytest.mark.parametrize(
    ("scopes", "agent"),
    [
        (frozenset({"gateway:proxy"}), None),  # hosted gateway key
        (frozenset({"ingest:write"}), uuid4()),  # agent-bound key
        (frozenset({"killswitch:pull"}), None),  # break-glass key
    ],
)
def test_every_api_key_principal_is_audited_as_api_key_with_its_id(scopes, agent) -> None:
    principal = _key(scopes=scopes, agent=agent)
    actor = audit_actor(principal)
    assert actor.actor_type == "api_key"
    assert actor.actor_key_id == principal.id
    assert actor.actor_id is None
    assert actor.actor_type != "system"


def test_humans_are_audited_as_human() -> None:
    principal = Principal(PrincipalKind.SESSION, TENANT, uuid4(), session_id=uuid4())
    actor = audit_actor(principal)
    assert (actor.actor_type, actor.actor_id, actor.actor_session_id) == (
        "human",
        principal.id,
        principal.session_id,
    )
