import hashlib
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.audit import (
    AUDIT_ACTIONS,
    RECEIPT_HEADER,
    AuditReceipt,
    AuditRecord,
    InMemoryAuditWriter,
    PgAuditWriter,
    canonical_detail,
)
from sibyl_control.core.canonical import CanonicalizationError, canonicalize

TENANT = UUID("01927000-0000-7000-8000-000000000001")


def test_jcs_sorts_keys_by_utf16_and_is_compact() -> None:
    assert canonicalize({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'
    # U+1F600 (surrogate pair d83d) sorts before U+FF21 in UTF-16, after it in code points
    assert canonicalize({"\uff21": 1, "\U0001f600": 2}).startswith('{"\U0001f600"'.encode())


def test_jcs_escapes_like_ecmascript() -> None:
    assert canonicalize('a"b\\c\n\u0001é/') == '"a\\"b\\\\c\\n\\u0001é/"'.encode()


def test_jcs_refuses_floats_and_unsafe_integers() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": 1.5})
    with pytest.raises(CanonicalizationError):
        canonicalize(2**53)
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "non-string key"})


def test_jcs_serialises_uuids_lowercase() -> None:
    u = UUID("01927000-0000-7000-8000-00000000000A")
    assert canonicalize({"id": u}) == b'{"id":"01927000-0000-7000-8000-00000000000a"}'


def test_detail_rejects_content_keys_anywhere() -> None:
    for detail in ({"prompt": "x"}, {"nested": {"messages": []}}, {"a": [{"body": 1}]}):
        with pytest.raises(ValueError, match="content key"):
            canonical_detail(detail)


HEX = "ab" * 32


@pytest.mark.parametrize(
    "detail",
    [
        {"content_hashes": {"input": HEX, "output": HEX, "system": HEX}},
        {"content_hashes": {"input_sha256": HEX}},
        {"nested": [{"Content_Hashes": {"input": HEX}}]},
    ],
)
def test_detail_accepts_content_hash_subtrees(detail: dict) -> None:
    assert canonical_detail(detail)


@pytest.mark.parametrize(
    "detail",
    [
        {"content_hashes": {"input": "raw prompt"}},
        {"content_hashes": {"input": {"prompt": HEX}}},
        {"content_hashes": {"input": HEX}, "prompt": "x"},
        {"hashes": {"input": HEX}},
    ],
)
def test_detail_refuses_content_dressed_as_hashes(detail: dict) -> None:
    with pytest.raises(ValueError, match="content key"):
        canonical_detail(detail)


def test_detail_rejects_oversize() -> None:
    with pytest.raises(ValueError, match="8 KB"):
        canonical_detail({"x": "a" * 9000})


def test_record_rejects_undeclared_actions() -> None:
    with pytest.raises(ValueError, match="undeclared"):
        AuditRecord(action="agent.deleted", actor_type="human", resource_type="agent")
    AuditRecord(action="asset.created", actor_type="human", resource_type="agent")


def test_taxonomy_contains_every_action_the_contract_names() -> None:
    for action in ("killswitch.pulled", "access.break_glass", "data.revealed", "config.changed"):
        assert action in AUDIT_ACTIONS


def test_receipt_header_round_trip() -> None:
    receipt = AuditReceipt(TENANT, 42, bytes(range(32)))
    value = receipt.header_value()
    assert value == f"{TENANT}:42:{bytes(range(32)).hex()}"
    assert AuditReceipt.parse(value) == receipt
    assert RECEIPT_HEADER == "X-Sibyl-Audit-Receipt"


async def test_in_memory_writer_chains_hashes_per_tenant() -> None:
    writer = InMemoryAuditWriter()
    rec = AuditRecord(
        action="asset.created", actor_type="human", resource_type="agent", detail={"k": 1}
    )
    first = await writer.append(None, TENANT, rec)
    second = await writer.append(None, TENANT, rec)
    other = await writer.append(None, uuid4(), rec)
    assert (first.seq, second.seq, other.seq) == (1, 2, 1)
    assert first.hash != second.hash
    assert writer.actions(TENANT) == ["asset.created", "asset.created"]


class FakeConn:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    async def fetchrow(self, sql: str, *args):
        self.calls.append((sql, args))
        return {"seq": 7, "hash": b"\x01" * 32, "recorded_at": None}


async def test_pg_writer_calls_audit_append_with_canonical_detail() -> None:
    conn = FakeConn()
    rec = AuditRecord(
        action="config.changed",
        actor_type="human",
        actor_id=uuid4(),
        resource_type="tenant",
        reason="raise retention for the audit",
        detail={"field": "audit_retention_days", "before": 400, "after": 730},
    )
    receipt = await PgAuditWriter().append(conn, TENANT, rec)
    assert receipt == AuditReceipt(TENANT, 7, b"\x01" * 32)
    sql, args = conn.calls[0]
    assert "sibyl.audit_append" in sql
    assert args[0] == TENANT
    assert args[5] == "config.changed"
    canonical = args[11]
    assert canonical == canonicalize(rec.detail)
    assert hashlib.sha256(canonical).digest()


def test_kernel_canonicaliser_is_byte_identical_to_shared_one() -> None:
    """Hash chains and signatures must come from exactly one implementation (G0)."""
    from uuid import UUID

    from sibyl_schemas.canonical import canonicalize as shared

    doc = {
        "z": 1,
        "a": [True, None, "é\u2028"],
        "id": UUID("6f1c2f9e-6b2b-4f5e-9d63-3a1f6b8d2c10"),
        "nested": {"\u00e9": 2, "e": -3},
    }
    expected = shared({**doc, "id": str(doc["id"])}, allow_floats=False)
    assert canonicalize(doc) == expected
