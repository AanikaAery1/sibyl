# ruff: noqa: RUF001, S311 -- deliberate Unicode edge cases; seeded RNG for a reproducible fuzz corpus
"""G0 fixes to the audit chain: canonical bytes recomputed in the database with RFC 8785
UTF-16 key order (code-review M1, security M2, tests F11), one 8 KB rule on canonical bytes
(M2), the recursive case-folded content-key denylist (M4), no forked seq under REPEATABLE
READ (security LOW L2), and tamper detection that depends on every check (tests F2, F14)."""

from __future__ import annotations

import asyncio
import json
import random
import uuid
from typing import Any

import asyncpg
import pytest
from sibyl_schemas import values as sv
from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.golden import fixtures_root

from .conftest import Conn, Database
from .fixtures import create_tenant

APPEND = (
    "SELECT * FROM sibyl.audit_append($1, $2, $3, NULL, NULL, $4, 'tenant', $1, NULL, $5, "
    "$6::jsonb, $7, now(), NULL)"
)
CHANGE = {"field": "x", "before": "a", "after": "b"}


def _jcs(doc: Any) -> str:
    return canonicalize(doc, allow_floats=False).decode()


def _integer_only(value: Any) -> bool:
    """Documents inside the hashed subset: no floats, integers within +/-(2**53 - 1)."""
    if isinstance(value, float):
        return False
    if isinstance(value, int) and not isinstance(value, bool):
        return abs(value) <= 2**53 - 1
    if isinstance(value, dict):
        return all(_integer_only(v) for v in value.values())
    if isinstance(value, list):
        return all(_integer_only(v) for v in value)
    return True


RFC = json.loads((fixtures_root() / "jcs" / "rfc8785.json").read_text("utf-8"))["documents"]
VECTORS = [json.loads(d["input"]) for d in RFC if _integer_only(json.loads(d["input"]))] + [
    {"Ａ": 1, "\U0001f600": 2},
    {"labels": {"": "pua", "\U00010000": "astral", "￿": "max-bmp"}},
    {"ﬁ": 1, "\U0001f600": 2, "a": 3, "€": 4, "\r": 5, "1": 6, "ö": 7},
    {"s": "  \u007f\u0001\u001f  ", "n": [0, -0, 9007199254740991, -9007199254740991]},
]


@pytest.mark.parametrize("doc", VECTORS, ids=range(len(VECTORS)))
def test_sql_jcs_equals_the_shared_canonicaliser(admin: Conn, doc: Any) -> None:
    assert admin.fetchval("SELECT sibyl.jcs($1::jsonb)", json.dumps(doc)) == _jcs(doc)


# Alphabets chosen to straddle every ordering hazard: ASCII, Latin-1, BMP below the surrogate
# block, the U+E000-U+FFFF band that UTF-16 sorts after astral characters, and astral planes.
ALPHABETS = (
    "ab_Z09",
    "éöÿ",
    "Ā€中퟿",
    "ﬁＡ�￿",
    "\U00010000\U0001f600\U0010fffd",
    '\u0001\u001f\u007f "\\',
)


def _key(rng: random.Random) -> str:
    return "".join(rng.choice(rng.choice(ALPHABETS)) for _ in range(rng.randint(0, 4)))


def _value(rng: random.Random, depth: int) -> Any:
    kind = rng.randint(0, 5 if depth < 3 else 3)
    if kind == 0:
        return rng.randint(-(2**53) + 1, 2**53 - 1)
    if kind == 1:
        return _key(rng)
    if kind == 2:
        return rng.choice([True, False, None])
    if kind == 3:
        return rng.randint(-5, 5)
    if kind == 4:
        return [_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return _doc(rng, depth + 1)


def _doc(rng: random.Random, depth: int = 0) -> dict[str, Any]:
    return {_key(rng): _value(rng, depth) for _ in range(rng.randint(0, 6))}


def test_sql_jcs_agrees_with_python_on_a_fuzzed_corpus(admin: Conn) -> None:
    rng = random.Random(8785)
    docs = [_doc(rng) for _ in range(1500)]
    texts = [json.dumps(d) for d in docs]
    got = admin.fetchval(
        "SELECT array_agg(sibyl.jcs(d::jsonb) ORDER BY i) FROM unnest($1::text[]) "
        "WITH ORDINALITY AS u(d, i)",
        texts,
    )
    wrong = [(d, g) for d, g in zip(docs, got, strict=True) if g != _jcs(d)]
    assert wrong == [], wrong[:3]


def _append_error(conn: Conn, tenant: uuid.UUID, *args: Any) -> asyncpg.PostgresError:
    with pytest.raises(asyncpg.PostgresError) as info:
        with conn.tx(tenant, rollback=True):
            conn.fetchrow(APPEND, tenant, *args)
    return info.value


def _verify(admin: Conn, tenant: uuid.UUID) -> tuple[bool, int | None, str | None]:
    with admin.tx(tenant, rollback=True):
        r = admin.fetchrow("SELECT * FROM sibyl.audit_verify($1)", tenant)
    return r["ok"], r["first_break_seq"], r["kind"]


def test_astral_and_private_use_keys_append_and_verify(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "audit-utf16")
    app = roles["sibyl_app"]
    detail = {**CHANGE, "ﬁ": 1, "\U0001f600": 2, "": {"\U00010000": 3, "￿": 4}}
    with app.tx(tenant):
        app.fetchrow(
            APPEND,
            tenant,
            "human",
            uuid.uuid4(),
            "config.changed",
            "why",
            json.dumps(detail),
            _jcs(detail).encode(),
        )
    assert _verify(admin, tenant) == (True, None, None)


@pytest.mark.parametrize(
    "canonical",
    [
        b'{"after":"b", "before":"a","field":"x"}',  # whitespace
        b'{"field":"x","before":"a","after":"b"}',  # key order
        b'{"after":"b","after":"b","before":"a","field":"x"}',  # duplicate member
        b'{"after":"\\u0062","before":"a","field":"x"}',  # needless escape
    ],
)
def test_non_canonical_bytes_are_refused_at_append(
    admin: Conn, roles: dict[str, Conn], canonical: bytes
) -> None:
    tenant = create_tenant(admin, f"audit-noncanon-{uuid.uuid4().hex[:6]}")
    err = _append_error(
        roles["sibyl_app"],
        tenant,
        "human",
        uuid.uuid4(),
        "config.changed",
        "r",
        json.dumps(CHANGE),
        canonical,
    )
    assert err.sqlstate == "SB024", err


@pytest.mark.parametrize("number", ["0.5", "1.0", "9007199254740993"])
def test_non_integral_numbers_are_refused_at_append_not_at_verify(
    admin: Conn, roles: dict[str, Conn], number: str
) -> None:
    tenant = create_tenant(admin, f"audit-float-{uuid.uuid4().hex[:6]}")
    detail = f'{{"anchors_checked":0,"from_seq":{number},"to_seq":1}}'
    err = _append_error(
        roles["sibyl_worker"],
        tenant,
        "system",
        None,
        "audit.verified",
        None,
        detail,
        detail.encode(),
    )
    assert err.sqlstate == "SB023", err
    assert _verify(admin, tenant) == (True, None, None)


def _padded(size: int) -> dict[str, Any]:
    """A config.changed detail whose canonical form is exactly ``size`` bytes."""
    doc: dict[str, Any] = {**CHANGE, "pad": ""}
    doc["pad"] = "p" * (size - len(_jcs(doc)))
    assert len(_jcs(doc).encode()) == size
    return doc


def test_the_8kb_rule_is_on_canonical_bytes_and_raised_as_sb023(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    tenant = create_tenant(admin, "audit-8kb")
    app = roles["sibyl_app"]
    at_limit = _padded(8192)
    with app.tx(tenant):
        app.fetchrow(
            APPEND,
            tenant,
            "human",
            uuid.uuid4(),
            "config.changed",
            "r",
            json.dumps(at_limit),
            _jcs(at_limit).encode(),
        )
    over = _padded(8193)
    err = _append_error(
        app,
        tenant,
        "human",
        uuid.uuid4(),
        "config.changed",
        "r",
        json.dumps(over),
        _jcs(over).encode(),
    )
    assert err.sqlstate == "SB023", err


def test_a_small_canonical_detail_with_a_large_jsonb_footprint_is_accepted(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    tenant = create_tenant(admin, "audit-footprint")
    detail = {**CHANGE, **{f"k{i:03}": i for i in range(700)}}
    canonical = _jcs(detail)
    assert len(canonical.encode()) < 8192
    assert admin.fetchval("SELECT pg_column_size($1::jsonb)", json.dumps(detail)) > 8192
    app = roles["sibyl_app"]
    with app.tx(tenant):
        app.fetchrow(
            APPEND,
            tenant,
            "human",
            uuid.uuid4(),
            "config.changed",
            "r",
            json.dumps(detail),
            canonical.encode(),
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"Prompt": "x"},
        {"nested": {"CONTENT": "x"}},
        {"items": [{"ok": 1}, {"Input_Messages": []}]},
        {"deep": {"a": {"b": {"headers": {}}}}},
        {"output": "x"},
    ],
)
def test_content_keys_are_refused_at_any_depth_and_any_case(
    admin: Conn, roles: dict[str, Conn], extra: dict[str, Any]
) -> None:
    tenant = create_tenant(admin, f"audit-content-{uuid.uuid4().hex[:6]}")
    detail = {**CHANGE, **extra}
    err = _append_error(
        roles["sibyl_app"],
        tenant,
        "human",
        uuid.uuid4(),
        "config.changed",
        "r",
        json.dumps(detail),
        _jcs(detail).encode(),
    )
    assert err.sqlstate == "SB023", err


def test_sql_content_key_denylist_equals_the_schemas_list(admin: Conn) -> None:
    expected = getattr(sv, "AUDIT_CONTENT_KEYS", None)
    assert expected is not None, "sibyl_schemas.values.AUDIT_CONTENT_KEYS (FIX-SCH) is missing"
    assert set(admin.fetchval("SELECT sibyl.audit_content_keys()")) == set(expected)
    assert all(k == k.lower() for k in expected)


def test_event_attrs_use_the_same_recursive_denylist(admin: Conn) -> None:
    for attrs, refused in (
        ({"gen_ai.request.model": "m", "nested": {"Body": "x"}}, True),
        ({"list": [{"MESSAGES": []}]}, True),
        ({"gen_ai.request.model": "m", "nested": {"tokens": 3}}, False),
    ):
        assert (
            admin.fetchval("SELECT sibyl.has_content_key($1::jsonb)", json.dumps(attrs)) is refused
        )


def test_repeatable_read_append_cannot_fork_the_chain(db: Database, admin: Conn) -> None:
    tenant = create_tenant(admin, "audit-rr")
    detail = json.dumps({"date_prefix": "d", "objects": 1, "bytes": 1, "holds_skipped": 0})

    async def scenario() -> None:
        late = await asyncpg.connect(**db.spec("sibyl_worker").kwargs())
        early = await asyncpg.connect(**db.spec("sibyl_worker").kwargs())
        try:
            tx = early.transaction(isolation="repeatable_read")
            await tx.start()
            await early.execute("SELECT sibyl.set_tenant($1)", tenant)
            await early.fetchval("SELECT count(*) FROM sibyl.audit_events")  # takes the snapshot
            async with late.transaction():
                await late.execute("SELECT sibyl.set_tenant($1)", tenant)
                await late.fetchrow(
                    APPEND, tenant, "system", None, "retention.objects_swept", None, detail, None
                )
            with pytest.raises(asyncpg.SerializationError):
                await early.fetchrow(
                    APPEND, tenant, "system", None, "retention.objects_swept", None, detail, None
                )
            await tx.rollback()
        finally:
            await late.close()
            await early.close()

    db.loop.run_until_complete(asyncio.wait_for(scenario(), 20))
    seqs = [
        r["seq"]
        for r in admin.fetch(
            "SELECT seq FROM sibyl.audit_events WHERE tenant_id = $1 ORDER BY seq", tenant
        )
    ]
    assert seqs == list(range(len(seqs)))
    assert _verify(admin, tenant) == (True, None, None)


def _tamper(admin: Conn, sql: str, *args: Any) -> None:
    with admin.tx():
        admin.execute("SET LOCAL session_replication_role = replica")
        admin.execute(sql, *args)


def test_rewritten_hash_of_the_last_row_is_hash_mismatch(admin: Conn) -> None:
    """Only the hash recompute guards the last row: no successor's prev-link covers it."""
    tenant = create_tenant(admin, "audit-tail-hash")
    last = admin.fetchval("SELECT max(seq) FROM sibyl.audit_events WHERE tenant_id = $1", tenant)
    _tamper(
        admin,
        "UPDATE sibyl.audit_events SET hash = sha256('x') WHERE tenant_id = $1 AND seq = $2",
        tenant,
        last,
    )
    _tamper(
        admin,
        "UPDATE sibyl.audit_chain_head SET hash = sha256('x') WHERE tenant_id = $1",
        tenant,
    )
    assert _verify(admin, tenant) == (False, last, "hash_mismatch")


def test_spliced_self_consistent_row_is_prev_mismatch(admin: Conn) -> None:
    """A forged prev_hash with a recomputed hash passes the hash check; only the link fails."""
    tenant = create_tenant(admin, "audit-splice")
    _tamper(
        admin,
        "UPDATE sibyl.audit_events SET prev_hash = sha256('forged'), "
        "hash = sha256(sha256('forged') || envelope_sha256 || detail_sha256) "
        "WHERE tenant_id = $1 AND seq = 1",
        tenant,
    )
    assert _verify(admin, tenant) == (False, 1, "prev_mismatch")


def _anchor_head(admin: Conn, tenant: uuid.UUID) -> int:
    head = admin.fetchrow(
        "SELECT seq, hash FROM sibyl.audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1",
        tenant,
    )
    kid = f"anchor-{uuid.uuid4().hex[:8]}"
    with admin.tx(tenant):
        admin.execute(
            "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref, state) "
            "VALUES ($1, 'audit_anchor', $2, 'file:test', 'retired')",
            kid,
            b"\x03" * 32,
        )
        admin.execute(
            "INSERT INTO sibyl.audit_anchors (tenant_id, kind, seq_from, seq_to, head_hash, "
            "signing_kid, signature) VALUES ($1, 'hourly', 0, $2, $3, $4, $5)",
            tenant,
            head["seq"],
            head["hash"],
            kid,
            b"\x04" * 64,
        )
    return int(head["seq"])


def test_tail_truncation_is_detected_against_the_chain_head(admin: Conn) -> None:
    tenant = create_tenant(admin, "audit-truncate-head")
    last = admin.fetchval("SELECT max(seq) FROM sibyl.audit_events WHERE tenant_id = $1", tenant)
    _tamper(admin, "DELETE FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2", tenant, last)
    assert _verify(admin, tenant) == (False, last, "truncated")


def test_tail_truncation_is_detected_against_the_latest_anchor(admin: Conn) -> None:
    """Even when the attacker also rewinds the chain head, the signed anchor still pins it."""
    tenant = create_tenant(admin, "audit-truncate-anchor")
    last = _anchor_head(admin, tenant)
    _tamper(admin, "DELETE FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2", tenant, last)
    _tamper(
        admin,
        "UPDATE sibyl.audit_chain_head h SET seq = e.seq, hash = e.hash FROM sibyl.audit_events e "
        "WHERE h.tenant_id = $1 AND e.tenant_id = $1 AND e.seq = $2",
        tenant,
        last - 1,
    )
    assert _verify(admin, tenant) == (False, last, "truncated")


def test_anchor_hash_disagreement_is_detected(admin: Conn) -> None:
    tenant = create_tenant(admin, "audit-anchor-mismatch")
    last = _anchor_head(admin, tenant)
    _tamper(
        admin,
        "UPDATE sibyl.audit_anchors SET head_hash = sha256('other') WHERE tenant_id = $1",
        tenant,
    )
    assert _verify(admin, tenant) == (False, last, "anchor_mismatch")
