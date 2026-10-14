"""``sibyl_schemas.audit_chain``: the audit row hash, anchor document and export format.

Golden values were produced by lane U's ``worker/housekeeping/chain.py`` (the implementation the
anchors loop, export writer and verify route shipped with) on the same inputs, so the shared
module is byte-identical to it; the SDK's offline verifier reads the same documents.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from sibyl_schemas import audit_chain as ac
from sibyl_schemas.canonical import canonicalize

T = UUID("01927000-0000-7000-8000-00000000000a")
ROW = {
    "action": "credential.verified",
    "actor_id": None,
    "actor_key_id": None,
    "actor_session_id": None,
    "actor_type": "system",
    "chain_version": 1,
    "occurred_at": datetime(2026, 10, 11, 9, 30, 1, 123456, tzinfo=UTC),
    "reason": None,
    "recorded_at": "2026-10-11T09:30:01.200000Z",
    "request_id": UUID("01927000-0000-7000-8000-0000000000c1"),
    "resource_id": UUID("01927000-0000-7000-8000-0000000000c2"),
    "resource_ref": "cred:é",
    "resource_type": "provider_credential",
    "seq": 7,
    "tenant_id": T,
    "severity": "notice",
    "is_evidence": True,
    "detail": {
        "credential_id": "01927000-0000-7000-8000-0000000000c2",
        "http_status": 200,
        "z": [1, "ü"],
    },
    "detail_sha256": bytes(range(32)),
    "envelope_sha256": bytes(range(1, 33)),
    "prev_hash": bytes(32),
    "hash": bytes(range(2, 34)),
}
ANCHOR = {
    "id": UUID("01927000-0000-7000-8000-0000000000a9"),
    "tenant_id": T,
    "kind": "export",
    "seq_from": 0,
    "seq_to": 7,
    "head_hash": bytes(range(3, 35)),
    "prev_anchor_id": None,
    "signing_kid": "anchor-2026-10",
    "signature": bytes(range(64)),
    "anchored_at": datetime(2026, 10, 11, 10, 0, tzinfo=UTC),
}
GOLDEN = {
    "row_hash": "cfd08cfc003a77eb45ec0f4dffa044587667d90e671f3b1c43b7752ec589e90a",
    "envelope_sha256": "83a257eceb720ee875376178b73566e6aef55d841e3fcd0ea76872763d78b7c2",
    "anchor_jcs_sha256": "d4edc5a911cee1283f3a9bbff47a22d43d01010c29c4e3b1417c36338db19b36",
    "jsonl_sha256": "71968f5d61e43d42ebb984cb4374a811a30530d8399081c076bf7404eaeb4304",
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_envelope_and_row_hash_match_the_golden_vector() -> None:
    env = ac.envelope(ROW)
    assert list(env) == list(ac.ENVELOPE_FIELDS)
    assert env["occurred_at"] == "2026-10-11T09:30:01.123456Z"
    assert env["tenant_id"] == str(T) and env["seq"] == 7
    assert ac.envelope_sha256(env).hex() == GOLDEN["envelope_sha256"]
    assert ac.row_hash(ac.GENESIS_HASH, env, ROW["detail"]).hex() == GOLDEN["row_hash"]


def test_anchor_document_is_the_signed_content() -> None:
    doc = ac.anchor_document_of(ANCHOR)
    assert doc["format"] == ac.ANCHOR_FORMAT
    assert set(doc) == {"format", *ac.ANCHOR_FIELDS}
    assert _sha(canonicalize(doc)) == GOLDEN["anchor_jcs_sha256"]
    view = ac.anchor_view(ANCHOR)
    assert ac.b64url_decode(view["signature"]) == ANCHOR["signature"]
    assert ac.anchor_document_of(view) == doc  # the published view re-derives the same document


def test_export_lines_and_jsonl_match_the_golden_vector() -> None:
    lines = [ac.event_line(ROW), {"type": "anchor", **ac.anchor_view(ANCHOR)}]
    body = ac.jsonl(lines)
    assert _sha(body) == GOLDEN["jsonl_sha256"]
    assert ac.decode_jsonl(body) == lines
    header = ac.export_header(
        tenant_id=T,
        export_id=UUID(int=1),
        from_seq=0,
        to_seq=7,
        anchor_id=ANCHOR["id"],
        exported_at=datetime(2026, 10, 11, 10, 0, tzinfo=UTC),
    )
    assert header["type"] == "header" and header["format"] == ac.EXPORT_FORMAT


def test_rfc3339_normalises_to_utc_and_refuses_naive_times() -> None:
    plus_two = datetime(2026, 1, 1, 2, 0, tzinfo=timezone(timedelta(hours=2)))
    assert ac.rfc3339(plus_two) == "2026-01-01T00:00:00.000000Z"
    assert ac.rfc3339(None) is None
    with pytest.raises(ValueError, match="timezone"):
        ac.rfc3339(datetime(2026, 1, 1))


def test_b64url_is_strict() -> None:
    assert ac.b64url_decode(ac.b64url(b"\xff\x00")) == b"\xff\x00"
    for bad in ("a", "ab=", "a+b/"):
        with pytest.raises(ValueError):
            ac.b64url_decode(bad)


# --- strict (no-coercion) variants for the offline verifier (CR-U1 / CR-U2) -------------------


def _export_event() -> dict[str, object]:
    return ac.decode_jsonl(ac.jsonl([ac.event_line(ROW)]))[0]


def test_strict_envelope_takes_the_fields_exactly_as_they_are() -> None:
    event = _export_event()
    strict = ac.envelope_strict(event)
    assert list(strict) == list(ac.ENVELOPE_FIELDS)
    assert strict == ac.envelope(event)  # an untampered export line: both agree
    assert ac.envelope_sha256(strict).hex() == GOLDEN["envelope_sha256"]


def test_strict_envelope_does_not_normalise_a_tampered_uuid_or_seq() -> None:
    event = {**_export_event(), "resource_id": str(ROW["resource_id"]).upper(), "seq": "7"}
    assert ac.envelope(event)["resource_id"] == str(ROW["resource_id"])  # coerced back
    strict = ac.envelope_strict(event)
    assert strict["resource_id"] == str(ROW["resource_id"]).upper() and strict["seq"] == "7"
    assert ac.envelope_sha256(strict).hex() != GOLDEN["envelope_sha256"]


def test_strict_envelope_fills_missing_fields_with_null() -> None:
    assert ac.envelope_strict({"seq": 1})["reason"] is None


def test_strict_anchor_document_is_the_view_as_published() -> None:
    view = ac.anchor_view(ANCHOR)
    doc = ac.anchor_document_of_strict(view)
    assert doc == ac.anchor_document_of(view)
    assert _sha(canonicalize(doc)) == GOLDEN["anchor_jcs_sha256"]
    tampered = {**view, "seq_from": "0"}
    strict = ac.anchor_document_of_strict(tampered)
    assert strict["seq_from"] == "0" and canonicalize(strict) != canonicalize(doc)
    assert ac.anchor_document_of(tampered) == doc  # the coercing form would have hidden it


def test_digests_can_refuse_floats() -> None:
    from sibyl_schemas.canonical import CanonicalizationError

    env = ac.envelope(ROW)
    floaty = {"ratio": 0.5}
    assert ac.detail_sha256(floaty)  # default: floats canonicalise (unchanged behaviour)
    with pytest.raises(CanonicalizationError):
        ac.detail_sha256(floaty, allow_floats=False)
    with pytest.raises(CanonicalizationError):
        ac.envelope_sha256({**env, "seq": 7.5}, allow_floats=False)
    with pytest.raises(CanonicalizationError):
        ac.row_hash(ac.GENESIS_HASH, env, floaty, allow_floats=False)
    assert (
        ac.row_hash(ac.GENESIS_HASH, env, ROW["detail"], allow_floats=False).hex()
        == (GOLDEN["row_hash"])
    )


def test_offline_break_kinds_are_chain_break_kinds() -> None:
    from sibyl_schemas.values import OFFLINE_CHAIN_BREAK_KINDS, ChainBreakKind

    assert {k.value for k in OFFLINE_CHAIN_BREAK_KINDS} == {
        "anchor_tenant",
        "no_anchor",
        "unanchored_tail",
    }
    assert OFFLINE_CHAIN_BREAK_KINDS < set(ChainBreakKind)
    assert ChainBreakKind.ANCHOR_SIGNATURE not in OFFLINE_CHAIN_BREAK_KINDS
