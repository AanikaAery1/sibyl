"""Golden bytes of lane U's audit-chain documents (pure, no database).

Pinned before the INT-1 repoint of ``worker/housekeeping/{chain,exports}.py`` and the SDK
verifier onto ``sibyl_schemas.audit_chain``: the export JSONL / CSV bytes and their sha256 for a
fixed set of rows and anchors, the anchor document's canonical bytes, the published anchor view,
the row hash, and the offline verifier's JSON report and summary line on that export (intact and
tampered). Every value below was captured from the pre-refactor code; any drift is a format
break that offline verifiers in the field would notice.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sibyl.cli import EXIT_BREAK, EXIT_OK
from sibyl.cli import audit as cli_audit
from sibyl.cli import main as sibyl_cli
from sibyl_control.core.canonical import canonicalize
from sibyl_control.core.crypto.signing import Ed25519Signer
from sibyl_control.worker.housekeeping import anchoring, chain, exports
from sibyl_schemas import audit_chain

TENANT = UUID("01927000-0000-7000-8000-0000000000aa")
OTHER = UUID("01927000-0000-7000-8000-0000000000bb")
USER = UUID("01927000-0000-7000-8000-0000000000c1")
REQUEST = UUID("01927000-0000-7000-8000-0000000000d1")
EXPORT_ID = UUID("01927000-0000-7000-8000-0000000000e1")
ANCHOR_IDS = (
    UUID("01927000-0000-7000-8000-0000000000f1"),
    UUID("01927000-0000-7000-8000-0000000000f2"),
)
KID = "anchor-golden-1"
SEED = bytes(range(32))
BASE = datetime(2026, 10, 11, 9, 30, 15, 123456, tzinfo=UTC)
EXPORTED_AT = datetime(2026, 10, 11, 10, 0, 0, 1, tzinfo=UTC)
ROWS = 6

GOLDEN_ROW_HASH_LAST = "1f71f57cb57712912101f33aa05aa7133c23471f184a75ab68bf6dd2cb1c8e4c"
GOLDEN_ANCHOR_DOC = (
    '{"anchored_at":"2026-10-11T10:01:00.000001Z","format":"sibyl.audit_anchor/1","he'
    'ad_hash":"1f71f57cb57712912101f33aa05aa7133c23471f184a75ab68bf6dd2cb1c8e4c","id"'
    ':"01927000-0000-7000-8000-0000000000f2","kind":"export","prev_anchor_id":"019270'
    '00-0000-7000-8000-0000000000f1","seq_from":3,"seq_to":5,"signing_kid":"anchor-go'
    'lden-1","tenant_id":"01927000-0000-7000-8000-0000000000aa"}'
)
GOLDEN_ANCHOR_VIEW_SHA = "1fa6459eb83759fb320f0bc4ed070e967edb0188b935427cfe80c1f8c47613a4"
GOLDEN_JSONL_SHA = "5ef388593cdf7c951c7a8255abfaf7c078889a66f0429ac031f80b3cf6d4c262"
GOLDEN_CSV_SHA = "04e3694cc03730ff105653eef3e1cbd54b07e485b5c858642c247a7778112498"
GOLDEN_REPORTS: dict[str, str] = {
    "anchor_fields": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "anchor 01927000-0000-'
        '7000-8000-0000000000f1 is not validly signed", "first_break_seq": 2, "from_s'
        'eq": 0, "kind": "anchor_signature", "ok": false, "rows": 6, "tenant_id": "01'
        '927000-0000-7000-8000-0000000000aa", "to_seq": 5, "warnings": []}'
    ),
    "anchor_tenant": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "the anchor names anot'
        'her tenant", "first_break_seq": 2, "from_seq": 0, "kind": "anchor_tenant", "'
        'ok": false, "rows": 6, "tenant_id": "01927000-0000-7000-8000-0000000000aa", '
        '"to_seq": 5, "warnings": []}'
    ),
    "detail": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "envelope or detail di'
        'ffers from its digest", "first_break_seq": 3, "from_seq": 0, "kind": "conten'
        't_mismatch", "ok": false, "rows": 0, "tenant_id": "01927000-0000-7000-8000-0'
        '000000000aa", "to_seq": null, "warnings": []}'
    ),
    "gap": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "row 2 is missing (fou'
        'nd 3)", "first_break_seq": 2, "from_seq": 0, "kind": "gap", "ok": false, "ro'
        'ws": 0, "tenant_id": "01927000-0000-7000-8000-0000000000aa", "to_seq": null,'
        ' "warnings": []}'
    ),
    "hash": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "row hash does not rec'
        'ompute", "first_break_seq": 5, "from_seq": 0, "kind": "hash_mismatch", "ok":'
        ' false, "rows": 0, "tenant_id": "01927000-0000-7000-8000-0000000000aa", "to_'
        'seq": null, "warnings": []}'
    ),
    "intact": (
        '{"anchored_to": 5, "anchors_checked": 2, "detail": null, "first_break_seq": '
        'null, "from_seq": 0, "kind": null, "ok": true, "rows": 6, "tenant_id": "0192'
        '7000-0000-7000-8000-0000000000aa", "to_seq": 5, "warnings": []}'
    ),
    "no_anchor": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "no anchor was given o'
        'r found in the export", "first_break_seq": null, "from_seq": 0, "kind": "no_'
        'anchor", "ok": false, "rows": 6, "tenant_id": "01927000-0000-7000-8000-00000'
        '00000aa", "to_seq": 5, "warnings": []}'
    ),
    "prev": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "prev_hash is not the '
        'previous row\'s hash", "first_break_seq": 4, "from_seq": 0, "kind": "prev_mis'
        'match", "ok": false, "rows": 0, "tenant_id": "01927000-0000-7000-8000-000000'
        '0000aa", "to_seq": null, "warnings": []}'
    ),
    "rehashed": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "the anchor\'s head_has'
        'h differs from the row", "first_break_seq": 2, "from_seq": 0, "kind": "ancho'
        'r_mismatch", "ok": false, "rows": 6, "tenant_id": "01927000-0000-7000-8000-0'
        '000000000aa", "to_seq": 5, "warnings": []}'
    ),
    "tail": (
        '{"anchored_to": 2, "anchors_checked": 1, "detail": "rows after the last anch'
        'or are not attested", "first_break_seq": 3, "from_seq": 0, "kind": "unanchor'
        'ed_tail", "ok": false, "rows": 6, "tenant_id": "01927000-0000-7000-8000-0000'
        '000000aa", "to_seq": 5, "warnings": []}'
    ),
    "uuid_case": (
        '{"anchored_to": null, "anchors_checked": 0, "detail": "envelope or detail di'
        'ffers from its digest", "first_break_seq": 1, "from_seq": 0, "kind": "conten'
        't_mismatch", "ok": false, "rows": 0, "tenant_id": "01927000-0000-7000-8000-0'
        '000000000aa", "to_seq": null, "warnings": []}'
    ),
}
GOLDEN_SUMMARIES: dict[str, str] = {
    "anchor_fields": (
        "BROKEN at seq 2: anchor_signature (anchor 01927000-0000-7000-8000-0000000000"
        "f1 is not validly signed)\n"
    ),
    "anchor_tenant": "BROKEN at seq 2: anchor_tenant (the anchor names another tenant)\n",
    "detail": ("BROKEN at seq 3: content_mismatch (envelope or detail differs from its digest)\n"),
    "gap": "BROKEN at seq 2: gap (row 2 is missing (found 3))\n",
    "hash": "BROKEN at seq 5: hash_mismatch (row hash does not recompute)\n",
    "intact": "OK: 6 rows (seq 0..5), 2 anchor(s) verified\n",
    "no_anchor": "BROKEN at seq None: no_anchor (no anchor was given or found in the export)\n",
    "prev": "BROKEN at seq 4: prev_mismatch (prev_hash is not the previous row's hash)\n",
    "rehashed": (
        "BROKEN at seq 2: anchor_mismatch (the anchor's head_hash differs from the row)\n"
    ),
    "tail": ("BROKEN at seq 3: unanchored_tail (rows after the last anchor are not attested)\n"),
    "uuid_case": (
        "BROKEN at seq 1: content_mismatch (envelope or detail differs from its digest)\n"
    ),
}


def _jcs(value: Any) -> bytes:
    return canonicalize(value)


def _stamp(seq: int) -> str:
    moment = BASE.replace(second=(BASE.second + seq) % 60)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row(seq: int, prev: bytes) -> dict[str, Any]:
    """An ``audit_events`` row as ``exports._rows`` hands it on (timestamps already text)."""
    human = seq % 2 == 0
    row: dict[str, Any] = {
        "tenant_id": TENANT,
        "seq": seq,
        "action": "audit.exported" if human else "audit.anchored",
        "actor_type": "human" if human else "system",
        "actor_id": USER if human else None,
        "actor_key_id": None,
        "actor_session_id": None,
        "resource_type": "tenant",
        "resource_id": TENANT,
        "resource_ref": f"audit_export:{EXPORT_ID}" if human else None,
        "reason": "quarterly review: ünïcødé" if seq == 2 else None,
        "request_id": REQUEST if human else None,
        "occurred_at": _stamp(seq) if human else None,
        "recorded_at": _stamp(seq),
        "chain_version": 1,
        "severity": "notice" if human else "info",
        "is_evidence": True,
        "detail": {"from_seq": 0, "to_seq": seq, "nested": {"z": [1, "two"], "a": None}},
    }
    envelope = audit_chain.envelope(row)
    env_sha = hashlib.sha256(_jcs(envelope)).digest()
    det_sha = hashlib.sha256(_jcs(row["detail"])).digest()
    row["envelope_sha256"] = env_sha
    row["detail_sha256"] = det_sha
    row["prev_hash"] = prev
    row["hash"] = hashlib.sha256(prev + env_sha + det_sha).digest()
    return row


def _rows() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    prev = bytes(32)
    for seq in range(ROWS):
        out.append(_row(seq, prev))
        prev = out[-1]["hash"]
    return out


def _signer() -> Ed25519Signer:
    return Ed25519Signer.from_seed(KID, SEED)


def _anchor(rows: list[dict[str, Any]], index: int, seq_from: int, seq_to: int) -> dict[str, Any]:
    """A stored ``audit_anchors`` row, signed the way ``anchoring.write_anchor`` signs it."""
    anchored_at = EXPORTED_AT.replace(minute=index)
    row: dict[str, Any] = {
        "tenant_id": TENANT,
        "id": ANCHOR_IDS[index],
        "kind": "hourly" if index == 0 else "export",
        "seq_from": seq_from,
        "seq_to": seq_to,
        "head_hash": rows[seq_to]["hash"],
        "prev_anchor_id": None if index == 0 else ANCHOR_IDS[index - 1],
        "signing_kid": KID,
        "anchored_at": anchored_at,
        "external_ref": None,
    }
    signed = _signer().sign_document(_document(row))
    row["signature"] = audit_chain.b64url_decode(signed.signature)
    return row


def _document(row: dict[str, Any]) -> dict[str, Any]:
    """The anchor document as the anchors loop signs it (``anchoring.write_anchor``)."""
    return anchoring.anchor_document(
        anchor_id=row["id"],
        tenant_id=row["tenant_id"],
        kind=row["kind"],
        seq_from=row["seq_from"],
        seq_to=row["seq_to"],
        head_hash=row["head_hash"],
        prev_anchor_id=row["prev_anchor_id"],
        signing_kid=row["signing_kid"],
        anchored_at=row["anchored_at"],
    )


def _anchors(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_anchor(rows, 0, 0, 2), _anchor(rows, 1, 3, ROWS - 1)]


def _request(fmt: str) -> exports.ExportRequest:
    return exports.ExportRequest.from_payload(
        {"export_id": str(EXPORT_ID), "from_seq": 0, "to_seq": ROWS - 1, "format": fmt}
    )


def _export(fmt: str = "jsonl") -> bytes:
    rows = _rows()
    return exports.render(TENANT, _request(fmt), rows, _anchors(rows), ANCHOR_IDS[1], EXPORTED_AT)


def _keys_doc() -> dict[str, Any]:
    return {
        "data": [
            {
                "kid": KID,
                "public_key": audit_chain.b64url(_signer().public_key_raw),
                "state": "active",
            }
        ]
    }


# --- the tampered variants the offline verifier must report ------------------------------------


def _lines() -> list[dict[str, Any]]:
    return audit_chain.decode_jsonl(_export())


def _event(lines: list[dict[str, Any]], seq: int) -> dict[str, Any]:
    return next(ln for ln in lines if ln.get("type") == "event" and ln["seq"] == seq)


def _tamper_detail(lines: list[dict[str, Any]]) -> None:
    _event(lines, 3)["detail"]["to_seq"] = 999


def _tamper_gap(lines: list[dict[str, Any]]) -> None:
    lines.remove(_event(lines, 2))


def _tamper_prev(lines: list[dict[str, Any]]) -> None:
    _event(lines, 4)["prev_hash"] = "00" * 32


def _tamper_hash(lines: list[dict[str, Any]]) -> None:
    _event(lines, 5)["hash"] = "11" * 32


def _tamper_anchor_head(lines: list[dict[str, Any]]) -> None:
    anchor = next(ln for ln in lines if ln.get("type") == "anchor")
    anchor["seq_from"] = 1


def _tamper_anchor_tenant(lines: list[dict[str, Any]]) -> None:
    anchor = next(ln for ln in lines if ln.get("type") == "anchor")
    anchor["tenant_id"] = str(OTHER)


def _tamper_no_anchor(lines: list[dict[str, Any]]) -> None:
    lines[:] = [ln for ln in lines if ln.get("type") != "anchor"]


def _tamper_tail(lines: list[dict[str, Any]]) -> None:
    lines[:] = [ln for ln in lines if ln.get("type") != "anchor" or ln["seq_to"] == 2]


def _tamper_rehashed(lines: list[dict[str, Any]]) -> None:
    """A forger with database write: edits row 1 and recomputes every digest after it."""
    _event(lines, 1)["detail"]["to_seq"] = 42
    prev = bytes.fromhex(_event(lines, 1)["prev_hash"])
    for seq in range(1, ROWS):
        event = _event(lines, seq)
        env = hashlib.sha256(_jcs({k: event[k] for k in audit_chain.ENVELOPE_FIELDS})).digest()
        det = hashlib.sha256(_jcs(event["detail"])).digest()
        prev = hashlib.sha256(prev + env + det).digest()
        event.update(
            envelope_sha256=env.hex(),
            detail_sha256=det.hex(),
            hash=prev.hex(),
        )
        if seq + 1 < ROWS:
            _event(lines, seq + 1)["prev_hash"] = prev.hex()


def _tamper_uuid_case(lines: list[dict[str, Any]]) -> None:
    _event(lines, 1)["resource_id"] = str(TENANT).upper()


VARIANTS = {
    "intact": None,
    "detail": _tamper_detail,
    "gap": _tamper_gap,
    "prev": _tamper_prev,
    "hash": _tamper_hash,
    "anchor_fields": _tamper_anchor_head,
    "anchor_tenant": _tamper_anchor_tenant,
    "no_anchor": _tamper_no_anchor,
    "tail": _tamper_tail,
    "rehashed": _tamper_rehashed,
    "uuid_case": _tamper_uuid_case,
}


def _variant(name: str) -> list[dict[str, Any]]:
    lines = copy.deepcopy(_lines())
    tamper = VARIANTS[name]
    if tamper is not None:
        tamper(lines)
    return lines


def _report(name: str) -> str:
    keys = cli_audit.load_public_keys(json.dumps(_keys_doc()).encode())
    return cli_audit.render(cli_audit.verify_export(_variant(name), keys))


# --- tests ---------------------------------------------------------------------------------


def test_row_hash_and_envelope_are_pinned() -> None:
    rows = _rows()
    last = rows[-1]
    recomputed = audit_chain.row_hash(
        bytes(last["prev_hash"]), audit_chain.envelope(last), last["detail"]
    )
    assert recomputed == last["hash"]
    assert last["hash"].hex() == GOLDEN_ROW_HASH_LAST


def test_anchor_document_canonical_bytes_are_pinned() -> None:
    anchor = _anchors(_rows())[1]
    body = canonicalize(_document(anchor))
    assert body.decode() == GOLDEN_ANCHOR_DOC
    assert canonicalize(audit_chain.anchor_document_of(anchor)) == body
    assert chain.anchor_signature_ok(anchor, _signer().public_key_raw)
    assert not chain.anchor_signature_ok({**anchor, "seq_from": 4}, _signer().public_key_raw)
    view = anchoring.anchor_view(anchor)
    assert view == audit_chain.anchor_view(anchor)
    assert hashlib.sha256(canonicalize(view)).hexdigest() == GOLDEN_ANCHOR_VIEW_SHA


def test_export_bytes_are_pinned() -> None:
    assert hashlib.sha256(_export("jsonl")).hexdigest() == GOLDEN_JSONL_SHA
    assert hashlib.sha256(_export("csv")).hexdigest() == GOLDEN_CSV_SHA


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_offline_verifier_report_is_pinned(name: str) -> None:
    assert _report(name) == GOLDEN_REPORTS[name]


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_cli_output_on_a_fixed_export_file_is_pinned(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    export = tmp_path / "export.jsonl"
    export.write_bytes(audit_chain.jsonl(_variant(name)))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(_keys_doc()))
    code = sibyl_cli(["audit", "verify", str(export), "--public-key", str(keys)])
    out = capsys.readouterr()
    assert code == (EXIT_OK if name == "intact" else EXIT_BREAK)
    assert out.out == GOLDEN_REPORTS[name] + "\n"
    assert out.err == GOLDEN_SUMMARIES[name]
