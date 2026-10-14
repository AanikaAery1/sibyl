"""Server-side audit verification (``POST /audit/verifications`` and its async job).

``sibyl.audit_verify`` walks the chain in Postgres (gap, prev/content/hash mismatch and, for a
full walk, truncation, head and anchor mismatches). Anchor **signatures** need the Ed25519 public
keys, so they are checked here: every anchor whose ``seq_to`` lies in the verified range must be
signed by a published ``audit_anchor`` key that is not ``compromised``. ``anchors_checked``
counts the anchors whose signature and head hash were both confirmed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sibyl_schemas.values import ChainBreakKind

from .chain import anchor_signature_ok
from .common import anchor_public_keys

SYNC_ROW_LIMIT = 100_000


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    rows: int
    anchors_checked: int
    first_break_seq: int | None
    kind: str | None
    from_seq: int
    to_seq: int | None

    def body(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "rows": self.rows,
            "anchors_checked": self.anchors_checked,
            "first_break_seq": self.first_break_seq,
            "kind": self.kind,
        }

    @property
    def last_seq(self) -> int | None:
        if self.to_seq is not None:
            return self.to_seq
        return self.from_seq + self.rows - 1 if self.rows else None

    def audit_detail(self) -> dict[str, Any]:
        if self.ok:
            return {
                "from_seq": self.from_seq,
                "to_seq": self.last_seq,
                "anchors_checked": self.anchors_checked,
                "rows": self.rows,
            }
        return {
            "first_break_seq": self.first_break_seq,
            "kind": self.kind,
            "from_seq": self.from_seq,
            "to_seq": self.last_seq,
            "rows": self.rows,
        }

    @property
    def action(self) -> str:
        return "audit.verified" if self.ok else "audit.verify_failed"


async def head_seq(conn: Any, tenant_id: UUID) -> int | None:
    value = await conn.fetchval(
        "SELECT seq FROM sibyl.audit_chain_head WHERE tenant_id = $1", tenant_id
    )
    return None if value is None else int(value)


async def verify_chain(
    conn: Any, tenant_id: UUID, from_seq: int = 0, to_seq: int | None = None
) -> VerificationResult:
    row = await conn.fetchrow(
        "SELECT ok, rows_checked, first_break_seq, kind FROM sibyl.audit_verify($1, $2, $3)",
        tenant_id,
        from_seq,
        to_seq,
    )
    rows = int(row["rows_checked"])
    if not row["ok"]:
        return VerificationResult(
            False, rows, 0, row["first_break_seq"], row["kind"], from_seq, to_seq
        )
    last = from_seq + rows - 1
    keys = await anchor_public_keys(conn)
    anchors = await conn.fetch(
        "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 AND seq_to >= $2"
        " AND seq_to <= $3 ORDER BY seq_to",
        tenant_id,
        from_seq,
        last,
    )
    checked = 0
    for anchor in anchors:
        key = keys.get(anchor["signing_kid"])
        if key is None or key[1] == "compromised" or not anchor_signature_ok(anchor, key[0]):
            return VerificationResult(
                False,
                rows,
                checked,
                int(anchor["seq_to"]),
                ChainBreakKind.ANCHOR_SIGNATURE.value,
                from_seq,
                to_seq,
            )
        checked += 1
    return VerificationResult(True, rows, checked, None, None, from_seq, to_seq)
