"""Lane U's one audit-chain addition over ``sibyl_schemas.audit_chain``: the anchor signature.

The row hash, the anchor document / view, the export lines, ``jsonl``, ``rfc3339`` and
``b64url`` live in ``sibyl_schemas.audit_chain`` (INT-1), shared by the anchors loop, the export
writer, the governance api and the Apache-2 offline verifier (``sibyl audit verify``). What stays
here needs the kernel crypto: the Ed25519 check of a stored anchor against a published
``audit_anchor`` public key (ADR-12), over ``JCS(anchor_document_of(row))``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sibyl_schemas.audit_chain import anchor_document_of, b64url

from ...core.canonical import canonicalize
from ...core.crypto.signing import verify_document


def anchor_signature_ok(row: Mapping[str, Any], public_key_raw: bytes) -> bool:
    """A stored ``audit_anchors`` row (raw 64-byte signature) is signed by ``public_key_raw``."""
    signature = b64url(bytes(row["signature"]))
    return verify_document(canonicalize(anchor_document_of(row)), signature, public_key_raw)
