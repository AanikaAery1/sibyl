"""``sibyl_schemas.ChainBreakKind`` is the set ``sibyl.audit_verify`` can report, plus
``anchor_signature`` (checked in Python, where the Ed25519 public keys live; lane U CR) and the
offline verifier's export-only verdicts (``OFFLINE_CHAIN_BREAK_KINDS``, CR-U2)."""

from __future__ import annotations

import re

from sibyl_schemas import values as sv

from .conftest import Conn


def test_audit_verify_kinds_equal_the_schemas_enum(admin: Conn) -> None:
    source = admin.fetchval(
        "SELECT pg_get_functiondef('sibyl.audit_verify(uuid, bigint, bigint)'::regprocedure)"
    )
    returned = set(re.findall(r"'([a-z_]+)'::text", source))
    python_only = {sv.ChainBreakKind.ANCHOR_SIGNATURE, *sv.OFFLINE_CHAIN_BREAK_KINDS}
    expected = {k.value for k in sv.ChainBreakKind} - {k.value for k in python_only}
    assert returned == expected
