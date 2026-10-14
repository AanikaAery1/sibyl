"""The erasure ledger in the BlobStore (R63), written through ``sibyl_control.migrate.ledger``.

Layout under ``ledger/erasure/`` (a prefix of its own, outside every tenant's prefix, so no
erasure ever deletes it):

* ``entries/<seq:012d>.json``: one signed entry per completed erasure, written create-only.
  Create-only is the append-only guarantee and the race guard: two writers cannot both claim
  a sequence number. The entries are the source of truth.
* ``ledger.jsonl``: the whole ledger, rebuilt from the entries after verification (what the
  restore runbook feeds to ``python -m sibyl_control.migrate ledger-verify`` and then to
  ``sibyl.erasure_reapply_from_ledger``).
* ``head.json``: the signed head ``{count, head_hash, at, sig}`` the backup manifest records.

Entries hold ids, scope, key ids and times only (no personal data: subject refs are salted
hashes), so they are stored signed but not encrypted: a restore must be able to read them
without the KEK or the database.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from sibyl_schemas.canonical import canonicalize

from ...core.blob.base import BlobExists, BlobNotFound, BlobStore
from ...migrate import ledger

PREFIX = "ledger/erasure"
ENTRIES = f"{PREFIX}/entries/"
JSONL_KEY = f"{PREFIX}/ledger.jsonl"
HEAD_KEY = f"{PREFIX}/head.json"
MAX_ENTRIES = 1_000_000
APPEND_ATTEMPTS = 5


def entry_key(seq: int) -> str:
    return f"{ENTRIES}{seq:012d}.json"


async def load(store: BlobStore) -> list[Mapping[str, Any]]:
    keys = sorted(await store.list_prefix(ENTRIES, limit=MAX_ENTRIES))
    entries: list[Mapping[str, Any]] = []
    for key in keys:
        entries.append(json.loads(await store.get(key)))
    for seq, entry in enumerate(entries):
        if entry.get("seq") != seq:
            raise ledger.LedgerError(f"ledger entry objects are not gapless at seq {seq}")
    return entries


def find(entries: Sequence[Mapping[str, Any]], request_id: str) -> Mapping[str, Any] | None:
    return next((e for e in entries if e.get("erasure_request_id") == request_id), None)


async def append(
    store: BlobStore,
    signing_key: Any,
    *,
    tenant_id: str,
    erasure_request_id: str,
    scope_kind: str,
    scope_ref: str | None,
    key_ids: Sequence[str],
    completed_at: str,
    subject_set: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    """Append one signed entry (idempotent per erasure request); → the entry."""
    for _ in range(APPEND_ATTEMPTS):
        entries = await load(store)
        existing = find(entries, erasure_request_id)
        if existing is not None:
            return existing
        entry = ledger.append(
            entries,
            signing_key=signing_key,
            tenant_id=tenant_id,
            erasure_request_id=erasure_request_id,
            scope_kind=scope_kind,
            scope_ref=scope_ref,
            key_ids=list(key_ids),
            completed_at=completed_at,
            subject_set=subject_set,
        )[-1]
        try:
            await store.put(
                entry_key(int(entry["seq"])),
                canonicalize(dict(entry), allow_floats=False),
                content_type="application/json",
                if_absent=True,
            )
        except BlobExists:
            continue  # another writer took this sequence number: reload and retry
        return entry
    raise ledger.LedgerError("could not append to the erasure ledger (contention)")


async def materialise(store: BlobStore, signing_key: Any, *, at: str) -> tuple[int, str]:
    """Verify the entries, then rewrite ``ledger.jsonl`` and the signed ``head.json``."""
    entries = await load(store)
    text = ledger.to_jsonl(entries)
    verified = ledger.verify(text, signing_key.public_key())
    head = ledger.sign_head(verified, signing_key, at=at)
    await store.put(JSONL_KEY, text.encode(), content_type="application/x-ndjson", if_absent=False)
    await store.put(
        HEAD_KEY,
        json.dumps(head, sort_keys=True).encode(),
        content_type="application/json",
        if_absent=False,
    )
    return ledger.head_of(verified)


async def read_jsonl(store: BlobStore) -> str:
    try:
        return (await store.get(JSONL_KEY)).decode()
    except BlobNotFound:
        return ""


def signing_key_from_settings(settings: Any) -> Any:
    path = getattr(settings, "ledger_signing_key_file", None)
    if not path:
        raise RuntimeError("SIBYL_LEDGER_SIGNING_KEY_FILE is not configured")
    with open(path, "rb") as fh:
        return ledger.load_private_key(fh.read())
