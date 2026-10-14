"""Behaviour every ``BlobStore`` adapter must share (fs and S3 run the same suite).

Each test module subclasses ``BlobStoreContract`` and provides a ``store`` fixture.
"""

from __future__ import annotations

import hashlib
from datetime import date
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.blob.base import (
    BlobExists,
    BlobNotFound,
    BlobStore,
    InvalidBlobKey,
    payload_key,
)

TENANT = UUID("01927000-0000-7000-8000-0000000000a1")
OTHER = UUID("01927000-0000-7000-8000-0000000000b2")


def key_for(tenant: UUID = TENANT, kind: str = "span_content") -> str:
    return payload_key(tenant, date(2026, 10, 10), kind, uuid4())


class BlobStoreContract:
    async def test_is_a_blob_store(self, store: BlobStore) -> None:
        assert isinstance(store, BlobStore)

    async def test_put_get_round_trip_reports_info(self, store: BlobStore) -> None:
        key = key_for()
        data = b"\x00sealed\xffbytes" * 10
        info = await store.put(key, data, content_type="application/octet-stream")
        assert info.key == key
        assert info.size == len(data)
        assert info.sha256 == hashlib.sha256(data).hexdigest()
        assert info.content_type == "application/octet-stream"
        assert await store.get(key) == data

    async def test_head_matches_put_and_missing_is_none(self, store: BlobStore) -> None:
        key = key_for()
        put = await store.put(key, b"abc", content_type="application/vnd.sibyl.sealed")
        assert await store.head(key) == put
        assert await store.head(key_for()) is None

    async def test_empty_object(self, store: BlobStore) -> None:
        key = key_for()
        info = await store.put(key, b"", content_type="application/octet-stream")
        assert info.size == 0
        assert await store.get(key) == b""

    async def test_if_absent_refuses_overwrite_and_keeps_original(self, store: BlobStore) -> None:
        key = key_for()
        await store.put(key, b"first", content_type="application/octet-stream")
        with pytest.raises(BlobExists):
            await store.put(key, b"second", content_type="application/octet-stream")
        assert await store.get(key) == b"first"

    async def test_overwrite_when_allowed(self, store: BlobStore) -> None:
        key = key_for()
        await store.put(key, b"first", content_type="application/octet-stream")
        info = await store.put(key, b"second!", content_type="text/plain", if_absent=False)
        assert info.size == 7
        assert await store.get(key) == b"second!"

    async def test_get_missing_raises(self, store: BlobStore) -> None:
        with pytest.raises(BlobNotFound):
            await store.get(key_for())

    async def test_delete_is_idempotent(self, store: BlobStore) -> None:
        key = key_for()
        await store.put(key, b"x", content_type="application/octet-stream")
        assert await store.delete(key) is True
        assert await store.delete(key) is False
        assert await store.head(key) is None
        with pytest.raises(BlobNotFound):
            await store.get(key)

    async def test_list_prefix_is_sorted_scoped_and_limited(self, store: BlobStore) -> None:
        mine = sorted(key_for(TENANT) for _ in range(5))
        theirs = key_for(OTHER)
        for key in [*mine, theirs]:
            await store.put(key, b"x", content_type="application/octet-stream")
        listed = await store.list_prefix(f"tenant/{TENANT}/")
        assert listed == mine
        assert await store.list_prefix(f"tenant/{TENANT}/", limit=2) == mine[:2]
        assert await store.list_prefix(f"tenant/{OTHER}/2026-10-10/span_content/") == [theirs]
        assert await store.list_prefix(f"tenant/{uuid4()}/") == []

    @pytest.mark.parametrize("bad", ["/abs/x.bin", "a/../b.bin", "a//b.bin", "", "a b"])
    async def test_invalid_keys_are_refused_everywhere(self, store: BlobStore, bad: str) -> None:
        with pytest.raises(InvalidBlobKey):
            await store.put(bad, b"x", content_type="application/octet-stream")
        with pytest.raises(InvalidBlobKey):
            await store.get(bad)
        with pytest.raises(InvalidBlobKey):
            await store.head(bad)
        with pytest.raises(InvalidBlobKey):
            await store.delete(bad)

    async def test_list_prefix_refuses_traversal(self, store: BlobStore) -> None:
        with pytest.raises(InvalidBlobKey):
            await store.list_prefix("tenant/../")
