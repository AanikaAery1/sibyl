"""Filesystem BlobStore: the shared contract plus atomicity, confinement and on-disk format."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from sibyl_control.core.blob.base import BlobError, BlobNotFound
from sibyl_control.core.blob.fs import FsBlobStore

from .blob_contract import BlobStoreContract, key_for


@pytest.fixture
def store(tmp_path: Path) -> FsBlobStore:
    return FsBlobStore(tmp_path / "blob")


class TestFsContract(BlobStoreContract):
    pass


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


async def test_root_is_created_private(tmp_path: Path) -> None:
    root = tmp_path / "nested" / "blob"
    store = FsBlobStore(root)
    await store.put(key_for(), b"x", content_type="application/octet-stream")
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


async def test_objects_and_directories_are_private(store: FsBlobStore) -> None:
    key = key_for()
    await store.put(key, b"secret-ish", content_type="application/octet-stream")
    path = store.root / key
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


async def test_failed_write_leaves_nothing_visible(
    store: FsBlobStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = key_for()

    def boom(fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(BlobError):
        await store.put(key, b"partial", content_type="application/octet-stream")
    monkeypatch.undo()
    assert await store.head(key) is None
    assert _files(store.root) == []
    with pytest.raises(BlobNotFound):
        await store.get(key)


async def test_temp_files_are_never_listed(store: FsBlobStore) -> None:
    key = key_for()
    await store.put(key, b"x", content_type="application/octet-stream")
    stray = (store.root / key).parent / ".tmp-abandoned"
    stray.write_bytes(b"junk")
    assert await store.list_prefix("tenant/") == [key]


async def test_symlinked_directory_cannot_escape_root(store: FsBlobStore, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    store.root.mkdir(parents=True, exist_ok=True)
    (store.root / "tenant").symlink_to(outside, target_is_directory=True)
    with pytest.raises(BlobError):
        await store.put(key_for(), b"x", content_type="application/octet-stream")
    assert list(outside.iterdir()) == []


async def test_corrupted_object_is_detected(store: FsBlobStore) -> None:
    key = key_for()
    await store.put(key, b"payload bytes", content_type="application/octet-stream")
    path = store.root / key
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 0x01
    path.write_bytes(bytes(raw))
    with pytest.raises(BlobError, match="integrity"):
        await store.get(key)


async def test_foreign_file_is_rejected(store: FsBlobStore) -> None:
    key = key_for()
    path = store.root / key
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not a sibyl object")
    with pytest.raises(BlobError):
        await store.get(key)


async def test_presigned_get_is_unsupported(store: FsBlobStore) -> None:
    assert await store.presigned_get(key_for(), expires_s=60) is None


async def test_delete_prunes_nothing_outside_the_key(store: FsBlobStore) -> None:
    a, b = key_for(), key_for()
    await store.put(a, b"a", content_type="application/octet-stream")
    await store.put(b, b"b", content_type="application/octet-stream")
    await store.delete(a)
    assert await store.get(b) == b"b"
