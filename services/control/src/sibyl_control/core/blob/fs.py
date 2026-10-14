"""Filesystem BlobStore (``SIBYL_BLOB_BACKEND=fs``, root ``SIBYL_BLOB_ROOT``).

Writes are atomic: bytes go to a private temp file in the target directory, are fsynced, and
are then published with ``link()`` (``if_absent``: fails if the key exists) or ``replace()``.
A reader therefore sees either nothing or the whole object, never a torn write. The directory
is fsynced after publishing. Nothing below the root may be a symlink, so a planted link cannot
redirect writes outside the root. Directories are 0700 and objects 0600.

On-disk format (internal to this adapter): ``SBLB`` magic, format version, sha256 of the data,
content-type length and bytes, then the data. ``get`` re-hashes and refuses a mismatch, so a
truncated or bit-flipped object surfaces as ``BlobError`` instead of a confusing decrypt
failure higher up. Objects are already encrypted by the caller; this adapter never sees
plaintext.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import secrets
import stat
from pathlib import Path

from .base import BlobError, BlobExists, BlobInfo, BlobNotFound, validate_key

MAGIC = b"SBLB"
FORMAT_VERSION = 1
_HEADER_FIXED = len(MAGIC) + 1 + 32 + 1
_DIR_MODE = 0o700
_FILE_MODE = 0o600
_TMP_PREFIX = ".tmp-"


def _encode(data: bytes, content_type: str) -> bytes:
    ct = content_type.encode("ascii")
    if not 0 < len(ct) <= 255:
        raise ValueError("content_type must be 1..255 ASCII characters")
    digest = hashlib.sha256(data).digest()
    return MAGIC + bytes([FORMAT_VERSION]) + digest + bytes([len(ct)]) + ct + data


def _decode_header(raw: bytes) -> tuple[bytes, str, int]:
    """Return (sha256 digest, content type, data offset)."""
    if len(raw) < _HEADER_FIXED or raw[: len(MAGIC)] != MAGIC:
        raise BlobError("not a Sibyl blob object")
    if raw[len(MAGIC)] != FORMAT_VERSION:
        raise BlobError("unsupported blob object version")
    digest = raw[len(MAGIC) + 1 : len(MAGIC) + 33]
    ct_len = raw[len(MAGIC) + 33]
    offset = _HEADER_FIXED + ct_len
    if len(raw) < offset:
        raise BlobError("truncated blob object header")
    return digest, raw[_HEADER_FIXED:offset].decode("ascii"), offset


def _validate_prefix(prefix: str) -> str:
    if prefix:
        validate_key(prefix.rstrip("/") or "x/")
    return prefix


class FsBlobStore:
    """Local-filesystem adapter; blocking IO runs in worker threads."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)

    # -- path handling -------------------------------------------------------------------

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        if self.root.is_symlink():
            raise BlobError("blob root must not be a symlink")
        os.chmod(self.root, _DIR_MODE)

    def _path(self, key: str, *, create_dirs: bool) -> Path:
        """Resolve ``key`` under the root; refuses any symlinked component."""
        validate_key(key)
        if create_dirs:
            self._ensure_root()
        current = self.root
        parts = key.split("/")
        for part in parts[:-1]:
            current = current / part
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                if not create_dirs:
                    return self.root.joinpath(*parts)
                try:
                    os.mkdir(current, _DIR_MODE)
                except FileExistsError:
                    mode = os.lstat(current).st_mode
                else:
                    continue
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise BlobError("blob path component is not a plain directory")
        return current / parts[-1]

    # -- blocking implementations --------------------------------------------------------

    def _put_sync(self, key: str, data: bytes, content_type: str, if_absent: bool) -> BlobInfo:
        encoded = _encode(data, content_type)
        final = self._path(key, create_dirs=True)
        tmp = final.parent / f"{_TMP_PREFIX}{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(tmp, flags, _FILE_MODE)
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            if if_absent:
                try:
                    os.link(tmp, final)
                except FileExistsError:
                    raise BlobExists(key) from None
            else:
                os.replace(tmp, final)
            self._fsync_dir(final.parent)
        except BlobError:
            raise
        except OSError as exc:
            raise BlobError(
                f"blob write failed ({errno.errorcode.get(exc.errno or 0, 'io')})"
            ) from exc
        finally:
            tmp.unlink(missing_ok=True)
        return BlobInfo(key, len(data), hashlib.sha256(data).hexdigest(), content_type)

    @staticmethod
    def _fsync_dir(directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_raw(self, key: str) -> bytes:
        path = self._path(key, create_dirs=False)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            raise BlobNotFound(key) from None
        except OSError as exc:
            raise BlobError("blob read failed") from exc
        with os.fdopen(fd, "rb") as fh:
            return fh.read()

    def _get_sync(self, key: str) -> bytes:
        raw = self._read_raw(key)
        digest, _ct, offset = _decode_header(raw)
        data = raw[offset:]
        if hashlib.sha256(data).digest() != digest:
            raise BlobError("blob integrity check failed")
        return data

    def _head_sync(self, key: str) -> BlobInfo | None:
        try:
            raw = self._read_raw(key)
        except BlobNotFound:
            return None
        digest, content_type, offset = _decode_header(raw)
        return BlobInfo(key, len(raw) - offset, digest.hex(), content_type)

    def _delete_sync(self, key: str) -> bool:
        path = self._path(key, create_dirs=False)
        try:
            os.unlink(path)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise BlobError("blob delete failed") from exc
        return True

    def _list_sync(self, prefix: str, limit: int) -> list[str]:
        _validate_prefix(prefix)
        directory, _, _ = prefix.rpartition("/")
        base = self.root / directory if directory else self.root
        if not base.is_dir() or base.is_symlink():
            return []
        found: list[str] = []
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            rel_dir = Path(dirpath).relative_to(self.root).as_posix()
            for name in filenames:
                if name.startswith("."):
                    continue
                key = name if rel_dir == "." else f"{rel_dir}/{name}"
                if key.startswith(prefix):
                    found.append(key)
        return sorted(found)[:limit]

    # -- BlobStore protocol ----------------------------------------------------------------

    async def put(
        self, key: str, data: bytes, *, content_type: str, if_absent: bool = True
    ) -> BlobInfo:
        validate_key(key)
        return await asyncio.to_thread(self._put_sync, key, data, content_type, if_absent)

    async def get(self, key: str) -> bytes:
        validate_key(key)
        return await asyncio.to_thread(self._get_sync, key)

    async def head(self, key: str) -> BlobInfo | None:
        validate_key(key)
        return await asyncio.to_thread(self._head_sync, key)

    async def delete(self, key: str) -> bool:
        validate_key(key)
        return await asyncio.to_thread(self._delete_sync, key)

    async def list_prefix(self, prefix: str, *, limit: int = 1000) -> list[str]:
        _validate_prefix(prefix)
        return await asyncio.to_thread(self._list_sync, prefix, limit)

    async def presigned_get(self, key: str, *, expires_s: int) -> str | None:
        validate_key(key)
        return None
