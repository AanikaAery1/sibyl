"""Optional disk spool: one gzip segment per failed batch, replayed oldest-first.

Segment name `<ts_ms>-<batch_id>.<kind>.gz`; the content is exactly the gzip body that
was POSTed, so replay reuses the original batch id and timestamps (ingest batch dedupe,
API §4.3, makes a replay after an ambiguous timeout safe). Writes are atomic (tmp + rename).
Caps: total bytes and age; the oldest segments go first and are counted as dropped.
"""

from __future__ import annotations

import contextlib
import gzip
import logging
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

log = logging.getLogger("sibyl")

BatchKind = Literal["traces", "logs", "events"]
_NAME_RE: Final = re.compile(r"^(\d{13})-([0-9a-f-]{36})\.(traces|logs|events)\.gz$")


@dataclass(frozen=True)
class Segment:
    path: Path
    created_ms: int
    batch_id: str
    kind: BatchKind
    size: int
    items: int


class Spool:
    def __init__(self, directory: str, max_bytes: int, max_age_s: float) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._max_bytes = max_bytes
        self._max_age_ms = int(max_age_s * 1000)
        self._lock = threading.Lock()
        self.dropped_items = 0
        self.corrupt_segments = 0

    def write(
        self, *, batch_id: str, kind: BatchKind, body_gz: bytes, items: int, now_ms: int
    ) -> None:
        name = f"{now_ms:013d}-{batch_id}.{kind}.gz"
        tmp = self._dir / f".{name}.{items}.tmp"
        with self._lock:
            tmp.write_bytes(body_gz)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._dir / f"{name}")
            (self._dir / f"{name}.n").write_text(str(items), "ascii")
        self.enforce_caps(now_ms)

    def segments(self) -> list[Segment]:
        found: list[Segment] = []
        for path in self._dir.iterdir():
            match = _NAME_RE.match(path.name)
            if match is None:
                continue
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                continue
            found.append(
                Segment(
                    path=path,
                    created_ms=int(match.group(1)),
                    batch_id=match.group(2),
                    kind=cast(BatchKind, match.group(3)),
                    size=size,
                    items=self._items(path),
                )
            )
        return sorted(found, key=lambda seg: (seg.created_ms, seg.batch_id))

    def _items(self, path: Path) -> int:
        try:
            return int(Path(f"{path}.n").read_text("ascii"))
        except (FileNotFoundError, ValueError):
            return 1

    def read(self, segment: Segment) -> bytes | None:
        """The gzip body, or None (segment deleted and counted) if it is corrupt."""
        try:
            body = segment.path.read_bytes()
            gzip.decompress(body)
        except (OSError, EOFError, gzip.BadGzipFile):
            self.corrupt_segments += 1
            log.warning("sibyl: dropping corrupt spool segment %s", segment.path.name)
            self.remove(segment, dropped=True)
            return None
        return body

    def remove(self, segment: Segment, *, dropped: bool = False) -> None:
        with self._lock:
            if dropped:
                self.dropped_items += segment.items
            for path in (segment.path, Path(f"{segment.path}.n")):
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()

    def has_segments(self) -> bool:
        return any(_NAME_RE.match(path.name) for path in self._dir.iterdir())

    def total_bytes(self) -> int:
        return sum(seg.size for seg in self.segments())

    def enforce_caps(self, now_ms: int) -> None:
        segments = self.segments()
        total = sum(seg.size for seg in segments)
        for seg in segments:
            too_old = now_ms - seg.created_ms > self._max_age_ms
            if not too_old and total <= self._max_bytes:
                break
            total -= seg.size
            self.remove(seg, dropped=True)
