"""Strong ETags and If-Match / If-None-Match (API.md §2.5).

ETag = ``"<row_version>"`` where the table has one, else ``"<sha256(updated_at ∥ id)[:16]>"``.
PATCH/PUT on policy objects require If-Match (428 when absent, 412 with the current
representation on mismatch). ``If-Match: *`` is honoured only to create on first write; against
an existing row it is a 412 so a client can never blind-overwrite policy.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID

from .problems import ProblemError


def etag_for_version(version: int) -> str:
    return f'"{int(version)}"'


def etag_for_row(updated_at: datetime, row_id: UUID) -> str:
    digest = hashlib.sha256(f"{updated_at.isoformat()}|{row_id}".encode()).hexdigest()
    return f'"{digest[:16]}"'


def _split(header: str) -> list[str]:
    return [part.strip() for part in header.split(",") if part.strip()]


def _strip_weak(tag: str) -> str:
    return tag[2:] if tag.startswith("W/") else tag


def check_if_match(
    header: str | None,
    current: str | None,
    *,
    allow_star_create: bool = False,
    current_body: Any = None,
) -> None:
    """Raise unless ``header`` licenses a write over ``current`` (``None`` = no row yet)."""
    if header is None or not header.strip():
        raise ProblemError("precondition_required", "send If-Match with the current ETag")
    tags = _split(header)
    if tags == ["*"]:
        if allow_star_create and current is None:
            return
        raise _failed(current_body)
    if current is not None and any(t == current for t in tags if not t.startswith("W/")):
        return
    raise _failed(current_body)


def _failed(current_body: Any) -> ProblemError:
    ext = {"current": current_body} if current_body is not None else {}
    return ProblemError("precondition_failed", extensions=ext)


def if_none_match_hit(header: str | None, current: str | None) -> bool:
    """True when a GET should answer 304 (weak comparison, RFC 9110 §13.1.2)."""
    if not header or current is None:
        return False
    tags = _split(header)
    if tags == ["*"]:
        return True
    return _strip_weak(current) in {_strip_weak(t) for t in tags}
