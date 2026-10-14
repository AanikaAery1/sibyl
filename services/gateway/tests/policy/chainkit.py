"""Test-only signed key-set chains (B10): genesis + N rotations, a fake ``?since=`` route."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .test_keychain import _Key

T0 = datetime.now(UTC) - timedelta(days=30)


def rotation_chain(rotations: int, *, t0: datetime = T0) -> tuple[list[_Key], list[str]]:
    """``keys[0]`` is the pinned genesis key; set ``n+1`` is signed by ``keys[n-1]`` and rotates
    to ``keys[n]`` (announced by the previous set), keeping the outgoing key ``retiring``."""
    keys = [_Key(f"k{i + 1}") for i in range(rotations + 2)]
    sets = [keys[0].sign_set(1, [keys[0].entry()], keys[1].entry(None), t0)]
    for n in range(1, rotations + 1):
        nxt = keys[n + 1].entry(None) if n < rotations else None
        retiring = {**keys[n - 1].entry("retiring"), "not_after": "2099-01-01T00:00:00.000Z"}
        sets.append(
            keys[n - 1].sign_set(n + 1, [keys[n].entry(), retiring], nxt, t0 + timedelta(days=n))
        )
    return keys, sets


def tamper(text: str) -> str:
    """Same signature, different signed body (issued_at moves to another year)."""
    doc = json.loads(text)
    doc["body"]["issued_at"] = "2030" + doc["body"]["issued_at"][4:]
    return json.dumps(doc)


@dataclass
class ChainRoute:
    """``GET /api/v1/policy/keys?since=n`` answering ``KeySetChain`` pages of ``page`` sets."""

    sets: list[str]
    page: int = 1000
    seen_since: list[int] = field(default_factory=list)
    latest: int | None = None
    data: list[str] | None = None  # served verbatim instead of the sets after ``since``

    def response(self, request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers  # public route, no key sent
        since = int(request.url.params["since"])
        self.seen_since.append(since)
        docs = [json.loads(s) for s in self.sets]
        after = [d for d in docs if d["body"]["sequence"] > since][: self.page]
        if self.data is not None:
            after = [json.loads(s) for s in self.data]
        latest = self.latest
        if latest is None:
            latest = max((d["body"]["sequence"] for d in docs), default=0)
        payload: dict[str, Any] = {"data": after, "latest_sequence": latest}
        return httpx.Response(200, content=json.dumps(payload).encode())
