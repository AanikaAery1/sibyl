"""Key-set catch-up over ``GET /api/v1/policy/keys?since=<sequence>`` (B9, B10, B18).

The api answers a ``KeySetChain``: ``{data: [every set with sequence > since, ascending, at most
1000], latest_sequence}``. The gateway asks with the sequence it holds, verifies every member in
order on a staged catch-up (from the pinned key at sequence 0: the self-signed genesis first),
pages with the staged sequence while the chain says more remain, and commits once. The first
failing member rejects the whole delivery; the chain keeps the last set it had verified.

Page parsing and verification are ``sibyl_schemas.keyset``'s (B33); this module only does the
asynchronous HTTP, off-loading verification to a worker thread.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

import httpx
from sibyl_schemas.keyset import (
    KEYS_PATH,
    MAX_CHAIN_PAGE,
    MAX_PAGES,
    MAX_SEQUENCE,
    ChainFetchError,
    ChainPage,
    parse_chain_page,
)

from .keychain import KeyChain

__all__ = [
    "KEYS_PATH",
    "MAX_CHAIN_PAGE",
    "MAX_PAGES",
    "MAX_SEQUENCE",
    "ChainFetchError",
    "ChainPage",
    "SyncResult",
    "follow_chain",
    "parse_chain_page",
]


@dataclass(frozen=True)
class SyncResult:
    adopted: int
    sequence: int


async def _page(client: httpx.AsyncClient, url: str, since: int) -> ChainPage:
    try:
        resp = await client.get(url, params={"since": since})
    except httpx.HTTPError as exc:
        raise ChainFetchError(type(exc).__name__) from None
    if resp.status_code != 200:
        raise ChainFetchError(f"HTTP {resp.status_code}")
    return parse_chain_page(resp.content)


async def follow_chain(
    client: httpx.AsyncClient, base_url: str, chain: KeyChain, *, now: datetime
) -> SyncResult:
    """Fetch, verify and adopt every set after the held sequence (public route, no key sent).

    Raises ``KeySetRejected`` (nothing adopted) or ``ChainFetchError``."""
    stage = chain.stage()
    url = base_url.rstrip("/") + KEYS_PATH
    for _ in range(MAX_PAGES):
        page = await _page(client, url, stage.sequence)
        if not await asyncio.to_thread(stage.accept_page, page, now=now):
            break
    if stage.count == 0:
        return SyncResult(0, chain.sequence)
    sequence = await asyncio.to_thread(chain.commit, stage)
    return SyncResult(stage.count, sequence)
