"""Key-set catch-up over `GET /api/v1/policy/keys?since=<sequence>` (B10, B18).

The api answers a `KeySetChain`: `{data: [every set with sequence > since, ascending, at most
1000], latest_sequence}`. The SDK asks with the sequence it holds, verifies every member in
order (from the pin; without one it trusts the self-signed genesis on first use), pages with
the staged sequence while the chain says more remain, and commits once. The first failing
member rejects the whole delivery; the verifier keeps the last set it had verified.

Paging, verification and trust on first use are `sibyl_schemas.keyset.follow_chain`'s (B33),
the same follower the gateway uses; this module adapts it to `KeySetVerifier`.
"""

from __future__ import annotations

from datetime import datetime

from sibyl_schemas import keyset
from sibyl_schemas.keyset import (
    KEYS_PATH,
    MAX_CHAIN_PAGE,
    MAX_PAGES,
    MAX_SEQUENCE,
    ChainFetchError,
    ChainFollower,
    ChainPage,
    Fetch,
    parse_chain_page,
)

from sibyl._keys import KeySetVerifier

__all__ = [
    "KEYS_PATH",
    "MAX_CHAIN_PAGE",
    "MAX_PAGES",
    "MAX_SEQUENCE",
    "ChainFetchError",
    "ChainPage",
    "Fetch",
    "follow_chain",
    "parse_chain_page",
]


def follow_chain(
    fetch: Fetch, verifier: KeySetVerifier | None, *, now: datetime
) -> tuple[KeySetVerifier | None, int]:
    """Fetch, verify and adopt every set after the held sequence: (verifier, sets adopted).

    Without a verifier the genesis is trusted on first use and returned only if the whole
    delivery verifies. Raises `KeySetRejected` (nothing adopted) or `ChainFetchError`."""
    held = verifier.follower if verifier is not None else None
    follower, adopted = keyset.follow_chain(fetch, held, now=now, kind=ChainFollower)
    if follower is None:
        return None, adopted
    if verifier is not None and follower is held:
        return verifier, adopted
    return KeySetVerifier._of(follower), adopted
