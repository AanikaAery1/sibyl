"""Status poller loop (lane H): provider status feeds -> ``provider_status`` (feeds R4)."""

from __future__ import annotations

import httpx

from ..loops import LoopContext
from .fetch import FetchPolicy
from .poller import PollerSettings, PollResult, poll


async def tick(ctx: LoopContext) -> None:
    settings = PollerSettings()
    policy = FetchPolicy(dev_hosts=frozenset(h.lower() for h in settings.dev_hosts))
    async with httpx.AsyncClient(follow_redirects=False, trust_env=False) as client:
        result = await poll(ctx.db, client=client, policy=policy, settings=settings)
    for note in result.skipped:
        ctx.log.warning("status feed skipped: %s", note)
    if result.failed:
        ctx.log.warning("status poller: %d feed(s) failed", result.failed)


__all__ = ["PollResult", "PollerSettings", "poll", "tick"]
