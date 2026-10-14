"""Step 3: identity resolution (API.md §4.2, R13 narrowing).

Order per item: explicit claim (``sibyl.agent_id`` / ``gen_ai.agent.id`` / the event's
``agent_id``) → ``X-Sibyl-Agent`` → the key's bound agent → auto-register a provisional
``unclaimed/<hash8>`` agent. The header and per-item claims may only **narrow**: a bound key
accepts nothing but its own agent; a header-narrowed tenant key accepts nothing but the
header's agent. ``provider.status`` / ``observation.gap`` may stay agent-less (U1).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from ..store import AgentRow

AGENTLESS_TYPES = frozenset({"provider.status", "observation.gap"})


def candidate_hash(candidate: str) -> str:
    return hashlib.sha256(candidate.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]


def unclaimed_slug(candidate: str) -> str:
    return f"unclaimed/{candidate_hash(candidate)[:8]}"


@dataclass(frozen=True)
class Claim:
    """An unknown identity that should be auto-registered."""

    candidate: str
    via: str

    @property
    def slug(self) -> str:
        return unclaimed_slug(self.candidate)

    @property
    def agent_id(self) -> UUID | None:
        """The gateway mints a deterministic UUIDv8 per unknown agent; register under it."""
        try:
            value = UUID(self.candidate)
        except ValueError:
            return None
        return value if value.version == 8 else None


@dataclass
class Directory:
    """Agents known to the batch, by id and slug."""

    by_id: dict[UUID, AgentRow] = field(default_factory=dict)
    by_slug: dict[str, AgentRow] = field(default_factory=dict)

    def add(self, agent: AgentRow) -> None:
        self.by_id[agent.id] = agent
        self.by_slug[agent.slug] = agent

    def lookup(self, ref: str) -> AgentRow | None:
        try:
            return self.by_id.get(UUID(ref))
        except ValueError:
            return self.by_slug.get(ref)


def split_refs(refs: list[str]) -> tuple[list[UUID], list[str]]:
    ids: list[UUID] = []
    slugs: list[str] = []
    for ref in refs:
        try:
            ids.append(UUID(ref))
        except ValueError:
            slugs.append(ref[:200])
    return ids, slugs


@dataclass(frozen=True)
class Resolution:
    agent: AgentRow | None = None
    claim: Claim | None = None
    refused: bool = False


def resolve(
    ref: str | None,
    via: str,
    event_type: str,
    *,
    scope: AgentRow | None,
    directory: Directory,
    key_id: UUID,
) -> Resolution:
    if ref:
        agent = directory.lookup(ref)
        if scope is not None:
            return (
                Resolution(agent=scope)
                if agent is not None and agent.id == scope.id
                else Resolution(refused=True)
            )
        return Resolution(agent=agent) if agent is not None else Resolution(claim=Claim(ref, via))
    if scope is not None:
        return Resolution(agent=scope)
    if event_type in AGENTLESS_TYPES:
        return Resolution()
    return Resolution(claim=Claim(f"api_key:{key_id}", "api_key_default"))


MAX_HANDOFF_REF = 256


def handoff_refs(event: dict[str, Any] | None) -> str | None:
    """D50 auto-discovery: the agent a run or tool handed off to (``handoff_to_agent``)."""
    if event is None or event.get("type") not in ("agent.invoke", "tool.call"):
        return None
    attrs = event.get("attrs")
    ref = attrs.get("handoff_to_agent") if isinstance(attrs, dict) else None
    if not isinstance(ref, str) or not ref.strip():
        return None
    return ref.strip()[:MAX_HANDOFF_REF]
