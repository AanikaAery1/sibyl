"""What a running stack looks like to the harness: URLs, tenants, agents, personas, keys.

Pure data, no control-plane imports: the in-process stack builds a `World`, and compose mode
(later) can build the same shape from environment variables and a seeded database. Actors and
the oracle only ever see a `World` plus URLs, never a database connection (ML §8.1).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

PERSONAS = ("admin", "operator", "auditor")
CHAOS_TENANT = "meridian"
STEADY_TENANT = "northstar"
EMPTY_TENANT = "sandbox"


@dataclass(frozen=True)
class Endpoints:
    """Base URLs of every service the harness talks to (no trailing slash)."""

    api: str
    ingest: str
    gateway: str
    sim_control: str
    doubles: str
    ca_file: str | None = None
    sdk_pin: str = ""  # `kid:public_key` of the snapshot signing key the SDK pins (R33)

    def double_url(self, double: str) -> str:
        return f"{self.doubles}/{double}/v1"


@dataclass(frozen=True)
class AgentInfo:
    slug: str
    id: UUID
    tier: int
    provider: str  # double slug, e.g. openai-stub
    model: str
    sdk_key: str = field(repr=False, default="")


@dataclass(frozen=True)
class PersonaInfo:
    name: str
    user_id: UUID
    roles: tuple[str, ...]
    token: str = field(repr=False, default="")
    stepup_token: str = field(repr=False, default="")  # a session with a fresh step-up


@dataclass(frozen=True)
class TenantInfo:
    slug: str
    id: UUID
    agents: dict[str, AgentInfo] = field(default_factory=dict)
    providers: dict[str, UUID] = field(default_factory=dict)
    personas: dict[str, PersonaInfo] = field(default_factory=dict)
    gateway_key: str = field(default="", repr=False)
    ingest_key: str = field(default="", repr=False)
    provider_secret: str = field(default="", repr=False)

    def agent(self, slug: str) -> AgentInfo:
        try:
            return self.agents[slug]
        except KeyError:
            raise KeyError(f"{self.slug} has no agent {slug!r}") from None

    def agent_by_id(self, agent_id: UUID | str) -> AgentInfo | None:
        wanted = str(agent_id)
        return next((a for a in self.agents.values() if str(a.id) == wanted), None)

    def token(self, persona: str) -> str:
        try:
            return self.personas[persona].token
        except KeyError:
            raise KeyError(f"{persona} has no binding in {self.slug}") from None


@dataclass(frozen=True)
class World:
    tenants: dict[str, TenantInfo]
    doubles_port: int
    template: str = ""
    bridges: tuple[str, ...] = ()  # compensations for known product defects, always reported

    def tenant(self, slug: str) -> TenantInfo:
        try:
            return self.tenants[slug]
        except KeyError:
            raise KeyError(f"unknown tenant {slug!r}") from None

    def owner_of(self, agent_id: UUID | str) -> tuple[TenantInfo, AgentInfo] | None:
        for tenant in self.tenants.values():
            agent = tenant.agent_by_id(agent_id)
            if agent is not None:
                return tenant, agent
        return None

    # ------------------------------------------------------------------ persistence

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, sort_keys=True, indent=1)

    @classmethod
    def from_json(cls, text: str) -> World:
        raw = json.loads(text)
        tenants: dict[str, TenantInfo] = {}
        for slug, t in raw["tenants"].items():
            agents = {
                a_slug: AgentInfo(
                    a["slug"],
                    UUID(a["id"]),
                    int(a["tier"]),
                    a["provider"],
                    a["model"],
                    a["sdk_key"],
                )
                for a_slug, a in t["agents"].items()
            }
            personas = {
                name: PersonaInfo(
                    p["name"],
                    UUID(p["user_id"]),
                    tuple(p["roles"]),
                    p["token"],
                    p.get("stepup_token", ""),
                )
                for name, p in t["personas"].items()
            }
            tenants[slug] = TenantInfo(
                t["slug"],
                UUID(t["id"]),
                agents,
                {k: UUID(v) for k, v in t["providers"].items()},
                personas,
                t["gateway_key"],
                t["ingest_key"],
                t["provider_secret"],
            )
        return cls(
            tenants,
            int(raw["doubles_port"]),
            raw.get("template", ""),
            tuple(raw.get("bridges") or ()),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), "utf-8")
        path.chmod(0o600)  # dev-only keys, but keys all the same

    @classmethod
    def load(cls, path: Path) -> World:
        return cls.from_json(path.read_text("utf-8"))


def describe(world: World) -> dict[str, Any]:
    """A key-free summary for reports."""
    return {
        slug: {"agents": len(t.agents), "tiers": sorted({a.tier for a in t.agents.values()})}
        for slug, t in world.tenants.items()
    }
