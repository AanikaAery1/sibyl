"""Deterministic traffic plans (qa-expert §1.1 rule 5).

Every random choice an actor makes comes from `rng_for(seed, scenario, agent, stream)`: a
`random.Random` seeded from a SHA-256 of those parts, so streams are independent of each other
and of the order in which agents are planned. A plan is a list of `Arrival`s, each with a
sim-time offset, a stable request id (UUIDv5) and a prompt; the same seed and scenario give a
byte-identical plan, which is what makes a failed run point at a diff instead of at luck.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import dataclass

from ..scenarios.model import AgentRef, Profile

NAMESPACE = uuid.UUID("0b1d5e5a-51b1-4c5a-9a5e-5ea1ab1e0001")
TOPICS = (
    "pallet freight quote",
    "refund for a damaged parcel",
    "route change for tomorrow",
    "invoice reconciliation",
    "driver shift swap",
    "customs paperwork",
    "late delivery apology",
    "fuel surcharge question",
)


def rng_for(seed: int, scenario: str, agent: AgentRef, stream: str) -> random.Random:
    digest = hashlib.sha256(f"{seed}|{scenario}|{agent}|{stream}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))  # noqa: S311 (simulation only)


def stable_id(seed: int, scenario: str, agent: AgentRef, n: int) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{seed}|{scenario}|{agent}|{n}"))


@dataclass(frozen=True)
class Arrival:
    n: int
    t: float  # sim seconds from scenario start
    request_id: str
    prompt: str
    tokens_hint: int


def plan_arrivals(
    seed: int, scenario: str, agent: AgentRef, profile: Profile, *, duration_s: float
) -> list[Arrival]:
    """Poisson arrivals at `profile.rps` over [0, duration_s)."""
    if profile.rps <= 0:
        return []
    timing = rng_for(seed, scenario, agent, "arrivals")
    content = rng_for(seed, scenario, agent, "content")
    out: list[Arrival] = []
    t = timing.uniform(0, 1 / profile.rps)  # jittered first call: agents never fire in lockstep
    while t < duration_s:
        n = len(out)
        topic = TOPICS[content.randrange(len(TOPICS))]
        ref = content.randrange(10_000, 99_999)
        out.append(
            Arrival(
                n,
                round(t, 3),
                stable_id(seed, scenario, agent, n),
                f"Customer {ref}: {topic}. Draft a short, polite answer.",
                content.randrange(40, 400),
            )
        )
        t += timing.expovariate(profile.rps)
    return out
