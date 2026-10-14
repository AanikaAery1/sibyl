"""Chaos driver: scenario timeline steps -> the sim admin API (port 8300 surface) and the
harness hooks. Chaos lives at the doubles, never in the product (ML §8.1).

Agent-scoped chaos uses per-agent provider credentials: every actor sends its own
`sk-sim-<tenant>-<slug>` upstream (passed through by the gateway to the agent's primary
provider), and a scoped step becomes a double `override` matching that credential. Patches for
one credential accumulate until the double is reset, so a scenario can layer knobs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import httpx

from ..scenarios.model import AgentRef, ChaosStep


def agent_credential(ref: AgentRef) -> str:
    return f"sk-sim-{ref.tenant}-{ref.slug}"


class ChaosHooks(Protocol):
    def pause_ingest(self, tenant: str, seconds: float) -> None: ...

    def actor_set(self, ref: AgentRef, patch: dict[str, Any]) -> None: ...

    def agents_of(self, tenant: str) -> list[AgentRef]: ...


class ChaosDriver:
    def __init__(self, client: httpx.AsyncClient, hooks: ChaosHooks) -> None:
        self._client = client
        self._hooks = hooks
        self._overrides: dict[str, dict[str, dict[str, Any]]] = {}  # double -> cred -> patch

    async def apply(self, step: ChaosStep) -> dict[str, Any]:
        row: dict[str, Any] = {"t_sim": step.at, "target": f"{step.kind}:{step.target}", "ok": True}
        handler: Callable[[ChaosStep], Any] = {
            "double": self._double,
            "status": self._status,
            "ingest": self._ingest,
            "actor": self._actor,
        }[step.kind]
        try:
            await handler(step)
        except ChaosRejected as exc:
            row |= {"ok": False, "error": str(exc)}
        return row

    async def _call(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        resp = await self._client.request(method, path, json=body)
        if resp.status_code >= 300:
            raise ChaosRejected(f"{method} {path} -> {resp.status_code}: {resp.text[:200]}")
        data: dict[str, Any] = resp.json()
        return data

    async def _double(self, step: ChaosStep) -> None:
        name = step.target
        if step.reset:
            await self._call("POST", f"/_sim/doubles/{name}/reset", {})
            self._overrides.pop(name, None)
            if not step.patch:
                return
        targets = list(step.agents)
        for tenant in step.tenants:
            targets += self._hooks.agents_of(tenant)
        if not targets:
            await self._call("PATCH", f"/_sim/doubles/{name}/knobs", dict(step.patch))
            return
        table = self._overrides.setdefault(name, {})
        for ref in targets:
            table[agent_credential(ref)] = {**table.get(agent_credential(ref), {}), **step.patch}
        overrides = [
            {"match": {"credential": cred}, "knobs": patch} for cred, patch in sorted(table.items())
        ]
        await self._call("PATCH", f"/_sim/doubles/{name}/knobs", {"overrides": overrides})

    async def _status(self, step: ChaosStep) -> None:
        if step.reset:
            await self._call("POST", f"/_sim/status/{step.target}/reset", {})
        if step.patch:
            await self._call("PATCH", f"/_sim/status/{step.target}", dict(step.patch))

    async def _ingest(self, step: ChaosStep) -> None:
        self._hooks.pause_ingest(step.target, step.pause_s)

    async def _actor(self, step: ChaosStep) -> None:
        self._hooks.actor_set(AgentRef.parse(step.target), dict(step.patch))


class ChaosRejected(Exception):
    """The sim refused a knob: recorded in the timeline and fails the run's sanity check."""
