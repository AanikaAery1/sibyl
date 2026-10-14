"""Persona verbs for the Sentinel scenario (S-33), each a real API call as the Admin.

* `configure_sentinel`: `GET /sentinel/config` for its ETag, then `PUT /sentinel/config`
  (If-Match, stepped-up session, a reason) pointing the tenant's Sentinel at `sentinel-stub` on
  the doubles port. Scripted mode configures a dev-only `sk-sim-` key the stub answers itself.
  With `SIBYL_SENTINEL_EVAL=1` and `eval: true` on the step, provider, model and key come from
  `SIBYL_SENTINEL_EVAL_PROVIDER` / `_MODEL` / `_API_KEY` (optional `_PRICE_IN` / `_PRICE_OUT`
  per million tokens); the stub then forwards that tenant's calls to the vendor (proxy mode).
  The key is only ever read from the environment and sent in the PUT body; it is never logged,
  echoed or written to the run record (the API answers with a 4-character hint at most).
* `set_capture_mode`: `POST /capture-policies` for one agent (supersedes its agent-scope
  policy; the tenant policy's redaction profile and retention are reused).
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final, Protocol

import httpx

from ..doubles.sentinel_stub import EVAL_ENV, NAME, sim_key
from ..harness.world import World
from ..scenarios.model import PersonaStep

API: Final = "/api/v1"
SIM_HOST: Final = "127.0.0.1"
DEFAULT_MODEL: Final = "sentinel-sim-1"
CONSEQUENCES: Final = "2026-10"
ENV_PROVIDER: Final = "SIBYL_SENTINEL_EVAL_PROVIDER"
ENV_MODEL: Final = "SIBYL_SENTINEL_EVAL_MODEL"
ENV_KEY: Final = "SIBYL_SENTINEL_EVAL_API_KEY"  # the variable's name, not a key
ENV_PRICE_IN: Final = "SIBYL_SENTINEL_EVAL_PRICE_IN"
ENV_PRICE_OUT: Final = "SIBYL_SENTINEL_EVAL_PRICE_OUT"


class Runner(Protocol):
    client: httpx.AsyncClient
    api: str
    world: World

    def _token(self, step: PersonaStep, *, stepped_up: bool = False) -> str: ...

    async def _call(
        self, step: PersonaStep, method: str, path: str, body: Any = None, **kw: Any
    ) -> tuple[int, Any]: ...

    async def _list(self, step: PersonaStep, path: str, **params: Any) -> list[dict[str, Any]]: ...

    def _agent_id(self, step: PersonaStep) -> str | None: ...


Verb = Callable[[PersonaStep], Awaitable[tuple[int, Any]]]


def real_mode(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return env.get(EVAL_ENV) == "1"


def stub_base_url(world: World) -> str:
    return f"https://{SIM_HOST}:{world.doubles_port}/{NAME}"


def config_body(
    step: PersonaStep, world: World, env: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """The PUT body (holds the key: never log or return it)."""
    env = os.environ if env is None else env
    args = step.args
    body: dict[str, Any] = {
        "enabled": bool(args.get("enabled", True)),
        "provider": str(args.get("provider", "anthropic")),
        "model": str(args.get("model", DEFAULT_MODEL)),
        "api_key": sim_key(step.tenant),
        "base_url": stub_base_url(world),
        "daily_budget_usd": str(args.get("budget", "5")),
        "sampling_rate": float(args.get("sampling_rate", 1.0)),
        "reason": str(args.get("reason", "sibyl-sim S-33: Sentinel under evaluation")),
    }
    if args.get("tasks"):
        body["tasks"] = list(args["tasks"])
    if args.get("price_in") is not None:
        body["price_in_usd_per_mtok"] = str(args["price_in"])
        body["price_out_usd_per_mtok"] = str(args.get("price_out", args["price_in"]))
    if args.get("eval") and real_mode(env):
        missing = [n for n in (ENV_PROVIDER, ENV_MODEL, ENV_KEY) if not env.get(n)]
        if missing:
            raise RuntimeError(f"{EVAL_ENV}=1 needs {', '.join(missing)}")
        body |= {"provider": env[ENV_PROVIDER], "model": env[ENV_MODEL], "api_key": env[ENV_KEY]}
        body.pop("price_in_usd_per_mtok", None)
        body.pop("price_out_usd_per_mtok", None)
        if env.get(ENV_PRICE_IN) and env.get(ENV_PRICE_OUT):
            body["price_in_usd_per_mtok"] = env[ENV_PRICE_IN]
            body["price_out_usd_per_mtok"] = env[ENV_PRICE_OUT]
    return body


def configure_sentinel(runner: Runner) -> Verb:
    async def act(step: PersonaStep) -> tuple[int, Any]:
        try:
            body = config_body(step, runner.world)
        except RuntimeError as exc:
            return 400, {"type": "about:blank/eval_env", "detail": str(exc)}
        current = await runner.client.get(
            f"{runner.api}{API}/sentinel/config",
            headers={"Authorization": f"Bearer {runner._token(step)}"},
        )
        etag = current.headers.get("etag") or '"0"'
        status, data = await runner._call(
            step, "PUT", "/sentinel/config", body, stepped_up=True, headers={"If-Match": etag}
        )
        del body  # holds the key
        return status, _without_key(data)

    return act


def _without_key(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if k != "api_key"}
    return data


def set_capture_mode(runner: Runner) -> Verb:
    async def act(step: PersonaStep) -> tuple[int, Any]:
        agent = runner._agent_id(step)
        tenant_policy = await runner._list(step, "/capture-policies", scope_kind="tenant")
        if not tenant_policy or agent is None:
            return 404, {"detail": "no tenant capture policy or no agent"}
        base = tenant_policy[0]
        current = await runner._list(step, "/capture-policies", scope_kind="agent", agent_id=agent)
        etag = f'"{current[0]["version_no"]}"' if current else "*"
        body = {
            "scope_kind": "agent",
            "agent_id": agent,
            "capture_mode": str(step.args.get("mode", "metadata")),
            "redaction_profile_id": base["redaction_profile_id"],
            "payload_retention_days": int(base.get("payload_retention_days") or 30),
            "consequences_version": str(base.get("consequences_version") or CONSEQUENCES),
            "acknowledged": True,
            "reason": str(step.args.get("reason", "sibyl-sim S-33: capture mode under test")),
        }
        return await runner._call(
            step, "POST", "/capture-policies", body, headers={"If-Match": etag}
        )

    return act


__all__ = ["config_body", "configure_sentinel", "real_mode", "set_capture_mode", "stub_base_url"]
