"""Shared building blocks of the contract scenarios: the request a scenario returns and the
helpers every lane's scenarios use to build real tenant-A objects on the ``contract_world``."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from .pg_world import ContractWorld

REASON = "contract scenario: exercised by the generated suites"


@dataclass
class Req:
    path: str
    body: Any = None
    params: dict[str, Any] = field(default_factory=dict)
    if_match: str | None = None
    agent_id: str | None = None  # the agent the request is about (object-rule cases)
    who: str | None = None  # who must make the request (default: owner / keys)
    headers: dict[str, str] = field(default_factory=dict)


Scenario = Callable[[ContractWorld], Req]


def unique(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def _api(w: ContractWorld, method: str, path: str, body: Any = None, **headers: str) -> Any:
    resp = w.client.request(method, "/api/v1" + path, json=body, headers=w.idem("owner", **headers))
    assert resp.status_code < 300, (path, resp.text)
    return resp


def _etag(w: ContractWorld, path: str) -> str:
    resp = w.client.get("/api/v1" + path, headers=w.headers("owner"))
    assert resp.status_code == 200, (path, resp.text)
    return str(resp.headers["etag"])


def provider(w: ContractWorld) -> UUID:
    pid = uuid4()
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect, base_url,"
        " is_known_provider) VALUES ($1, $2, $3, $3, 'openai', 'openai_compatible',"
        " 'https://api.openai.com/v1', true)",
        w.a.id,
        pid,
        unique("prov"),
    )
    return pid


def model(w: ContractWorld, provider_id: UUID | None = None) -> UUID:
    mid = uuid4()
    w.admin.in_tenant(
        w.a.id,
        "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1, $2, $3, $4)",
        w.a.id,
        mid,
        provider_id or provider(w),
        unique("model"),
    )
    return mid


def agent(w: ContractWorld, **fields: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "slug": unique("agent"),
        "name": "Billing agent",
        "kind": "autonomous_agent",
        "fail_mode": "closed",
        "tier": 3,
    }
    body.update(fields)
    resp = _api(w, "POST", "/agents", body)
    assert resp.status_code == 201, resp.text
    created: dict[str, Any] = resp.json()
    return created


def _with_agent(build: Callable[[ContractWorld, dict[str, Any]], Req]) -> Scenario:
    def scenario(w: ContractWorld) -> Req:
        created = agent(w)
        req = build(w, created)
        req.agent_id = created["id"]
        return req

    return scenario
