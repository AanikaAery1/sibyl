"""Load the frozen OpenAPI contract and expose its operations with the ``x-sibyl-*`` metadata.

The contract (``openapi/sibyl-api.v1.yaml``) is the single source for route-level authz, audit
and idempotency rules; handlers read them through ``guard(operation_id)`` instead of re-encoding.
Location: ``SIBYL_OPENAPI_PATH`` or the nearest ``openapi/sibyl-api.v1.yaml`` above this file.
CHANGE REQUEST (G0): ship the document inside ``sibyl-schemas`` (R70) and load it with
``importlib.resources`` so installed wheels do not depend on the repo layout.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

API_PREFIX = "/api/v1"
CONTRACT_FILE = "sibyl-api.v1.yaml"
HTTP_METHODS = ("get", "post", "put", "patch", "delete")
API_MODULES: tuple[str, ...] = (
    "auth",
    "tenancy",
    "keys",
    "registry",
    "policy",
    "credentials",
    "snapshot",
    "reads",
    "sse",
    "incidents",
    "approvals",
    "killswitch",
    "queue",
    "alerts",
    "governance",
    "action_gate",
    "ingest",
    "drift",
    "sentinel",
    "monitors",
    "findings",
)


@dataclass(frozen=True, eq=False)
class ContractOperation:
    method: str
    path: str
    mount_path: str
    surface: str  # api | root | ingest
    operation_id: str
    module: str
    scope: str
    scope_any: tuple[str, ...]
    key_scopes: tuple[str, ...]
    principals: tuple[str, ...]
    step_up: str
    object_rules: tuple[str, ...]
    audit: tuple[str, ...]
    audit_when: str
    idempotency: bool
    if_match: str
    rate_limit: str
    problems: dict[int, tuple[str, ...]]
    actions: dict[str, dict[str, Any]]
    request_schema: str | None
    path_params: tuple[dict[str, Any], ...]
    raw: dict[str, Any] = field(repr=False, compare=False)

    @property
    def route_key(self) -> str:
        return f"{self.method.upper()} {self.mount_path}"


def contract_path() -> Path:
    override = os.environ.get("SIBYL_OPENAPI_PATH")
    if override:
        return Path(override).resolve()
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "openapi" / CONTRACT_FILE
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"openapi/{CONTRACT_FILE} not found; set SIBYL_OPENAPI_PATH")


@cache
def load_document() -> dict[str, Any]:
    with contract_path().open(encoding="utf-8") as fh:
        doc: dict[str, Any] = yaml.safe_load(fh)
    return doc


def _surface(path_item: dict[str, Any]) -> str:
    servers = path_item.get("servers")
    if not servers:
        return "api"
    url = servers[0]["url"]
    return "ingest" if "ingest" in url else "root"


def _mount(surface: str, path: str) -> str:
    return API_PREFIX + path if surface == "api" else path


def _request_schema(raw: dict[str, Any]) -> str | None:
    body = raw.get("requestBody")
    if not body:
        return None
    ref = body["content"]["application/json"]["schema"].get("$ref", "")
    return ref.rsplit("/", 1)[-1] or None


def _build(method: str, path: str, surface: str, raw: dict[str, Any]) -> ContractOperation:
    audit = raw["x-sibyl-audit"]
    return ContractOperation(
        method=method,
        path=path,
        mount_path=_mount(surface, path),
        surface=surface,
        operation_id=raw["operationId"],
        module=raw["x-sibyl-module"],
        scope=raw["x-sibyl-scope"],
        scope_any=tuple(raw.get("x-sibyl-scope-any", ())),
        key_scopes=tuple(raw.get("x-sibyl-key-scopes", ())),
        principals=tuple(raw["x-sibyl-principals"]),
        step_up=raw.get("x-sibyl-step-up", "never"),
        object_rules=tuple(raw.get("x-sibyl-object-rules", ())),
        audit=() if audit == "none" else tuple(audit),
        audit_when=raw.get("x-sibyl-audit-when", "never"),
        idempotency=raw.get("x-sibyl-idempotency") == "required",
        if_match=raw.get("x-sibyl-if-match", "none"),
        rate_limit=raw.get("x-sibyl-rate-limit", "read"),
        problems={int(k): tuple(v) for k, v in raw.get("x-sibyl-problems", {}).items()},
        actions=dict(raw.get("x-sibyl-actions", {})),
        request_schema=_request_schema(raw),
        path_params=tuple(p for p in raw.get("parameters", []) if p.get("in") == "path"),
        raw=raw,
    )


@cache
def operations() -> tuple[ContractOperation, ...]:
    out: list[ContractOperation] = []
    for path, item in load_document()["paths"].items():
        surface = _surface(item)
        for method in HTTP_METHODS:
            if method in item:
                out.append(_build(method, path, surface, item[method]))
    return tuple(out)


@cache
def _by_id() -> dict[str, ContractOperation]:
    return {op.operation_id: op for op in operations()}


def operation(operation_id: str) -> ContractOperation:
    try:
        return _by_id()[operation_id]
    except KeyError:
        raise KeyError(f"operationId {operation_id!r} is not in the contract") from None
