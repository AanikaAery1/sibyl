"""Render the route table into the OpenAPI 3.1 document."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

import yaml
from sibyl_schemas import CONTRACT_TAG

from .dsl import UUID, ActionRule, Op, Q, Schema, integer, ref, string
from .enums import enum_schemas
from .params import PATH_PARAM_SCHEMAS
from .routes_action_gate import ACTION_GATE_OPS
from .routes_drift import DRIFT_OPS
from .routes_gov import GOV_OPS
from .routes_identity import IDENTITY_OPS
from .routes_monitors import FINDING_OPS, MONITOR_OPS, MONITOR_READ, MONITOR_READ_OPS
from .routes_ops import OPS_OPS
from .routes_registry import REGISTRY_OPS
from .routes_sentinel import SENTINEL_OPS
from .schemas_action_gate import action_gate_schemas
from .schemas_drift import drift_schemas
from .schemas_identity import identity_schemas
from .schemas_monitors import monitor_schemas
from .schemas_ops import ops_schemas
from .schemas_registry import registry_schemas
from .schemas_sentinel import sentinel_schemas

CONTRACT_VERSION = CONTRACT_TAG.removeprefix("contracts-v")  # G0-9: 1.1.0, frozen at M0


def _monitor_readable(op: Op) -> Op:
    """D53: a ``monitor:read`` key may call this read route (metadata, watched groups only)."""
    if op.op_id not in MONITOR_READ_OPS:
        return op
    rules = op.rules if "group" in op.rules else ("group", *op.rules)
    return replace(
        op,
        scope_any=(*op.scope_any, MONITOR_READ),
        key_scopes=(*op.key_scopes, MONITOR_READ),
        rules=rules,
    )


ALL_OPS: tuple[Op, ...] = tuple(
    _monitor_readable(op)
    for op in IDENTITY_OPS
    + REGISTRY_OPS
    + OPS_OPS
    + GOV_OPS
    + ACTION_GATE_OPS
    + DRIFT_OPS
    + SENTINEL_OPS
    + MONITOR_OPS
    + FINDING_OPS
)

MODULES: tuple[str, ...] = (
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
    "drift",  # D51 (wave 3 lane DRIFT)
    "sentinel",
    "monitors",  # D53 (wave 4 lane EXTMON)
    "findings",
)

SERVERS: dict[str, list[dict[str, Any]]] = {
    "api": [
        {
            "url": "https://{host}/api/v1",
            "description": "Control plane",
            "variables": {"host": {"default": "sibyl.local"}},
        }
    ],
    "root": [
        {
            "url": "https://{host}",
            "description": "Control plane host root",
            "variables": {"host": {"default": "sibyl.local"}},
        }
    ],
    "ingest": [
        {
            "url": "https://{ingest_host}",
            "description": "Ingest",
            "variables": {"ingest_host": {"default": "ingest.sibyl.local"}},
        }
    ],
}

DEFAULT_PROBLEMS: dict[int, tuple[str, ...]] = {
    400: ("invalid_cursor", "cursor_filter_mismatch"),
    401: ("unauthenticated",),
    403: ("forbidden",),
    404: ("not_found",),
    409: ("idempotency_in_progress", "idempotent_replay_unavailable"),
    412: ("precondition_failed",),
    422: ("validation_failed",),
    428: (),
    429: ("rate_limited",),
}

_PARAM_RE = re.compile(r"{([a-z_]+)}")


def _principals(op: Op) -> list[str]:
    if op.scope == "public":
        return ["anonymous"]
    if op.key_only:
        return ["api_key"]
    humans = ["session", "oidc"]
    return [*humans, "api_key"] if op.key_scopes else humans


def _security(op: Op) -> list[dict[str, list[str]]]:
    principals = _principals(op)
    if principals == ["anonymous"]:
        return []
    out: list[dict[str, list[str]]] = []
    if "session" in principals:
        out += [{"session": []}, {"oidc": []}]
    if "api_key" in principals:
        out.append({"apiKey": list(op.key_scopes)})
    return out


def _problems(op: Op) -> dict[int, list[str]]:
    statuses: set[int] = {429}
    if op.scope != "public":
        statuses |= {401, 403}
    if _PARAM_RE.search(op.path):
        statuses.add(404)
    if op.body or op.query or op.paged:
        statuses.add(422)
    if op.paged:
        statuses.add(400)
    if op.idem:
        statuses |= {409, 422, 428}
    if op.if_match:
        statuses |= {412, 428}
    statuses |= set(op.problems)
    out: dict[int, list[str]] = {}
    for status in sorted(statuses):
        codes = list(DEFAULT_PROBLEMS.get(status, ()))
        if status == 400 and not op.paged:
            codes = []
        if status == 403 and op.step_up:
            codes.append("step_up_required")
        if status == 403 and op.scope != "public" and not op.key_only:
            codes.append("break_glass_key_misuse")
        if status == 409 and not op.idem:
            codes = []
        if status == 422 and op.idem:
            codes.append("idempotency_key_reuse")
        if status == 428:
            codes += ["idempotency_key_required"] if op.idem else []
            codes += ["precondition_required"] if op.if_match else []
        if status == 412 and not op.if_match:
            codes = []
        for code in op.problems.get(status, ()):
            if code not in codes:
                codes.append(code)
        if codes:
            out[status] = codes
    return out


def _param(q: Q) -> dict[str, Any]:
    out: dict[str, Any] = {"name": q.name, "in": q.location, "schema": q.schema}
    if q.required:
        out["required"] = True
    if q.description:
        out["description"] = q.description
    if q.location == "query" and q.schema.get("type") == "array":
        out.update({"style": "form", "explode": False})
    return out


def _parameters(op: Op) -> list[dict[str, Any]]:
    params: list[dict[str, Any]] = []
    for name in _PARAM_RE.findall(op.path):
        schema = PATH_PARAM_SCHEMAS.get(name, UUID)
        params.append({"name": name, "in": "path", "required": True, "schema": schema})
    if op.paged:
        params += [
            {"$ref": "#/components/parameters/Limit"},
            {"$ref": "#/components/parameters/Cursor"},
        ]
    params += [_param(q) for q in op.query]
    if op.idem:
        params.append({"$ref": "#/components/parameters/IdempotencyKey"})
    if op.if_match:
        params.append({"$ref": "#/components/parameters/IfMatch"})
    return params


def _hdr(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/headers/{name}"}


def _ok_response(op: Op, status: int, schema_name: str | None, desc: str) -> dict[str, Any]:
    resp: dict[str, Any] = {"description": desc}
    headers: dict[str, Any] = {"X-Request-Id": _hdr("RequestId")}
    if status in (302,):
        headers["Location"] = _hdr("Location")
    if op.etag_out and status in (200, 201):
        headers["ETag"] = _hdr("ETag")
    if op.audit and op.audit_when != "worker" and 200 <= status < 300:
        headers["X-Sibyl-Audit-Receipt"] = _hdr("AuditReceipt")
    if op.idem and 200 <= status < 300:
        headers["Idempotency-Replayed"] = _hdr("IdempotencyReplayed")
    if op.paged:
        headers["Link"] = _hdr("Link")
    if status in (200, 304):
        for header, component in op.ok_headers:
            headers[header] = _hdr(component)
    resp["headers"] = headers
    if status in (204, 302, 304):
        return resp
    if op.content == "text/event-stream":
        resp["content"] = {"text/event-stream": {"schema": string()}}
    elif op.content == "application/octet-stream":
        resp["content"] = {"*/*": {"schema": string(contentMediaType="application/octet-stream")}}
    elif schema_name:
        body: Schema = ref(schema_name)
        if op.paged:
            data = {"type": "array", "items": ref(schema_name)}
            props: dict[str, Any] = {"data": data, **dict(op.page_extra)}
            body = {"allOf": [ref("Page"), {"type": "object", "properties": props}]}
        resp["content"] = {"application/json": {"schema": body}}
    return resp


def _responses(op: Op) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for status, schema_name, desc in op.ok:
        out[str(status)] = _ok_response(op, status, schema_name, desc)
    for status in _problems(op):
        out[str(status)] = {"$ref": "#/components/responses/Problem"}
    return out


def _action_ext(rule: ActionRule) -> dict[str, Any]:
    out: dict[str, Any] = {"scope": rule.scope, "audit": list(rule.audit)}
    if rule.scope_any:
        out["scope_any"] = list(rule.scope_any)
    out["step_up"] = rule.step_up or "never"
    if rule.rules:
        out["object_rules"] = list(rule.rules)
    if rule.note:
        out["note"] = rule.note
    return out


def _description(op: Op) -> str:
    parts = [op.description] if op.description else []
    if op.step_up_note:
        parts.append(f"Step-up: {op.step_up_note}.")
    if op.audit_note:
        parts.append(f"Audit: {op.audit_note}.")
    return " ".join(parts)


def operation(op: Op) -> dict[str, Any]:
    rate = op.rate or ("read" if op.method == "get" else "mutation")
    doc: dict[str, Any] = {
        "operationId": op.op_id,
        "summary": op.summary,
        "tags": [op.module],
        "x-sibyl-module": op.module,
        "x-sibyl-scope": op.scope,
        "x-sibyl-audit": list(op.audit) if op.audit else "none",
        "x-sibyl-audit-when": op.audit_when if op.audit else "never",
        "x-sibyl-principals": _principals(op),
        "x-sibyl-key-scopes": list(op.key_scopes),
        "x-sibyl-step-up": op.step_up or "never",
        "x-sibyl-object-rules": list(op.rules),
        "x-sibyl-idempotency": "required" if op.idem else "none",
        "x-sibyl-if-match": op.if_match or "none",
        "x-sibyl-rate-limit": rate,
        "x-sibyl-problems": {str(k): v for k, v in _problems(op).items()},
    }
    if op.scope_any:
        doc["x-sibyl-scope-any"] = list(op.scope_any)
    if op.per_action:
        doc["x-sibyl-actions"] = {k: _action_ext(v) for k, v in op.per_action.items()}
    desc = _description(op)
    if desc:
        doc["description"] = desc
    doc["security"] = _security(op)
    params = _parameters(op)
    if params:
        doc["parameters"] = params
    if op.body:
        doc["requestBody"] = {
            "required": op.body_required,
            "content": {"application/json": {"schema": ref(op.body)}},
        }
    doc["responses"] = _responses(op)
    return doc


REASONED_BODIES: tuple[str, ...] = (
    "TenantPatch",
    "UserInvite",
    "OidcIssuerCreate",
    "OidcIssuerPatch",
    "AgentGroupCreate",
    "AgentGroupPatch",
    "ApiKeyCreate",
    "ApiKeyRotate",
    "ToolCreate",
    "ToolPatch",
    "DataSourceCreate",
    "DataSourcePatch",
    "BusinessProcessCreate",
    "BusinessProcessPatch",
    "ProviderCreate",
    "ProviderPatch",
    "ModelCreate",
    "ModelPatch",
    "ProviderCredentialCreate",
    "ProviderCredentialRotate",
    "CapturePolicyCreate",
    "FallbackChainCreate",
    "FallbackChainPut",
    "AlertRuleCreate",
    "AlertRulePatch",
)
"""Audited human writes that take an optional ``reason`` (the operator's own words in the audit
chain); ``X-Sibyl-Reason`` (>= 10 chars) is honoured when the body has none."""


def _with_reason(schemas: dict[str, Schema]) -> dict[str, Schema]:
    out = dict(schemas)
    for name in REASONED_BODIES:
        body = out[name]
        if "reason" in body["properties"]:
            raise ValueError(f"{name} already declares reason")
        out[name] = {**body, "properties": {**body["properties"], "reason": ref("Reason")}}
    return out


def _components() -> dict[str, Any]:
    schemas = _with_reason(
        {
            **identity_schemas(),
            **enum_schemas(),
            **registry_schemas(),
            **ops_schemas(),
            **action_gate_schemas(),
            **drift_schemas(),
            **sentinel_schemas(),
            **monitor_schemas(),
        }
    )
    return {
        "securitySchemes": {
            "session": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "sibyl_sess_<value> (console BFF, server-to-server)",
            },
            "oidc": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT (aud=sibyl-api)"},
            "apiKey": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "sbl_<env>_<prefix12>_<secret>",
            },
        },
        "parameters": {
            "Limit": {
                "name": "limit",
                "in": "query",
                "schema": integer(minimum=1, maximum=200, default=50),
            },
            "Cursor": {"name": "cursor", "in": "query", "schema": string(maxLength=1024)},
            "IdempotencyKey": {
                "name": "Idempotency-Key",
                "in": "header",
                "required": True,
                "schema": string(minLength=1, maxLength=128),
            },
            "IfMatch": {"name": "If-Match", "in": "header", "required": True, "schema": string()},
        },
        "headers": {
            "ETag": {"schema": string(), "description": "Strong validator"},
            "AuditReceipt": {
                "schema": string(pattern=r"^[0-9a-f-]{36}:\d+:[0-9a-f]{64}$"),
                "description": "<tenant>:<seq>:<hash>",
            },
            "IdempotencyReplayed": {"schema": string(enum=["true"])},
            "Link": {"schema": string(), "description": '<…>; rel="next"'},
            "Location": {"schema": string(format="uri")},
            "RequestId": {"schema": string(maxLength=128)},
            "RateLimit": {"schema": string()},
            "RateLimitPolicy": {"schema": string()},
            "RetryAfter": {"schema": integer(minimum=0)},
            "SnapshotKid": {
                "schema": string(pattern=r"^[A-Za-z0-9._-]{1,64}$"),
                "description": "kid of the signing key (verify against the accepted key set)",
            },
            "SnapshotSignature": {
                "schema": string(pattern=r"^[A-Za-z0-9_-]{86}$"),
                "description": "base64url Ed25519 signature over the raw response bytes (B4)",
            },
            "SnapshotVersion": {
                "schema": string(pattern=r"^[0-9]{1,19}$"),
                "description": "policy_snapshot_issue version of this snapshot (also the ETag)",
            },
        },
        "responses": {
            "Problem": {
                "description": "RFC 9457 problem details",
                "headers": {
                    "RateLimit": _hdr("RateLimit"),
                    "RateLimit-Policy": _hdr("RateLimitPolicy"),
                    "Retry-After": _hdr("RetryAfter"),
                },
                "content": {"application/problem+json": {"schema": ref("Problem")}},
            }
        },
        "schemas": dict(sorted(schemas.items())),
    }


def build_document() -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for op in ALL_OPS:
        item = paths.setdefault(op.path, {})
        if op.server != "api":
            item["servers"] = SERVERS[op.server]
        if op.method in item:
            raise ValueError(f"duplicate operation {op.method} {op.path}")
        item[op.method] = operation(op)
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Sibyl Control Plane API",
            "version": f"{CONTRACT_VERSION}-phase1",
            "description": (
                "Tenant-scoped REST + SSE, ingest and gateway control routes. Errors are RFC 9457"
                " problem details (https://sibyl.dev/problems/<code>). Generated from"
                " openapi/sibyl_openapi; do not edit by hand."
            ),
        },
        "x-sibyl-contract-version": CONTRACT_VERSION,
        "servers": SERVERS["api"],
        "tags": [{"name": m} for m in MODULES],
        "paths": paths,
        "components": _components(),
    }


def render_yaml() -> str:
    return yaml.safe_dump(build_document(), sort_keys=False, allow_unicode=True, width=100)
