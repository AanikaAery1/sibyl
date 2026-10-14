"""Common, tenancy, identity and API-key schemas (API.md §2, §5.1-§5.3)."""

from __future__ import annotations

from .dsl import (
    N_TS,
    N_UUID,
    REASON,
    TS,
    UUID,
    Schema,
    array,
    body_obj,
    boolean,
    free_object,
    integer,
    nullable,
    obj,
    ref,
    ro,
    string,
)

KEY_PATTERN = r"^sbl_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}$"
SLUG = string(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")


def _common() -> dict[str, Schema]:
    return {
        "Uuid": string(format="uuid"),
        "Timestamp": string(format="date-time"),
        "NullableUuid": {"type": ["string", "null"], "format": "uuid"},
        "NullableTimestamp": {"type": ["string", "null"], "format": "date-time"},
        "Sha256Hex": string(pattern=r"^[0-9a-f]{64}$"),
        "Money": string(pattern=r"^-?[0-9]+\.[0-9]{4}$", description="4-dp decimal string"),
        "Slug": SLUG,
        "Reason": string(minLength=10, maxLength=2000),
        "Problem": obj(
            {
                "type": string(format="uri", description="https://sibyl.dev/problems/<code>"),
                "title": string(),
                "status": integer(),
                "detail": string(),
                "instance": string(),
                "request_id": string(),
                "errors": array(obj({"pointer": string(), "code": string(), "message": string()})),
                "current": {"description": "Current representation on 409 stale_precondition"},
                "retry_after_s": integer(),
                "step_up_url": string(format="uri"),
            },
            ("type", "title", "status"),
        ),
        "Page": obj(
            {
                "data": array({}),
                "next_cursor": {"type": ["string", "null"]},
                "has_more": boolean(),
            },
            ("data", "next_cursor", "has_more"),
        ),
        "Job": obj(
            {
                "id": ro(UUID),
                "kind": string(),
                "state": ref("JobState"),
                "result": nullable(free_object("job result")),
                "error": {"type": ["string", "null"]},
                "attempts": integer(minimum=0),
                "requested_by": N_UUID,
                "created_at": ro(TS),
                "updated_at": ro(TS),
                "started_at": N_TS,
                "finished_at": N_TS,
            },
            ("id", "kind", "state"),
        ),
        "JobAccepted": obj({"job_id": UUID}, ("job_id",)),
        "ReasonBody": body_obj({"reason": REASON}, ("reason",)),
        "OptionalReasonBody": body_obj(
            {"reason": REASON},
            description="optional; X-Sibyl-Reason is honoured when the body has no reason",
        ),
        "ReturnTo": body_obj({"return_to": string(maxLength=2048)}),
    }


def _tenancy() -> dict[str, Schema]:
    tenant_props: dict[str, Schema] = {
        "id": ro(UUID),
        "slug": ro(SLUG),
        "name": string(maxLength=120),
        "status": ro(ref("TenantStatus")),
        "region_declared": {"type": ["string", "null"], "maxLength": 32},
        "unknown_agent_fail_mode": ref("FailMode"),
        "hold_on_incident": boolean(),
        "raw_retention_days": integer(minimum=1, maximum=30),
        "audit_retention_days": integer(minimum=400, maximum=2557),
        "backup_retention_days": integer(minimum=1, default=7),
        "routing_version": ro(integer(format="int64")),
        "graph_version": ro(integer(format="int64")),
        "limits": ro(
            obj(
                {
                    "max_agents": integer(),
                    "ingest_rate_limit": integer(),
                    "ingest_burst": integer(),
                },
            )
        ),
    }
    patch_fields = (
        "name",
        "region_declared",
        "unknown_agent_fail_mode",
        "hold_on_incident",
        "raw_retention_days",
        "audit_retention_days",
        "backup_retention_days",
    )
    return {
        "Tenant": obj(tenant_props, ("id", "slug", "name", "status", "routing_version")),
        "TenantPatch": body_obj({k: tenant_props[k] for k in patch_fields}, minProperties=1),
        "Membership": obj(
            {
                "id": ro(UUID),
                "user_id": UUID,
                "role_name": ref("RoleName"),
                "scope_kind": ref("MembershipScopeKind"),
                "scope_id": N_UUID,
                "expires_at": N_TS,
                "created_at": ro(TS),
            },
            ("id", "user_id", "role_name", "scope_kind"),
        ),
        "MembershipCreate": body_obj(
            {
                "user_id": UUID,
                "role_name": ref("RoleName"),
                "scope_kind": ref("MembershipScopeKind"),
                "scope_id": UUID,
                "expires_at": TS,
                "reason": REASON,
            },
            ("user_id", "role_name", "scope_kind", "reason"),
        ),
        "Principal": obj(
            {
                "user": ref("AppUser"),
                "tenant": ref("Tenant"),
                "memberships": array(ref("Membership")),
                "scopes": array(ref("Scope")),
                "step_up_valid_until": N_TS,
            },
            ("user", "tenant", "memberships", "scopes"),
        ),
        "Session": obj(
            {
                "id": ro(UUID),
                "user_id": UUID,
                "created_at": ro(TS),
                "last_seen_at": N_TS,
                "expires_at": TS,
                "step_up_at": N_TS,
                "ip_hash": {"type": ["string", "null"]},
                "user_agent": {"type": ["string", "null"]},
                "current": boolean(),
            },
            ("id", "user_id", "expires_at"),
        ),
        "AppUser": obj(
            {
                "id": ro(UUID),
                "email": {"type": ["string", "null"], "format": "email"},
                "display_name": {"type": ["string", "null"]},
                "status": ref("UserStatus"),
                "oidc_issuer_id": UUID,
                "last_login_at": ro(N_TS),
                "created_at": ro(TS),
            },
            ("id", "status"),
        ),
        "AppUserDetail": {
            "allOf": [
                ref("AppUser"),
                obj({"memberships": array(ref("Membership"))}),
            ]
        },
        "UserInvite": body_obj(
            {
                "email": string(format="email", maxLength=320),
                "oidc_issuer_id": UUID,
                "role_name": ref("RoleName"),
                "scope_kind": ref("MembershipScopeKind"),
                "scope_id": UUID,
            },
            ("email", "oidc_issuer_id", "role_name", "scope_kind"),
        ),
        "UserInvited": obj(
            {"user": ref("AppUser"), "membership": ref("Membership")}, ("user", "membership")
        ),
        "UserPatch": body_obj(
            {
                "status": ref("UserStatus"),
                "display_name": string(maxLength=120),
                "reason": REASON,
            },
            minProperties=1,
        ),
        "OidcIssuer": obj(
            {
                "id": ro(UUID),
                "issuer_url": string(format="uri", pattern="^https://"),
                "client_id": string(),
                "allowed_email_domains": array(string()),
                "role_claim": {"type": ["string", "null"]},
                "role_claim_map": nullable(free_object("claim value -> role_name")),
                "jit_default_role": nullable(ref("RoleName")),
                "is_active": boolean(),
                "created_at": ro(TS),
            },
            ("id", "issuer_url", "client_id", "is_active"),
            description="Never carries client_secret or client_secret_ct.",
        ),
        "OidcIssuerCreate": body_obj(
            {
                "issuer_url": string(format="uri", pattern="^https://"),
                "client_id": string(maxLength=255),
                "client_secret": string(writeOnly=True, maxLength=1024),
                "allowed_email_domains": array(string(), maxItems=64),
                "role_claim": string(),
                "role_claim_map": free_object("claim value -> role_name"),
                "jit_default_role": ref("RoleName"),
            },
            ("issuer_url", "client_id", "client_secret", "allowed_email_domains"),
        ),
        "OidcIssuerPatch": body_obj(
            {
                "client_secret": string(writeOnly=True, maxLength=1024),
                "allowed_email_domains": array(string(), maxItems=64),
                "role_claim": {"type": ["string", "null"]},
                "role_claim_map": nullable(free_object("claim value -> role_name")),
                "jit_default_role": nullable(ref("RoleName")),
                "is_active": boolean(),
            },
            minProperties=1,
        ),
        "AgentGroup": obj(
            {
                "id": ro(UUID),
                "slug": SLUG,
                "name": string(maxLength=120),
                "description": {"type": ["string", "null"]},
                "parent_group_id": N_UUID,
                "owner_user_id": N_UUID,
                "created_at": ro(TS),
            },
            ("id", "slug", "name"),
        ),
        "AgentGroupCreate": body_obj(
            {
                "slug": SLUG,
                "name": string(maxLength=120),
                "description": string(maxLength=2000),
                "parent_group_id": UUID,
                "owner_user_id": UUID,
            },
            ("slug", "name"),
        ),
        "AgentGroupPatch": body_obj(
            {
                "name": string(maxLength=120),
                "description": {"type": ["string", "null"]},
                "parent_group_id": N_UUID,
                "owner_user_id": N_UUID,
            },
            minProperties=1,
        ),
    }


def _keys() -> dict[str, Schema]:
    return {
        "ApiKey": obj(
            {
                "id": ro(UUID),
                "name": string(),
                "env": ref("ApiKeyEnv"),
                "prefix": string(minLength=12, maxLength=12),
                "scopes": array(ref("ApiKeyScope")),
                "agent_id": N_UUID,
                "monitor_id": {**N_UUID, "description": "the external monitor a key is bound to"},
                "status": ref("ApiKeyStatus"),
                "expires_at": TS,
                "last_used_at": N_TS,
                "last_used_ip_hash": {"type": ["string", "null"]},
                "rotated_from_id": N_UUID,
                "rotation_grace_until": N_TS,
                "created_by": N_UUID,
                "created_at": TS,
            },
            ("id", "name", "env", "prefix", "scopes", "status", "expires_at"),
            description="Never carries secret_hash or the secret.",
        ),
        "ApiKeyCreate": body_obj(
            {
                "name": string(minLength=1, maxLength=80),
                "env": ref("ApiKeyEnv"),
                "scopes": array(ref("ApiKeyScope"), minItems=1, uniqueItems=True),
                "agent_id": {**UUID, "description": "bound agent; omitted = tenant-level"},
                "expires_at": {**TS, "description": "default now+365 d, max now+400 d"},
            },
            ("name", "env", "scopes"),
        ),
        "ApiKeyCreated": {
            "allOf": [
                ref("ApiKey"),
                obj(
                    {
                        "secret": {
                            "type": ["string", "null"],
                            "pattern": KEY_PATTERN,
                            "description": (
                                "shown exactly once; null when an Idempotency-Key replay"
                                " re-sends the response (the secret is never stored)"
                            ),
                        }
                    },
                    ("secret",),
                ),
            ]
        },
        "TenantKey": obj(
            {
                "id": ro(UUID),
                "purpose": ref("TenantKeyPurpose"),
                "version": integer(minimum=1),
                "algorithm": string(),
                "kek_id": string(),
                "state": ref("TenantKeyState"),
                "activated_at": TS,
                "retired_at": N_TS,
                "shredded_at": N_TS,
            },
            ("id", "purpose", "version", "algorithm", "state", "activated_at"),
            description="Metadata only. wrapped_dek is never serialised.",
        ),
        "TenantKeyRotate": body_obj(
            {"reason": string(minLength=10, maxLength=500)},
            ("reason",),
        ),
        "TenantKeyRotated": obj(
            {"active": ref("TenantKey"), "retired": ref("TenantKey")},
            ("active", "retired"),
            description="The new active version and the version it retired. "
            "Retired keys still decrypt existing objects; new writes use the active version.",
        ),
        "ApiKeyRotate": body_obj(
            {
                "grace_s": integer(minimum=0, maximum=86400, default=3600),
                "scopes": array(ref("ApiKeyScope"), minItems=1, uniqueItems=True),
            }
        ),
    }


def identity_schemas() -> dict[str, Schema]:
    return {**_common(), **_tenancy(), **_keys()}
