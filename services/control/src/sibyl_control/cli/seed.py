"""``sibyl seed``: idempotent demo data (D29, R55, R56, ruling B3).

* ``meridian``: 20 synthetic agents in three groups across three providers (``openai-stub``,
  ``anthropic-stub``, ``ollama-stub``, all pointing at the ``sibyl-sim`` doubles), tiers 1-3,
  continuity plans, approved fallback chains (alt-model, alt-provider with a vaulted credential,
  backup agent, human queue), tools, data sources, business processes and dependency edges.
* ``northstar``: 3 agents (the isolation proof).
* ``sandbox``: empty (only the Platform Admin, B3).

Tenants come from ``sibyl.tenant_create()`` (DEKs wrapped under ``SIBYL_KEK``); personas, their
memberships and agent groups are inserted directly (lane A owns those routes). Everything else
goes through the real api handlers in-process, acting as the Platform Admin (``owner``) or the
On-call Operator (``security_admin``, the tier-1 four-eyes approver), so validation, audit rows,
idempotency and outbox rows are exactly what an API client would produce. Every write is preceded
by an existence check, so a second run writes nothing.

Tier-1 agents stay ``proposed``: leaving it needs an agent-bound API key (R35), which the
quickstart mints (lane A); the report lists them.

The sim doubles are development hosts: ``base_url_dev_host`` (writable only by
``sibyl_migrate``) must list the sim host. With ``--migrate-dsn`` the seed inserts it; otherwise
run once as the migrate role: ``INSERT INTO sibyl.base_url_dev_host (host, note)
VALUES ('sim', 'sibyl-sim doubles') ON CONFLICT DO NOTHING``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx

from ..api.app import create_app
from ..api.deps import Services, StaticTokenResolver
from ..core.authz import MembershipGrant, Principal, PrincipalKind, grants_from_memberships
from ..core.crypto.deks import kek_from_settings, new_wrapped_dek
from ..core.crypto.envelope import PURPOSES, KeyEncryptionKey
from ..core.db import Database
from ..core.idempotency import PgIdempotencyStore
from ..core.ratelimit import RateDecision, RatePolicy
from ..core.settings import Settings

API = "/api/v1"
SEED_REASON = "sibyl seed: demo data (D29)"
DEFAULT_SIM_HOST = "sim"  # compose network alias; in the sim TLS certificate
# The simulator serves every double on one TLS port, addressed by path: /{double}/v1/*.
DEFAULT_SIM_PORTS = {"openai-stub": 18082, "anthropic-stub": 18082, "ollama-stub": 18082}


# --- the demo world -------------------------------------------------------------------------


@dataclass(frozen=True)
class Persona:
    username: str
    email: str
    subject: str
    display_name: str


PERSONAS = {
    "admin": Persona(
        "admin",
        "admin@demo.sibyl.example",
        "0192a000-0000-7000-8000-00000000d001",
        "Platform Admin",
    ),
    "operator": Persona(
        "operator",
        "operator@demo.sibyl.example",
        "0192a000-0000-7000-8000-00000000d002",
        "On-call Operator",
    ),
    "auditor": Persona(
        "auditor",
        "auditor@demo.sibyl.example",
        "0192a000-0000-7000-8000-00000000d003",
        "Compliance Auditor",
    ),
}

# R56 bindings; B3: the On-call Operator only in meridian and northstar, sandbox holds the
# Platform Admin alone.
BINDINGS: dict[str, dict[str, tuple[str, ...]]] = {
    "meridian": {
        "admin": ("owner",),
        "operator": ("operator", "security_admin"),
        "auditor": ("auditor",),
    },
    "northstar": {
        "admin": ("owner",),
        "operator": ("operator", "security_admin"),
        "auditor": ("auditor",),
    },
    "sandbox": {"admin": ("owner",)},
}


@dataclass(frozen=True)
class ProviderSpec:
    slug: str
    name: str
    kind: str
    models: tuple[str, ...]


@dataclass(frozen=True)
class AgentSpec:
    slug: str
    name: str
    kind: str
    tier: int
    group: str
    provider: str
    process: str
    fail_mode: str = "closed"
    risk: str = "limited"
    reads: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    delegates: tuple[str, ...] = ()
    backup: str | None = None


@dataclass(frozen=True)
class TenantSpec:
    slug: str
    name: str
    groups: tuple[tuple[str, str], ...] = ()
    processes: tuple[tuple[str, str, str], ...] = ()
    providers: tuple[ProviderSpec, ...] = ()
    tools: tuple[tuple[str, str, str], ...] = ()
    data_sources: tuple[tuple[str, str, str, str], ...] = ()
    agents: tuple[AgentSpec, ...] = ()


STUBS = (
    ProviderSpec("openai-stub", "OpenAI (sim double)", "openai", ("gpt-5.4", "gpt-5-mini")),
    ProviderSpec(
        "anthropic-stub",
        "Anthropic (sim double)",
        "anthropic",
        ("claude-sonnet-5", "claude-haiku-5"),
    ),
    ProviderSpec("ollama-stub", "Ollama (sim double)", "ollama", ("llama-4-70b", "qwen3-32b")),
)

# USD per 1M (input, output) tokens on each stub model's tenant row. Ingest prices every call
# from these (no catalogue row exists for the stub names), so month-to-date spend, R5
# budget_breach and L4 budget_proximity have something to read (S-05, S-06). Illustrative list
# prices of each provider's matching tier: flagship ~2.50-3 in / 15 out, small 0.25-1 in / 2-5
# out. The Ollama models are self-hosted: no per-token bill, priced at zero rather than left
# unpriced.
MODEL_PRICES: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        "gpt-5.4": ("2.5000", "15.0000"),
        "gpt-5-mini": ("0.2500", "2.0000"),
        "claude-sonnet-5": ("3.0000", "15.0000"),
        "claude-haiku-5": ("1.0000", "5.0000"),
        "llama-4-70b": ("0.0000", "0.0000"),
        "qwen3-32b": ("0.0000", "0.0000"),
    }
)


def _a(
    slug: str, name: str, kind: str, tier: int, group: str, provider: str, process: str, **kw: Any
) -> AgentSpec:
    return AgentSpec(slug, name, kind, tier, group, provider, process, **kw)


MERIDIAN = TenantSpec(
    "meridian",
    "Meridian Logistics",
    groups=(
        ("payments", "Payments"),
        ("support", "Customer support"),
        ("operations", "Fleet operations"),
    ),
    processes=(
        ("order-to-cash", "Order to cash", "critical"),
        ("customer-care", "Customer care", "high"),
        ("fleet-dispatch", "Fleet dispatch", "medium"),
    ),
    providers=STUBS,
    tools=(
        ("invoice-api", "Invoice API", "http_api"),
        ("refund-api", "Refund API", "http_api"),
        ("route-planner", "Route planner", "function"),
        ("kb-search", "KB search", "retrieval"),
    ),
    data_sources=(
        ("crm", "CRM", "database", "pii"),
        ("ledger", "General ledger", "database", "restricted"),
        ("kb", "Knowledge base", "vector_index", "internal"),
    ),
    agents=(
        _a(
            "billing-agent",
            "Billing agent",
            "autonomous_agent",
            1,
            "payments",
            "openai-stub",
            "order-to-cash",
            reads=("ledger",),
            tools=("invoice-api",),
            risk="high",
        ),
        _a(
            "refund-agent",
            "Refund agent",
            "autonomous_agent",
            1,
            "payments",
            "anthropic-stub",
            "order-to-cash",
            reads=("ledger", "crm"),
            tools=("refund-api",),
            risk="high",
        ),
        _a(
            "quote-assistant",
            "Quote assistant",
            "copilot",
            1,
            "payments",
            "openai-stub",
            "order-to-cash",
            tools=("invoice-api",),
            risk="high",
        ),
        _a(
            "dispatch-planner",
            "Dispatch planner",
            "autonomous_agent",
            1,
            "operations",
            "openai-stub",
            "fleet-dispatch",
            tools=("route-planner",),
            risk="high",
        ),
        _a(
            "collections-bot",
            "Collections bot",
            "chatbot",
            2,
            "payments",
            "anthropic-stub",
            "order-to-cash",
            reads=("crm",),
            backup="quote-assistant",
        ),
        _a(
            "invoice-reader",
            "Invoice reader",
            "rag_pipeline",
            2,
            "payments",
            "ollama-stub",
            "order-to-cash",
            reads=("ledger",),
            backup="billing-agent",
        ),
        _a(
            "support-triage",
            "Support triage",
            "chatbot",
            2,
            "support",
            "openai-stub",
            "customer-care",
            reads=("crm", "kb"),
            tools=("kb-search",),
            delegates=("returns-agent", "faq-bot"),
            backup="faq-bot",
        ),
        _a(
            "returns-agent",
            "Returns agent",
            "autonomous_agent",
            2,
            "support",
            "anthropic-stub",
            "customer-care",
            reads=("crm",),
            tools=("refund-api",),
            backup="support-triage",
        ),
        _a(
            "escalation-router",
            "Escalation router",
            "workflow",
            2,
            "support",
            "openai-stub",
            "customer-care",
            delegates=("support-triage",),
            backup="faq-bot",
        ),
        _a(
            "eta-predictor",
            "ETA predictor",
            "model_endpoint",
            2,
            "operations",
            "ollama-stub",
            "fleet-dispatch",
            backup="route-optimizer",
            fail_mode="open",
        ),
        _a(
            "route-optimizer",
            "Route optimizer",
            "autonomous_agent",
            2,
            "operations",
            "openai-stub",
            "fleet-dispatch",
            tools=("route-planner",),
            backup="eta-predictor",
        ),
        _a(
            "driver-assistant",
            "Driver assistant",
            "copilot",
            2,
            "operations",
            "anthropic-stub",
            "fleet-dispatch",
            tools=("route-planner",),
            backup="dispatch-planner",
        ),
        _a(
            "faq-bot",
            "FAQ bot",
            "chatbot",
            3,
            "support",
            "ollama-stub",
            "customer-care",
            reads=("kb",),
            tools=("kb-search",),
            fail_mode="open",
            risk="minimal",
        ),
        _a(
            "kb-summarizer",
            "KB summarizer",
            "rag_pipeline",
            3,
            "support",
            "openai-stub",
            "customer-care",
            reads=("kb",),
            fail_mode="open",
            risk="minimal",
        ),
        _a(
            "sentiment-tagger",
            "Sentiment tagger",
            "model_endpoint",
            3,
            "support",
            "ollama-stub",
            "customer-care",
            fail_mode="open",
            risk="minimal",
        ),
        _a(
            "email-drafter",
            "Email drafter",
            "copilot",
            3,
            "support",
            "anthropic-stub",
            "customer-care",
            reads=("crm",),
            fail_mode="open",
        ),
        _a(
            "receipt-ocr",
            "Receipt OCR",
            "model_endpoint",
            3,
            "payments",
            "openai-stub",
            "order-to-cash",
            fail_mode="open",
            risk="minimal",
        ),
        _a(
            "spend-reporter",
            "Spend reporter",
            "workflow",
            3,
            "payments",
            "ollama-stub",
            "order-to-cash",
            reads=("ledger",),
            fail_mode="open",
        ),
        _a(
            "fuel-analyst",
            "Fuel analyst",
            "rag_pipeline",
            3,
            "operations",
            "anthropic-stub",
            "fleet-dispatch",
            fail_mode="open",
            risk="minimal",
        ),
        _a(
            "shift-scheduler",
            "Shift scheduler",
            "workflow",
            3,
            "operations",
            "openai-stub",
            "fleet-dispatch",
            delegates=("route-optimizer",),
            fail_mode="open",
        ),
    ),
)

NORTHSTAR = TenantSpec(
    "northstar",
    "Northstar Health",
    groups=(("clinical", "Clinical operations"),),
    processes=(("patient-intake", "Patient intake", "high"),),
    providers=(STUBS[0], STUBS[2]),
    data_sources=(("ehr", "EHR", "database", "pii"),),
    agents=(
        _a(
            "intake-assistant",
            "Intake assistant",
            "chatbot",
            2,
            "clinical",
            "openai-stub",
            "patient-intake",
            reads=("ehr",),
            backup="scheduling-bot",
        ),
        _a(
            "scheduling-bot",
            "Scheduling bot",
            "chatbot",
            3,
            "clinical",
            "ollama-stub",
            "patient-intake",
            fail_mode="open",
        ),
        _a(
            "claims-coder",
            "Claims coder",
            "autonomous_agent",
            3,
            "clinical",
            "openai-stub",
            "patient-intake",
            reads=("ehr",),
        ),
    ),
)

SANDBOX = TenantSpec("sandbox", "Sandbox")
WORLD: tuple[TenantSpec, ...] = (MERIDIAN, NORTHSTAR, SANDBOX)


# --- plumbing -------------------------------------------------------------------------------


class _Unlimited:
    """The seed is a trusted operator tool: no rate limits on its in-process calls."""

    def _ok(self, policy: RatePolicy) -> RateDecision:
        return RateDecision(True, policy, policy.quota, 0, 0)

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        return self._ok(policy)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        return self._ok(policy)


class SeedError(RuntimeError):
    pass


@dataclass
class Report:
    created: dict[str, int] = field(default_factory=dict)
    awaiting_bound_key: list[str] = field(default_factory=list)

    def add(self, kind: str, n: int = 1) -> None:
        self.created[kind] = self.created.get(kind, 0) + n

    @property
    def total(self) -> int:
        return sum(self.created.values())


@dataclass(frozen=True)
class Options:
    sim_host: str = DEFAULT_SIM_HOST
    sim_ports: tuple[tuple[str, int], ...] = tuple(DEFAULT_SIM_PORTS.items())
    issuer_url: str = "https://localhost:8443/dex"
    client_id: str = "sibyl-console"

    def base_url(self, provider: str) -> str:
        return f"https://{self.sim_host}:{dict(self.sim_ports)[provider]}/{provider}/v1"

    def status_feed_url(self, provider: str) -> str:
        """The simulator's Statuspage-v2 feed for this double (read-only copy on the TLS port)."""
        feed = provider.split("-", 1)[0]  # openai-stub -> openai
        port = dict(self.sim_ports)[provider]
        return f"https://{self.sim_host}:{port}/status/{feed}/api/v2/summary.json"


class Api:
    """In-process client for the real handlers, acting as one persona at a time."""

    def __init__(self, client: httpx.AsyncClient, resolver: StaticTokenResolver) -> None:
        self.client = client
        self.resolver = resolver

    def act_as(self, token: str, tenant_id: UUID, user_id: UUID, roles: tuple[str, ...]) -> None:
        # The seed is run by an operator holding the database credentials; it acts with a
        # fresh step-up so credential creation (step-up always) goes through the real route.
        self.resolver.add(
            token,
            Principal(
                PrincipalKind.SESSION,
                tenant_id,
                user_id,
                grants_from_memberships(MembershipGrant(r) for r in roles),
                step_up_at=datetime.now(UTC) + timedelta(hours=1),
                roles=frozenset(roles),
            ),
        )

    async def call(
        self, token: str, method: str, path: str, body: Any = None, **headers: str
    ) -> dict[str, Any]:
        sent = {"Authorization": f"Bearer {token}", "Idempotency-Key": str(uuid4()), **headers}
        resp = await self.client.request(method, API + path, json=body, headers=sent)
        if resp.status_code >= 300:
            raise SeedError(f"{method} {path} -> {resp.status_code}: {resp.text[:400]}")
        data: dict[str, Any] = resp.json()
        data["_etag"] = resp.headers.get("etag")
        return data


# --- tenant and identity phase (direct SQL, lane A routes) -----------------------------------


async def _tenant(conn: Any, kek: KeyEncryptionKey, spec: TenantSpec, report: Report) -> UUID:
    existing = await conn.fetchval("SELECT id FROM sibyl.tenant WHERE slug = $1", spec.slug)
    if existing is not None:
        return UUID(str(existing))
    tenant_id = uuid4()
    deks = [new_wrapped_dek(kek, tenant_id, purpose, 1).wrapped for purpose in PURPOSES]
    async with conn.transaction():
        await conn.fetchval(
            "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', $3, $4, $5, $6, NULL, $7)",
            spec.slug,
            spec.name,
            kek.kek_id,
            *deks,
            tenant_id,
        )
    report.add("tenant")
    return tenant_id


async def _in_tenant(conn: Any, tenant_id: UUID, sql: str, *args: Any) -> Any:
    async with conn.transaction():
        await conn.execute("SELECT sibyl.set_tenant($1)", tenant_id)
        return await conn.fetchval(sql, *args)


async def _identities(
    conn: Any, tenant_id: UUID, spec: TenantSpec, opts: Options, report: Report
) -> tuple[dict[str, UUID], dict[str, UUID]]:
    """Issuer, persona users, memberships (R56/B3) and agent groups; returns users and groups."""
    issuer = await _in_tenant(
        conn, tenant_id, "SELECT id FROM sibyl.oidc_issuer WHERE issuer_url = $1", opts.issuer_url
    )
    if issuer is None:
        issuer = await _in_tenant(
            conn,
            tenant_id,
            "INSERT INTO sibyl.oidc_issuer (tenant_id, issuer_url, client_id) VALUES ($1, $2, $3)"
            " RETURNING id",
            tenant_id,
            opts.issuer_url,
            opts.client_id,
        )
        report.add("oidc_issuer")
    users: dict[str, UUID] = {}
    for username, roles in BINDINGS[spec.slug].items():
        persona = PERSONAS[username]
        uid = await _in_tenant(
            conn,
            tenant_id,
            "SELECT id FROM sibyl.app_user WHERE oidc_issuer_id = $1 AND subject = $2",
            issuer,
            persona.subject,
        )
        if uid is None:
            uid = await _in_tenant(
                conn,
                tenant_id,
                "INSERT INTO sibyl.app_user (tenant_id, oidc_issuer_id, subject, email,"
                " email_verified, display_name, status) VALUES ($1, $2, $3, $4, true, $5,"
                " 'active') RETURNING id",
                tenant_id,
                issuer,
                persona.subject,
                persona.email,
                persona.display_name,
            )
            report.add("app_user")
        elif await _in_tenant(
            conn,
            tenant_id,
            "UPDATE sibyl.app_user SET email = $2, display_name = $3 WHERE id = $1"
            " AND (email IS DISTINCT FROM $2 OR display_name IS DISTINCT FROM $3)"
            " AND status <> 'deprovisioned' RETURNING id",
            uid,
            persona.email,
            persona.display_name,
        ):
            report.add("app_user_renamed")  # an earlier seed's persona naming
        users[username] = uid
        for role in roles:
            if (
                await _in_tenant(
                    conn,
                    tenant_id,
                    "SELECT id FROM sibyl.membership WHERE user_id = $1 AND role_name = $2"
                    " AND scope_kind = 'tenant' AND revoked_at IS NULL",
                    uid,
                    role,
                )
                is None
            ):
                await _in_tenant(
                    conn,
                    tenant_id,
                    "INSERT INTO sibyl.membership (tenant_id, user_id, role_name)"
                    " VALUES ($1, $2, $3)"
                    " RETURNING id",
                    tenant_id,
                    uid,
                    role,
                )
                report.add("membership")
    groups: dict[str, UUID] = {}
    for slug, name in spec.groups:
        gid = await _in_tenant(
            conn, tenant_id, "SELECT id FROM sibyl.agent_group WHERE slug = $1", slug
        )
        if gid is None:
            gid = await _in_tenant(
                conn,
                tenant_id,
                "INSERT INTO sibyl.agent_group (tenant_id, slug, name, owner_user_id)"
                " VALUES ($1, $2, $3, $4) RETURNING id",
                tenant_id,
                slug,
                name,
                users.get("admin"),
            )
            report.add("agent_group")
        groups[slug] = gid
    return users, groups


# --- registry and policy phase (through the api) --------------------------------------------


@dataclass
class Ctx:
    api: Api
    conn: Any
    tenant_id: UUID
    spec: TenantSpec
    opts: Options
    report: Report
    groups: dict[str, UUID]
    ids: dict[str, UUID] = field(default_factory=dict)

    async def find(self, sql: str, *args: Any) -> Any:
        return await _in_tenant(self.conn, self.tenant_id, sql, *args)

    async def ensure(
        self,
        key: str,
        lookup: str,
        args: Sequence[Any],
        kind: str,
        path: str,
        body: dict[str, Any],
        *,
        actor: str = "admin",
    ) -> UUID:
        found = await self.find(lookup, *args)
        if found is None:
            found = (await self.api.call(actor, "POST", path, body))["id"]
            self.report.add(kind)
        self.ids[key] = UUID(str(found))
        return self.ids[key]


async def _catalogs(c: Ctx) -> None:
    for slug, name, crit in c.spec.processes:
        await c.ensure(
            f"bp:{slug}",
            "SELECT id FROM sibyl.business_process WHERE slug = $1",
            [slug],
            "business_process",
            "/business-processes",
            {"slug": slug, "name": name, "criticality": crit},
        )
    for slug, name, kind in c.spec.tools:
        await c.ensure(
            f"tool:{slug}",
            "SELECT id FROM sibyl.tool WHERE slug = $1",
            [slug],
            "tool",
            "/tools",
            {"slug": slug, "name": name, "kind": kind, "is_approved": True},
        )
    for slug, name, kind, classification in c.spec.data_sources:
        await c.ensure(
            f"ds:{slug}",
            "SELECT id FROM sibyl.data_source WHERE slug = $1",
            [slug],
            "data_source",
            "/data-sources",
            {"slug": slug, "name": name, "kind": kind, "classification": classification},
        )
    for prov in c.spec.providers:
        pid = await c.ensure(
            f"provider:{prov.slug}",
            "SELECT id FROM sibyl.provider WHERE slug = $1",
            [prov.slug],
            "provider",
            "/providers",
            {
                "slug": prov.slug,
                "name": prov.name,
                "provider_kind": prov.kind,
                "dialect": "openai_compatible",
                "base_url": c.opts.base_url(prov.slug),
                "status_feed_url": c.opts.status_feed_url(prov.slug),
            },
        )
        for model in prov.models:
            input_usd, output_usd = MODEL_PRICES[model]
            await c.ensure(
                f"model:{model}",
                "SELECT id FROM sibyl.model WHERE provider_id = $1 AND model_name = $2",
                [pid, model],
                "model",
                "/models",
                {
                    "provider_id": str(pid),
                    "model_name": model,
                    "input_usd_per_1m": input_usd,
                    "output_usd_per_1m": output_usd,
                },
            )
        await c.ensure(
            f"cred:{prov.slug}",
            "SELECT id FROM sibyl.provider_credential WHERE provider_id = $1 AND status = 'active'",
            [pid],
            "provider_credential",
            "/provider-credentials",
            {
                "provider_id": str(pid),
                "name": f"{prov.slug} fallback key",
                "base_url": c.opts.base_url(prov.slug),
                "auth_scheme": "bearer",
                "secret": f"sim-{prov.slug}-demo-key-not-a-secret",
            },
        )


async def _capture_policy(c: Ctx) -> None:
    if await c.find(
        "SELECT id FROM sibyl.capture_policy WHERE scope_kind = 'tenant' AND superseded_by IS NULL"
    ):
        return
    profile = await c.find(
        "SELECT id FROM sibyl.redaction_profile WHERE name = 'pii_standard' AND origin = 'system'"
    )
    await c.api.call(
        "admin",
        "POST",
        "/capture-policies",
        {
            "scope_kind": "tenant",
            "capture_mode": "redacted",
            "redaction_profile_id": str(profile),
            "payload_retention_days": 30,
            "consequences_version": "2026-10",
            "acknowledged": True,
        },
        **{"If-Match": "*"},
    )
    c.report.add("capture_policy")


async def _agents(c: Ctx) -> None:
    for spec in c.spec.agents:
        first_model = next(p for p in c.spec.providers if p.slug == spec.provider).models[0]
        await c.ensure(
            f"agent:{spec.slug}",
            "SELECT id FROM sibyl.agent WHERE slug = $1",
            [spec.slug],
            "agent",
            "/agents",
            {
                "slug": spec.slug,
                "name": spec.name,
                "kind": spec.kind,
                "tier": spec.tier,
                "fail_mode": spec.fail_mode,
                "risk_class": spec.risk,
                "agent_group_id": str(c.groups[spec.group]),
                "business_process_id": str(c.ids[f"bp:{spec.process}"]),
                "framework": "sibyl-sim",
                "tags": ["demo", spec.group],
                "version": {"primary_model_id": str(c.ids[f"model:{first_model}"])},
            },
        )


async def _edges(c: Ctx) -> None:
    for spec in c.spec.agents:
        aid = c.ids[f"agent:{spec.slug}"]
        first_model = next(p for p in c.spec.providers if p.slug == spec.provider).models[0]
        wanted = [("model", c.ids[f"model:{first_model}"], "uses_model")]
        wanted += [("data_source", c.ids[f"ds:{d}"], "reads_data") for d in spec.reads]
        wanted += [("tool", c.ids[f"tool:{t}"], "calls_tool") for t in spec.tools]
        wanted += [("agent", c.ids[f"agent:{d}"], "delegates_to") for d in spec.delegates]
        for dst_kind, dst_id, edge_type in wanted:
            if await c.find(
                "SELECT id FROM sibyl.dependency_edge WHERE src_kind = 'agent' AND src_id = $1"
                " AND dst_kind = $2 AND dst_id = $3 AND edge_type = $4 AND valid_to IS NULL",
                aid,
                dst_kind,
                dst_id,
                edge_type,
            ):
                continue
            await c.api.call(
                "admin",
                "POST",
                "/dependency-edges",
                {
                    "src_kind": "agent",
                    "src_id": str(aid),
                    "dst_kind": dst_kind,
                    "dst_id": str(dst_id),
                    "edge_type": edge_type,
                },
            )
            c.report.add("dependency_edge")


def _alt_provider(c: Ctx, spec: AgentSpec) -> str:
    """The failover provider: openai-stub fails over to ollama-stub (S-01), others to openai."""
    slugs = [p.slug for p in c.spec.providers]
    if spec.provider == "openai-stub" and "ollama-stub" in slugs:
        return "ollama-stub"
    return "openai-stub" if spec.provider != "openai-stub" else slugs[-1]


def _steps(c: Ctx, spec: AgentSpec) -> list[dict[str, Any]]:
    provider = next(p for p in c.spec.providers if p.slug == spec.provider)
    alt = next(p for p in c.spec.providers if p.slug == _alt_provider(c, spec))
    steps: list[dict[str, Any]] = []
    if spec.tier == 3:
        steps.append({"kind": "retry", "risk": "low", "max_attempts": 2})
    if len(provider.models) > 1:
        steps.append(
            {
                "kind": "alt_model_same_provider",
                "risk": "low",
                "provider_id": str(c.ids[f"provider:{provider.slug}"]),
                "model_id": str(c.ids[f"model:{provider.models[1]}"]),
            }
        )
    if spec.tier < 3 and alt.slug != provider.slug:
        steps.append(
            {
                "kind": "alt_provider",
                "risk": "medium",
                "provider_id": str(c.ids[f"provider:{alt.slug}"]),
                "model_id": str(c.ids[f"model:{alt.models[0]}"]),
                "credential_id": str(c.ids[f"cred:{alt.slug}"]),
            }
        )
    if spec.backup is not None:
        steps.append(
            {
                "kind": "backup_agent",
                "risk": "medium",
                "backup_agent_id": str(c.ids[f"agent:{spec.backup}"]),
            }
        )
    if spec.tier == 3:
        steps.append({"kind": "degraded_safe_mode", "risk": "low"})
    steps.append({"kind": "human_queue", "risk": "high"})
    return steps


async def _continuity(c: Ctx) -> None:
    for spec in c.spec.agents:
        aid = c.ids[f"agent:{spec.slug}"]
        if not await c.find("SELECT id FROM sibyl.continuity_plan WHERE agent_id = $1", aid):
            body: dict[str, Any] = {
                "degraded_mode": "queue_only" if spec.tier == 1 else "safe_no_tools",
                "approval_timeout_policy": "hold",
                "credential_mode": "vaulted_fallback" if spec.tier < 3 else "passthrough",
                "on_call_ref": f"pagerduty:{spec.group}",
                "budget_usd_month": {1: "5000.0000", 2: "1500.0000", 3: "300.0000"}[spec.tier],
                "max_inflight": {1: 50, 2: 30, 3: 10}[spec.tier],
                "reason": SEED_REASON,
            }
            await c.api.call(
                "admin", "PUT", f"/agents/{aid}/continuity-plan", body, **{"If-Match": "*"}
            )
            c.report.add("continuity_plan")
        if await c.find(
            "SELECT id FROM sibyl.fallback_chain WHERE agent_id = $1 AND status = 'approved'", aid
        ):
            continue
        chain_id = await c.find(
            "SELECT id FROM sibyl.fallback_chain WHERE agent_id = $1"
            " AND status = 'draft' ORDER BY version_no DESC LIMIT 1",
            aid,
        )
        if chain_id is None:
            chain = await c.api.call(
                "admin",
                "POST",
                f"/agents/{aid}/fallback-chains",
                {"steps": _steps(c, spec), "note": SEED_REASON},
            )
            chain_id = chain["id"]
            c.report.add("fallback_chain")
        approver = (
            "operator" if spec.tier == 1 else "admin"
        )  # tier 1: four eyes (approver != requester)
        await c.api.call(
            approver,
            "POST",
            f"/fallback-chains/{chain_id}/actions",
            {"action": "approve", "reason": SEED_REASON},
        )
        c.report.add("chain_approval")


async def _lifecycle(c: Ctx) -> None:
    for spec in c.spec.agents:
        aid = c.ids[f"agent:{spec.slug}"]
        stage = await c.find("SELECT lifecycle FROM sibyl.agent WHERE id = $1", aid)
        if spec.tier == 1:
            if stage == "proposed":
                c.report.awaiting_bound_key.append(f"{c.spec.slug}/{spec.slug}")
            continue
        for target in ("approved", "deployed"):
            order = ("proposed", "approved", "deployed")
            if stage in order and order.index(stage) < order.index(target):
                await c.api.call(
                    "admin",
                    "POST",
                    f"/agents/{aid}/lifecycle",
                    {"to_stage": target, "reason": SEED_REASON},
                )
                stage = target
                c.report.add("lifecycle_transition")


async def _populate(c: Ctx) -> None:
    if not c.spec.agents:
        return
    await _capture_policy(c)
    await _catalogs(c)
    await _agents(c)
    await _edges(c)
    await _continuity(c)
    await _lifecycle(c)


# --- entry points ---------------------------------------------------------------------------


async def ensure_dev_host(migrate_dsn: str, host: str) -> None:
    """``base_url_dev_host`` is writable only by ``sibyl_migrate`` (G0)."""
    conn = await asyncpg.connect(migrate_dsn)
    try:
        await conn.execute(
            "INSERT INTO sibyl.base_url_dev_host (host, note) VALUES ($1, 'sibyl-sim doubles')"
            " ON CONFLICT DO NOTHING",
            host,
        )
    finally:
        await conn.close()


async def seed(
    settings: Settings,
    *,
    opts: Options | None = None,
    migrate_dsn: str | None = None,
    tenants: Sequence[TenantSpec] = WORLD,
) -> Report:
    opts = opts or Options()
    kek = kek_from_settings(settings)
    if migrate_dsn:
        await ensure_dev_host(migrate_dsn, opts.sim_host)
    report = Report()
    db = await Database.connect(
        settings.dsn(), min_size=1, max_size=4, application_name="sibyl-seed"
    )
    conn = await asyncpg.connect(settings.dsn())
    try:
        allowed = await conn.fetchval("SELECT $1 = ANY (sibyl.base_url_dev_hosts())", opts.sim_host)
        if not allowed:
            raise SeedError(
                f"{opts.sim_host!r} is not in sibyl.base_url_dev_host; pass --migrate-dsn or"
                " insert it once as sibyl_migrate (see the module docstring)"
            )
        resolver = StaticTokenResolver({})
        services = Services(
            principals=resolver,
            rate_limiter=_Unlimited(),
            db=db,
            idempotency=PgIdempotencyStore(db),
            settings=settings,
        )
        transport = httpx.ASGITransport(app=create_app(services, settings=settings))
        async with httpx.AsyncClient(transport=transport, base_url="http://seed") as client:
            api = Api(client, resolver)
            for spec in tenants:
                tenant_id = await _tenant(conn, kek, spec, report)
                users, groups = await _identities(conn, tenant_id, spec, opts, report)
                for username, roles in BINDINGS[spec.slug].items():
                    api.act_as(username, tenant_id, users[username], roles)
                await _populate(Ctx(api, conn, tenant_id, spec, opts, report, groups))
    finally:
        await conn.close()
        await db.close()
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sibyl seed", description=__doc__.split("\n")[0])
    parser.add_argument("--migrate-dsn", help="DSN of the sibyl_migrate role (dev-host row)")
    parser.add_argument("--sim-host", default=DEFAULT_SIM_HOST)
    parser.add_argument(
        "--sim-ports", default=json.dumps(DEFAULT_SIM_PORTS), help="JSON map of double slug -> port"
    )
    parser.add_argument(
        "--issuer-url",
        default=None,
        help="dex issuer (default: $SIBYL_OIDC_ISSUER or https://localhost:8443/dex)",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings()
    opts = Options(
        sim_host=args.sim_host,
        sim_ports=tuple(json.loads(args.sim_ports).items()),
        issuer_url=args.issuer_url or settings.oidc_issuer or Options().issuer_url,
    )
    try:
        report = asyncio.run(seed(settings, opts=opts, migrate_dsn=args.migrate_dsn))
    except SeedError as exc:
        print(f"sibyl seed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(
            json.dumps(
                {"created": report.created, "awaiting_bound_key": report.awaiting_bound_key},
                indent=2,
            )
        )
    else:
        done = ", ".join(f"{k}={v}" for k, v in sorted(report.created.items())) or "nothing"
        print(f"sibyl seed: created {done}")
        if report.awaiting_bound_key:
            print(
                "tier-1 agents awaiting an agent-bound key (R35): "
                + ", ".join(report.awaiting_bound_key)
            )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


def register(subparsers: Any) -> None:
    """Mount ``seed`` under ``python -m sibyl_control.cli`` (same options as ``sibyl seed``)."""
    parser = subparsers.add_parser("seed", help="build the D29 demo world (idempotent)")
    parser.add_argument("--migrate-dsn", help="DSN of the sibyl_migrate role (dev-host row)")
    parser.add_argument("--sim-host", default=DEFAULT_SIM_HOST)
    parser.add_argument("--sim-ports", default=json.dumps(DEFAULT_SIM_PORTS))
    parser.add_argument("--issuer-url", default=None)
    parser.set_defaults(handler=_cli_run)


async def _cli_run(args: argparse.Namespace, ctx: Any) -> int:
    opts = Options(
        sim_host=args.sim_host,
        sim_ports=tuple(json.loads(args.sim_ports).items()),
        issuer_url=args.issuer_url or ctx.settings.oidc_issuer or Options().issuer_url,
    )
    try:
        report = await seed(ctx.settings, opts=opts, migrate_dsn=args.migrate_dsn)
    except SeedError as exc:
        ctx.out.write(f"sibyl seed: {exc}\n")
        return 2
    payload = {"created": report.created, "awaiting_bound_key": report.awaiting_bound_key}
    ctx.out.write(json.dumps(payload, indent=2) + "\n")
    return 0
