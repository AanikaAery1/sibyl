# Chair initial position for Step 2 (written before reading member outputs, 2026-10-09)

Founder decisions that bite hardest: commercial multi-tenant, gateway in-line, automatic failover, full capture, zero budget.

## Position
- **Two hot-path services, everything else async.** The gateway (request path) and the SDK's local `resolve_route()` are the only latency-sensitive code. They read a signed, TTL'd policy snapshot and never call the control plane synchronously. Fail-open/closed is a per-agent field in that snapshot.
- **Build the gateway on LiteLLM proxy only if we can keep it a thin dependency.** It solves adapters, streaming, budgets and fallbacks today, but it is a large, fast-moving codebase and the gateway is our product's critical path and security boundary. My lean: own the OpenAI-compatible surface and the routing/snapshot logic ourselves, use LiteLLM's Python library (not the proxy server) for upstream adapters. Revisit if the architect's ADR disagrees with evidence.
- **Postgres primary; add Redis now.** With automatic failover, a state transition must reach the gateway within seconds. Postgres LISTEN/NOTIFY can do it, but Redis Streams plus a key-value policy cache is one container and buys the pub/sub and rate-limit primitives we will need anyway. I was against Redis in Step 1; automatic failover changed the calculus. Expect the backend-architect to settle it.
- **Full-capture payloads go to a BlobStore from day one.** MinIO in compose (S3 API, OSS, GDPR-erasable per prefix), Postgres holds pointers plus a capped preview. Putting multi-KB prompts in JSONB at 1k events/s is a Phase 2 regret.
- **Shared schema + RLS.** Schema-per-tenant does not scale operationally for a SaaS with hundreds of tenants and breaks migrations; RLS plus tenant-prefixed cache keys plus one isolation test per table is the industry default.
- **Self-hosted OIDC IdP (Keycloak or Zitadel) rather than hand-rolled auth.** Commercial buyers will ask for SAML/OIDC/SCIM; hand-rolled auth is the thing security review always fails. Cost is one more container.
- **Durable automatic failover = Postgres-backed state machine with idempotent worker steps in Phase 1.** Temporal is the right Phase 2 answer once sagas (pre-emptive gradual shift, verified failback, drills) exist. Automatic does not yet mean complex.
- **Governance-led positioning changes Phase 1 scope**: asset profile must carry risk tier, data classification, owner, lifecycle stage and approval status from day one; audit event taxonomy must be designed for evidence export, not just debugging.

## What I most want the members to settle
1. LiteLLM: library vs proxy vs none (chief-architect, backend-architect).
2. Redis in Phase 1 or not (backend-architect, database-architect).
3. Whether "store all data by default" is defensible for a commercial product and what has to be true (security-auditor). I suspect the honest answer is: default on, but with secret-pattern scrubbing always on and a per-tenant redaction policy that is one click to enable.
4. Detection-to-reroute latency budget for automatic failover (sre-engineer, backend-architect). My target: < 10 s from the triggering event to the gateway honouring the new route.
