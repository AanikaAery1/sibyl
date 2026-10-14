## Council · datamodel · Vigil (Step 3)

Two waves. Wave 1: database-architect (registry, telemetry, rollups, graph, streams), backend-architect (continuity, routing, failover, approvals, alerts, health, queue, snapshot document), ai-engineer (`vigil-event/1` envelope and 14 event types, OTel GenAI mapping pinned to semconv v1.37.0, checkpoint, handoff packet v1, health response, feature snapshot, labels; every example validated against its JSON Schema), security-auditor (identity, keys, credentials, capture policy, ~90-action audit taxonomy, erasure, legal hold, kill switch). Wave 2: database-architect consolidated everything into DATAMODEL.md. Chair position written first (CHAIR-INITIAL.md); chair rulings on cross-member conflicts in CHAIR-RULINGS.md (R1–R20).

### Decisions (headline)
- One wide daily-partitioned `events` table for `vigil-event/1`; no spans table; captured content never inline (every body is a `PayloadRef` with sha256 and redaction-profile hash).
- Rollups `agent_metrics_1m`/`_1h` with mergeable log-bucket histograms, recomputed idempotently per dirty bucket; health reads rollups only.
- `routing_apply()` is the only writer of `routing_state`, used by the worker saga and inline by api for kill/quarantine/undo; every route change produces the same transition + audit + outbox rows.
- Credentials never appear in the policy snapshot; the gateway fetches the memory-only bundle separately.
- No `org` table: tenant is the sole isolation boundary; `agent_group` scopes engineer/operator/viewer.
- Capture policy and redaction profiles are immutable versioned rows with no default; every profile must be a superset of the `secrets_only` baseline (database fact, not app convention).
- Audit: `audit_append()` SECURITY DEFINER with per-tenant advisory lock; envelope canonicalised in-DB, detail by `vigil-schemas`; `audit_action` lookup table validates the taxonomy; hourly signed anchors.
- Explicit `legal_hold` rows; crypto-shred erasure as a 7-state machine whose certificate names when pre-shred backups expire.
- Composite `(tenant_id, id)` uniqueness and FKs on every tenant table; text + CHECK enums generated from `vigil-schemas`; no Postgres ENUMs; no soft delete.

### Conflicts surfaced (and how resolved)
See CHAIR-RULINGS.md for all twenty. The ones that changed earlier documents:
- **R1** api writing `routing_state` directly for kill (security) vs worker-only (ARCHITECTURE §5) → `routing_apply()` as sole writer; §5 amended.
- **R3** D13 "automatic on detected failure for all tiers" vs tier table keeping backup-agent failover approval-gated for tier 1 → tier table wins; D13 clarified in DECISIONS.md.
- **R4** three partitioned tables (ADR-3) vs spans collapsed into events → collapse; ADR-3 amended.
- **R6** 1-minute buckets vs MTTD p95 < 90 s (sre) → detected rules evaluate the open partial minute with `min_samples`; leading rules closed buckets only.
- **R11** "JCS in-DB" (ADR-12) is not implementable in Postgres → canonicalisation split; ADR-12 amended.
- **R12/R13** API-key hashing and key scoping → HMAC-SHA-256 + pepper; keys agent-bound or tenant-level, header may only narrow.
- **Chair changed position**: I expected a possible spans table and a packet-as-blob design; the members' events-only model and the checkpoint/packet-as-JSONB-rows-with-PayloadRefs design are better and were adopted.

### Premise checks
- security-auditor: OIDC-only identity leaves no kill-switch path when the tenant's IdP is down, which is exactly when you need it. Proposes a break-glass `killswitch:pull`-only API key, printed once, every use critical-audited. Escalated.
- ai-engineer: `policy.decision` is emitted only for non-default decisions, otherwise event volume doubles; `observation.gap` is first-class so control-plane outages never train or alert on silence.
- database-architect: per-tenant raw retention cannot be honoured by shared partitions alone; sweeper plus 30-day cap in Phase 1.

### Gate status (datamodel)
- [x] Entities and relationships for every Phase 1 domain, with invariants
- [x] Event schemas as JSON Schema with validated examples (ai-engineer.md)
- [x] Column-vs-JSONB-vs-PayloadRef mapping agreed between ai-engineer and database-architect
- [x] Audit taxonomy, key hierarchy, RBAC matrix (security-auditor.md)
- [x] Consolidated DATAMODEL.md: 62 tables in nine domains, 9 partitioned, 7 ERDs (all rendered), 11-table infrastructure allowlist, `routing_apply()` 24-arg and `audit_append()` 14-arg signatures, write paths, migration 0 + nine domain migrations with three CI gates, seed contract that only calls the service layer so the demo's audit chain is genuine
- [ ] Founder answers to the eight Step 3 questions

### Wave-2 resolutions worth knowing (DATAMODEL.md §9, U1–U15)
R8 decided as `call_merge` staging plus append-only `events`, multi-row INSERT ON CONFLICT instead of COPY (ARCHITECTURE §3 amended). `events.agent_id` nullable only for `provider.status` and `observation.gap` (ai-engineer to loosen the schema). Feature snapshots sampled, not per tick. Tier and fail_mode live only on `agent`. Inline checkpoint/packet previews (≤64 KB in rows) are erased by hard delete plus backup expiry, not crypto-shred; the erasure certificate says so. Label table is the truth; `alert.verdict` is a projection.

### Open questions for the founder (defaults the council proceeds on)
1. Break-glass: a tenant-level `killswitch:pull`-only API key as the IdP-down emergency path? Default: yes.
2. Operator hold after undo (30 min): block detected hard-failure actions too, or only predictions? Default: blocks all rule/policy actors; humans and kill bypass.
3. `fail_safe` approval timeout (10 min) on tier-1 agents tagged PII/residency: shift without a human, or force `hold`? Default: force `hold` for PII/residency-tagged agents.
4. Tier RTO defaults when a continuity plan is silent: 15 min / 1 h / 4 h for tiers 1/2/3. Default: yes.
5. Mandatory true/false-positive verdict before an alert can close (one click, with "unsure")? Default: mandatory; it is what makes the Step 5 training set honest.
6. OTel semconv pinned at v1.37.0; bump the normaliser at code freeze if newer? Default: bump at freeze.
7. Erasure certificate states "pre-shred backups expire on <date>" with `backup_retention_days = 7`? Default: yes.
8. Audit retention: 400 days minimum, up to 7 years per contract (security) vs 7 years for everyone (database). Default: 400 days minimum, contractual extension.
9. Payload retention ceiling per tenant in Phase 1: up to 365 days, or cap at 90? Default: 365, cost is per tenant.
10. Demo naming: tenants `meridian` (20 agents), `northstar` (3 agents, isolation proof), `sandbox` (empty, onboarding demo); dex personas Platform Admin (`admin`), On-call Operator (`operator`), Compliance Auditor (`auditor`). Default: yes.

### Next
Step 4: API design for the main services plus the SDK interface. backend-architect leads the REST/SSE surface (OpenAPI), ai-engineer the SDK interface and OTLP ingest contract, security-auditor the auth/authz on every route, technical-writer the developer-facing SDK quickstart. Waits for the founder's review of Step 3.
