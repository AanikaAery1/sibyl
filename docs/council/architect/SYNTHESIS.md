## Council · architect · Vigil (Step 2)

Members: chief-architect, backend-architect, database-architect, security-auditor, sre-engineer, ai-engineer. Chair position written first (CHAIR-INITIAL.md). Deliverable: ARCHITECTURE.md.

### Decisions
See ARCHITECTURE.md §6 (13 ADRs). Headline: own thin Python gateway with signed snapshot; Postgres as the only durability point including the event bus; BlobStore with fs and S3 adapters from day one; shared-schema RLS; OIDC relying party only; automatic failover as a Postgres state machine with risk-tier gates; OTel GenAI as the sole wire contract; per-tenant hash-chained audit with signed anchors.

### Conflicts surfaced (and how resolved)
- **C1 Redis in Phase 1.** Chair initial and Step 1 chief-architect: yes, for fan-out and counters. chief-architect (Step 2), backend-architect: no, Postgres outbox + NOTIFY + SSE reaches gateways in < 2 s. sre-engineer: fine if strictly disposable. security, database: if ever, Valkey (BSD), not Redis (SSPL/AGPL). Resolved: **no Redis/Valkey in Phase 1**; explicit reopen triggers in ADR-4. **Chair changed position.**
- **C2 Payload storage.** backend-architect: Postgres `blobs` table. chief-architect: fs volume now, S3 adapter ready. database-architect: S3-API object store (MinIO) from day one, never a Postgres blob adapter. sre-engineer: fs adapter plus 8 KB inline cap, because 1k events/s ≈ 130–200 GB/day. security: MinIO is AGPL. Resolved: **BlobStore interface with `fs` (compose default, no extra container) and `s3` (CI-tested against SeaweedFS, Apache-2) adapters, both Phase 1; no Postgres blob adapter; MinIO not bundled**. Chair's initial "MinIO from day one" refined to "S3 API from day one".
- **C3 TimescaleDB.** Step 1 chief-architect and Chair assumed it. Step 2 chief-architect and database-architect reject it: compression and continuous aggregates are TSL-licensed and absent from RDS, Cloud SQL and Azure PG, which breaks the managed-Postgres migration. Resolved: **plain partitioning**. STEP1 A3 superseded.
- **C4 LiteLLM.** Chair initial: library for adapters. backend-architect: library on the cross-dialect fallback path only, behind a `Dialect` interface. ai-engineer: library at most, routing authority never in LiteLLM. security: prefer own, its admin UI, master key and callbacks are attack surface. chief-architect: none; its enterprise tier is our product. Resolved for the chief-architect: **no LiteLLM code in the request path**; `Dialect` interface retained with our own adapters (OpenAI-compatible covers Ollama; Anthropic translation). Vendor the price JSON.
- **C5 Provider credential custody.** chief-architect ADR-10: vault by default, passthrough opt-out. security-auditor: passthrough by default, vault only for fallback targets, allowlist `base_url`. Both agree cross-provider failover is impossible without custody; nobody had surfaced this before Step 2. Resolved: **passthrough for the primary call, vaulted only for configured fallback targets**, console shows which agents have continuity. **Escalated as Q1** because it is a liability decision.
- **C6 Predicted failover for tier 1.** D6 says automatic. chief-architect, backend-architect and sre-engineer all recommend propose-and-approve with a timeout for leading-indicator-only triggers on tier 1, automatic for detected failures on every tier and for lower tiers on predictions. Resolved as the council's recommendation; **escalated as Q3** since it refines a founder decision.
- **C7 Capture default.** D7: store all by default. security-auditor: defensible only under seven conditions and should be an explicit onboarding choice, not a silent default; ai-engineer and security: secrets scrubbing must be unconditional; database-architect: redaction capability ships in Phase 1 and every object records its profile; sre: it is a capacity decision. Resolved: **secrets scrubbing unconditional; `capture_mode` chosen explicitly in the onboarding wizard with `full` pre-selected; default payload retention 30 days; redaction profile recorded**. **Escalated as Q2** because it modifies D7's "default".
- **C8 Identity.** security-auditor: OIDC RP plus a local Argon2id+TOTP fallback. chief-architect: OIDC RP only, never store passwords, dex for demo. Resolved for the chief-architect: owning password auth is the thing security reviews fail; dex's static users cover the demo. Chair's initial Keycloak/Zitadel position dropped (Keycloak too heavy as default, Zitadel AGPL).
- **C9 Propagation latency.** chief-architect < 2 s via SSE; backend 5 s gateway / 10 s SDK; sre SLO p95 5 s / 30 s. Resolved: targets 2 s / 10 s, SLOs 5 s / 30 s; sub-second push is Q6 territory, not needed for the demo.
- **C10 Availability claim.** STEP1 said "data plane effectively 99.99% via fail-open". sre-engineer: not true for zero-code proxy agents on one host. Resolved: **SLOs stated per deployment shape**. STEP1 §4 corrected in ARCHITECTURE.md §6.
- **C11 "Postgres the only stateful component" (D4).** chief-architect and database-architect both note D7 forces a second stateful thing (the blob volume). Resolved: Postgres is the only **durability point for structured state**; blobs are a second, and the most portable, stateful component.
- **C12 CI latency gate.** chief-architect: hard gate on every PR. sre-engineer: impossible on shared runners. Resolved: hard gate on a self-hosted reference runner, warn-only on shared runners.

### Premise checks
- security-auditor challenged D7 directly (see C7) and flagged that a governance-led product hoarding prompts by default has a credibility problem with its own buyer.
- sre-engineer challenged D6: automatic failover that flaps is worse than a click; hysteresis, cooldown and a verified-failback gate are day-one, and the provider-outage drill fails on more than two transitions in ten minutes.
- chief-architect and ai-engineer both flagged that "predict failures" is rules in Phase 1 and must be labelled as such in the console (`source: rules/v1`, `confidence: low`).
- backend-architect flagged that zero-code agents only get `request_only` handoff packets; the continuity sentence is over-promised for proxy-only onboarding unless the console says so.

### Gate status (architect)
- [x] C4 context and container views (Mermaid, validated by members with mermaid-cli)
- [x] Hot-path sequence and failover state machine
- [x] 13 ADRs with alternatives and consequences
- [x] Threat model (security-auditor.md: 20 STRIDE rows, 10 boundaries)
- [x] SLOs per component and deployment shape (sre-engineer.md)
- [x] Storage architecture, multi-tenancy, audit chain design (database-architect.md)
- [x] SDK, OTel contract, prediction contract (ai-engineer.md)
- [ ] API contract sketch exists (backend-architect.md §5) but Step 4 designs it
- [ ] gstack `/plan-eng-review` on ARCHITECTURE.md: deferred to the founder's choice (interactive review; the founder's own review supersedes)
- [ ] Founder answers to Q1–Q8

### Next
Step 3 (data model + event schemas): database-architect leads; backend-architect (routing/failover/queue entities), ai-engineer (OTel span → `vigil-event/1` normalisation, checkpoint and packet schema), security-auditor (credential, key and audit event entities). Waits for the founder's review of Step 2.
