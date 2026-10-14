# Step 6 — Phased roadmap: chair synthesis (2026-10-10)

Members: sprint-prioritizer (515 lines, lead: phase scopes, re-estimate, cut lines, Step 7 waves and lanes, milestones), chief-architect (426, dependency graph, wave 0 contract freeze, contract drift X1–X9, seam tests, risks T1–T10, debt and phase deltas), product-manager (435, personas, capability value ranking, buyer-side cut order, design-partner profile, competition, north star, pricing hypotheses), project-shipper (442, 12-minute demo script, demo blockers B1–B5, milestones, Phase 1 done, cloud cutover C0–C13, launch checklists, versioning). Consolidated: `ROADMAP.md`.

## Headline
Phase 1 as specified is **about 230 engineer-days**, roughly 3× the Step 1 estimate of ~75. The growth comes from founder decisions taken after Step 1 (multi-tenancy, in-line gateway, automatic tiered failover with approvals, erasure) and the ~110-route, 28-scenario surface. It does not fit the ~20 working-day window. The council recommends a cut line that lands Phase 1 at **27 working days P50 / 32 P80**, followed by a **~7-day Phase 1.5** that restores everything cut and acts as the gate before any design-partner traffic.

## Conflicts surfaced and chair rulings (R52–R71)

| # | Conflict | Members | Ruling |
|---|---|---|---|
| R52 | Phase 1 duration: ~21 days (chief-architect, sequencing view, no slippage) vs 27 P50 / 32 P80 (sprint-prioritizer, throughput view, recommended cuts) | CA §1, SP §2 | **Plan to 27 working days P50, commit to 32 P80.** CA's 21 is the best case if wave 0 closes on day 3 and throughput holds at 2 E/lane-day; it is reported as the stretch, not the plan. |
| R53 | Cut line: SP tiers A+B vs PM buyer-side order (risk rubric first, then R6–R8, then leading rules, …, break-glass/step-up) | SP §3, PM §2.5 | **Adopt SP Tier A (A1–A8) + Tier B (B1–B4)**, plus PM cut 1: the risk-assessment suggestion rubric moves to Phase 2; declared `risk_class` and the single "deployed and unclassified" finding stay. **R6–R8 stay** in Phase 1 (R37 gates silent degradation; SP keeps them). **Break-glass key and step-up stay** (D20; security veto). Tier C rejected; C2 would reverse D17 and is not offered. |
| R54 | Phase 1.5 role | PM §3, SP §1.2 | Phase 1.5 is a **gate, not a parking lot**: everything cut by R53 returns, plus 5 consecutive green nightlies, a tested off-host restore, and an external security assessment with no open CRITICAL/HIGH, all before a design partner's first production call. |
| R55 | Demo mode forbids vaulted credentials, but S-01 alt-provider failover and S-15 need them | CA X6, SP Q2 | `SIBYL_DEMO=1` **allows** `provider_credential` rows only when `base_url` resolves to an allowlisted `sibyl-sim` provider double; any other base URL is refused with `409 demo_mode`. Unblocks the wave 0 freeze. |
| R56 | Persona roles cannot perform the scripted actions | PS B1 | Demo bindings: **Platform Admin = `owner`, On-call Operator = `operator` + `security_admin`, Compliance Auditor = `auditor`**. No fourth persona. |
| R57 | Quickstart contradicts the contract | PS B2–B5 | All four fixes adopted: two keys (tenant-level `gateway:proxy`; agent-bound `ingest:write routing:read handoff:write`); chaos only via `sibyl-sim` on its own port; live view uses `GET /api/v1/events/stream` (ids + versions) and the console; tier-2 narration says 20 s (D39). technical-writer updates the quickstart in wave 0. |
| R58 | Contract drift across Steps 2–5 | CA X1–X9 | All nine of chief-architect's fixes adopted and applied in wave 0: ~12 coarse outbox topics on **two NOTIFY channels** (`sibyl_policy`, `sibyl_outbox`); policy routes at `/api/v1/policy/{snapshot,keys}` + `/.well-known/sibyl-keys.json`; erasure cascade extended to the 14 Step 4/5 tables with a generated completeness check; `health_snapshot` write-on-change; role list = six roles; `pgaudit` on the allowlist, `pgvector` removed until Phase 3; ARCHITECTURE §5 marked superseded by API.md; `partition_registry.grain` += `3day`. |
| R59 | Step 4/5 amendments: append or fold | CA Q1 | **Fold** into the base migrations (no code exists yet). All 73 Phase 1 tables (76 incl. Phase 2 ML tables, created empty) apply as a non-superuser. |
| R60 | Outbox/rollup cursors can skip rows that commit out of order (missed failure) | CA T2 | **Commit-ordered `xid8` cursors** (`pg_snapshot_xmin` horizon) for outbox, rollups and SSE. Seam test with deliberately interleaved commits. |
| R61 | Ingest auto-register holds the tenant audit lock up to 10 s and can stall the kill switch | CA T5 | Auto-register runs in **its own short transaction** before the batch; kill-switch latency is a seam test (p99 < 1 s under ingest load). |
| R62 | Gateway is the duration critical path (16–18 dev-days, one owner) | CA §1.2 | **Split into two lanes**, G-hot (proxy, streaming, fail modes) and G-policy (snapshot verify, routing decision, inline fallback), joined by a `PolicyView` interface frozen in wave 0. |
| R63 | Restoring a pre-erasure backup resurrects erased data | PS §3.5 | **Phase 1 done item**: an append-only erasure ledger outside Postgres (BlobStore, separate prefix, hash-chained) and a mandatory re-shred step in the restore runbook; the restore drill asserts zero resurrected rows. |
| R64 | Milestones: SP M0–M4 (days 4/14/23/25/27) vs PS M0–M5 (adds demo freeze) | SP §5, PS §2 | SP's day numbering with PS's split: **M0** contracts frozen (d4) · **M1** traffic seen, health explained (d14) · **M2** detected failover, handoff, audit (d23) · **M3** prediction, approvals, kill, queue; reports the D36 precision/recall result either way (d25) · **M4** erasure, CRITICAL gates green, end-to-end demo (d27) · **M5** demo freeze: two consecutive clean rehearsals, `v0.1.0` tag (inside P80 buffer). |
| R65 | Wave 0 length 3 days (CA) vs 4 (SP); automatic Tier C cuts on overrun (SP Q5) | CA, SP | Wave 0 is **4 days**. An overrun past 5 days triggers a **re-plan presented to the founder**; no scope is cut automatically. |
| R66 | Commit mechanics; "repo is not a git repository" | SP Q4 | Correction: `~/projects/vigil` **is** a git repo (Steps 1–6 committed). Lanes hand back uncommitted worktrees; the chair commits each lane locally after its gate passes; the founder reviews at each milestone; **nothing is pushed without his explicit approval**. |
| R67 | Threshold adaptation from verdicts: Phase 1.5 (ML §3.9) vs Phase 2 (SP) | SP Q6 | **Phase 2**: it needs verdict volume only a real tenant produces. |
| R68 | Learned-layer promotion unlikely inside a 90-day pilot | PM Q2 | Phase 2 exits with the learned layer **in shadow** plus a model card and a reported verdict count. Promotion is volume-triggered (D37/R42 floors), not dated. |
| R69 | LiteLLM coexistence | PM Q6 | Phase 2 supports "Sibyl in front, LiteLLM as an OpenAI-compatible upstream" with retries disabled on one side; documented, compatibility-tested; no provider-breadth work. |
| R70 | `sibyl-schemas` licence | PS §6 | Published **Apache-2** alongside `sibyl-sdk` (the SDK depends on it). Registries, OpenAPI documents and fixtures live in `sibyl-schemas` (ADR-13 note). |
| R71 | Nightly CI compute under D10 | SP Q3 | Gates run locally during Phase 1. Once a private remote exists: PR suite on free hosted minutes, nightly on a self-hosted runner on the founder's **personal** machine, not employer infrastructure (D1). |

## Accepted without conflict
- North star: **verified governed coverage**, the share of production AI calls through Sibyl from agents that have an owner, a tier, a declared risk class and a fallback proven by a real failover or drill in the last 30 days (PM), with four counter-metrics.
- Demo-killers that must never be cut: automatic failover with the task still completing; a handoff packet a human completes in the queue; the hash-chained audit with `sibyl audit verify` and a readable decision record (PM). Verdicts, fail-open/closed and the secrets scrub are not on screen but are also uncuttable.
- 12-minute demo script with a `sibyl-sim demo` conductor that pre-starts slow scenarios (no clock override, R45), recorded fallback chapters per segment, separate demo and harness stacks (PS).
- Cloud cutover C0–C13: off-host backup first (R2/B2 free tier), k3d rehearsal before any managed Kubernetes, 7-night parallel run before partner traffic (PS); six-step migration path and 16 accepted Phase 1 debt items with named paybacks (CA).
- Seam tests S1–S14 with shared golden fixtures; S4/S5/S9/S10 on real Postgres per PR (CA). Top risks T1–T10 with owner lanes (CA).
- Design-partner profile: regulated or quasi-regulated, 500–5,000 staff, 10–60 production LLM workflows (≥ 3 tier-1), ≥ 2 providers, a recent outage they can describe; 10 written pilot success criteria (PM).
- Competitive line: Sibyl starts at governed continuity, human handoff and audit-grade evidence; never out-build Langfuse/Phoenix/OpenLLMetry/Helicone on trace UI, evals or instrumentation, nor LiteLLM on provider breadth (PM).
- Pricing hypotheses for Phase 3 only, all unvalidated; SDK and kill switch never paywalled (PM, D15).
- SDK SemVer 0.x until the first paying tenant; server accepts current + two previous SDK minors; PyPI Trusted Publishing (PS).

## Open questions for the founder

### Council defaults (say "continue" to adopt)
1. **R52/R53 size and cut line:** plan Phase 1 at 27 working days P50 (32 P80) with Tier A+B cuts and a 7-day Phase 1.5 gate, rather than forcing 20 days through Tier C. Default yes.
2. **Design-partner hosting:** partner #1 self-hosts single-tenant in their own cloud via Helm (k3s on one VM is fine); Sibyl-hosted multi-tenant from partner #2. Keeps partner data out of a single operator's custody. Default yes.
3. **External security assessment funding:** sequence it as unpaid pilot → assessment → first invoice funds it, keeping D10 intact until revenue. Default yes.
4. **First wedge:** pick the partner first and let geography follow; ship NIST AI RMF + ISO/IEC 42001 mappings first, the EU AI Act pack second. Default yes.
5. **Review cadence in Step 7:** chair commits locally at each wave gate; you review at each milestone M0–M5. Default yes.

### Founder-only (no default; these need you)
6. **Entity and IP ownership.** Pilot agreements, the DPA and terms need a contracting entity, and prospects' legal teams will ask who owns the IP. This precedes any outreach; it does not block the build. (The founder confirmed 2026-10-10 that Sibyl is not built on employer equipment.)
7. **Package names.** Reserving `sibyl-sdk` and `sibyl-schemas` on PyPI and the `@sibyl` npm scope needs your accounts and is public. Approve reserving them during wave 0, with a fallback such as `sibyl-ai-*` if taken? Availability has not been checked.

## Next
Step 7 — build Phase 1, starting with wave 0 (4 days: schemas, folded migrations, OpenAPI, `PolicyView`, fixtures, R55–R63 fixes, quickstart update). Waits for the founder's review of Step 6.
