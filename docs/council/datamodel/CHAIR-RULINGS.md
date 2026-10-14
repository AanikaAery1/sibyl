# Chair rulings on wave-1 conflicts (input to wave 2, 2026-10-10)

Read alongside the four wave-1 reports. Where a ruling amends ARCHITECTURE.md, the amendment is applied there too.

| # | Conflict | Ruling |
|---|---|---|
| R1 | Who writes `routing_state`: worker only (ARCHITECTURE §5) vs api direct for kill (security) | **`routing_apply()` is the only writer**, called by the worker saga step and inline by api for operator-immediate actions (kill, quarantine, release, undo). ARCHITECTURE §5 amended. |
| R2 | Global `policy_snapshot_issue` sequence vs "no global business sequences" | Allowed as **infrastructure** (allowlisted with `tenants`, `alembic_version`). Per-tenant `routing_version` remains the business counter. |
| R3 | D13 "automatic on detected failure for all tiers" vs tier table keeping backup-agent failover at approval for tier 1 | **Tier table wins.** Backup agent is a different blast radius than an alternate model. Recorded as a D13 clarification. |
| R4 | `spans` table vs spans collapsed into `events` | **Collapse.** A span is an event with `latency_ms` and `parent_span_id`; raw OTel spans stay in BlobStore. ADR-3 amended to two partitioned tables (`events`, `payload_refs`). |
| R5 | `consumer_cursor` vs `consumer_offsets`; outbox vs events-as-log | **database-architect's split**: telemetry consumers tail `events` by `(received_at, event_id)`; domain events go through `outbox`; one `consumer_offsets` table keyed `(group, tenant, topic)`. |
| R6 | 1-minute rollup buckets vs MTTD p95 < 90 s | **Keep 1 m buckets and the 10 s tick.** Detected (hard-failure) rules evaluate the open partial minute plus the previous one with a `min_samples` guard; leading rules evaluate closed buckets only. sre-engineer's MTTD SLI stands. |
| R7 | Per-tenant raw retention vs shared daily partitions | Partitions drop at the configured maximum (cap 30 d); a per-tenant DELETE sweeper enforces shorter settings. Per-tenant partitions are a dedicated-DB-tier feature. |
| R8 | `COPY` (ARCHITECTURE §3) vs `INSERT … ON CONFLICT DO NOTHING` vs the two-author `gen_ai.request` merge | **database-architect decides in wave 2**; ai-engineer's `call_merge` staging table is the default so `events` stays append-only. |
| R9 | `source` enum adds `api`; `actor_type` adds `agent` | **Both accepted.** Operator actions originate in api; SDK-originated actions are attributable to the agent identity. |
| R10 | `provider.status` under a platform tenant id (cross-tenant readable row) | **No RLS exception.** The worker fans one write-on-change row out per tenant (`provider_status` is already tenant-scoped per database-architect). |
| R11 | ADR-12 "JCS in-DB" is not implementable in Postgres | **security-auditor's split**: envelope canonicalised in-DB (flat, deterministic), detail canonicalised by `vigil-schemas` and verified by jsonb equality before hashing. ADR-12 amended. |
| R12 | API key hashing: Argon2id vs HMAC-SHA-256 + pepper | **HMAC-SHA-256 + pepper** (32-byte random secrets, gateway verifies locally in microseconds). |
| R13 | Tenant-wide gateway key with free `X-Vigil-Agent` override vs per-agent keys | **Keys are agent-bound or tenant-level; the header may only narrow, never widen.** Format `vgl_<env>_<prefix12>_<secret>`. |
| R14 | Implicit legal hold via open incidents vs explicit `legal_hold` rows | **Explicit rows**, optionally auto-created on incident open via `tenant.hold_on_incident`. Erasure and shred check the table, not incident state. |
| R15 | Redaction profile recorded by FK vs content hash | **Content hash** of an immutable, versioned profile (`payload_refs.redaction_profile_hash`). |
| R16 | `org` table vs tenant-only | **No `org` table.** `agent_group` with group-scoped memberships for engineer/operator/viewer; owner/admin/security_admin/auditor tenant-scoped. |
| R17 | `health_snapshot` cadence | **Every 10 s tick, partitioned, 3-day retention.** The flat-line evidence is worth ~170k rows/day/tenant. |
| R18 | Alert rules global vs per-tenant copies | **Per-tenant copies** seeded from `rules/v1/defaults.yaml` with `origin='seed'` and `overridden` flag; RLS stays uniform. |
| R19 | Content inline in events | **Never.** Every captured body is a `PayloadRef`; `attrs` capped at 4 KB. The 64 KB inline cap applies only to checkpoint state and packet bodies in their own rows. |
| R20 | Postgres 17 lacks `uuidv7()` | Migration 0 ships a SQL `uuidv7()` function; note for the Postgres 18 upgrade. |

Escalated to the founder after wave 2 (not ruled): break-glass kill-switch API key when the tenant IdP is down; operator-hold scope after undo; `fail_safe` approval timeout for PII/residency-tagged tier-1 agents; tier RTO defaults 15 m / 1 h / 4 h; forced alert verdict on close; semconv bump at code freeze; erasure vs pre-shred backups and `backup_retention_days`; audit retention 400 d vs 7 y.
