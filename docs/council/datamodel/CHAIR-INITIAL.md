# Chair initial position for Step 3 (written before reading member outputs, 2026-10-09)

## What the data model must make impossible
- A row without `tenant_id`, or a query path that skips `SET LOCAL app.tenant_id`. RLS with FORCE on every table, generated isolation test per table.
- Two active routing states for one agent. One `routing_state` row per agent, `routing_version` strictly increasing per tenant.
- A payload body inside an event or audit row. Bodies live in BlobStore; rows hold refs and hashes.
- A plaintext credential or API key column anywhere.
- An audit row written by anything other than `audit_append()`.
- A capture policy that was never chosen (no default row).

## Shape I expect
- **Events**: one wide, daily-partitioned `events` table for `vigil-event/1`, with ~20 first-class columns (ids, ts/observed_at, type, provider/model, latency, tokens, cost, status, policy_state, payload_ref, redaction_profile, seq) and a JSONB `attrs` for the rest. Spans are not a separate table in Phase 1; the OTel span is the raw record kept in BlobStore, the event is the normalised derivative.
- **Rollups**: `agent_metrics_1m` and `_1h` keyed by (tenant, agent, provider, model, bucket), mergeable log-bucket histograms for latency, counters for errors, tokens, cost, fallbacks. Health reads only rollups, never raw events.
- **Routing/failover**: `continuity_plan` (static intent), `routing_state` (current desired), `routing_transition` (immutable log), `failover` (durable workflow row), `approval`. The signed snapshot is a projection of these, never stored as truth.
- **Identity**: `tenant` → `user` (iss, sub) → `membership` (role). `org` is unnecessary in Phase 1: tenant is the commercial unit. Keep a nullable `parent_tenant_id` for enterprise hierarchies later.
- **Audit**: `audit_events` per-tenant hash chain, `audit_anchors` hourly signed. Taxonomy as a lookup table so new actions need a row, not a migration.
- **Enums**: check constraints over text, not Postgres enums (enum ALTERs are painful in migrations), except where the set is truly fixed (fail_mode).

## Where I expect disagreement
- Spans table vs events-only (database-architect may want spans for tool-call hierarchy).
- `org` layer (security-auditor may want org ≠ tenant for reseller/enterprise).
- How much of the handoff packet is columns vs a JSON blob (I lean: `handoff_task` has state/claim/deadline columns, the packet body is a blob ref plus a small JSONB summary for the queue view).
