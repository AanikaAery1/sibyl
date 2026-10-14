# Step 4 — APIs + SDK: chair synthesis (2026-10-10)

Members: backend-architect (999 lines, ~110 control-plane routes + gateway + OpenAPI skeleton), ai-engineer (804, ingest + `sibyl-sdk` + handoff schema), security-auditor (514, 36 scopes, per-route authz, STRIDE top 15, scrub contract), technical-writer (623, quickstart, conventions, runbook, docs IA, glossary). Consolidated contract: `API.md`.

## Conflicts surfaced and chair rulings (R21–R36)

| # | Conflict | Members | Ruling |
|---|---|---|---|
| R21 | Scope spelling: `telemetry:write` (DATAMODEL §4.1, ai-engineer) vs `ingest:write` / `agents:*` / `routing:read` (security-auditor renames) | ai-eng Q1, sec Q4 | **Adopt security-auditor's `<resource>:<verb>` catalogue** as the one grammar; `ingest:write`, `agents:*`, `routing:read`. Step 3 names are amended, not aliased. Code does not exist yet; one rename now beats aliases forever. |
| R22 | API key prefix `sb_` (writer) vs `sbl_<env>_<prefix12>_<secret>` (backend, ai-eng, security) | writer Q1 | **`sbl_`**. Writer updates quickstart. |
| R23 | Provider credential passthrough header | writer Q1 | Client sends its provider key in `Authorization` unchanged (OpenAI-client compatibility, D16) and the Sibyl key in `X-Sibyl-Key`. Gateway strips `X-Sibyl-*` upstream. |
| R24 | Incident resource shape: failover saga row (backend B1) vs projection of failover+approval+alert+handoff (security Q3) vs union with alerts (backend Q2) | backend Q2, sec Q3 | **Incident = failover saga row (B1).** Alerts stay a separate list cross-linked via `alert.failover_id`; console merges client-side. Security's action→scope table binds to `POST /incidents/{id}/actions`; `POST /agents/{id}/actions` is dropped (one write path). |
| R25 | Action enum: backend `approve\|deny\|undo\|clear_hold\|release\|fail_back\|cancel` (+ `POST /incidents` kinds `failover\|degrade\|recover\|handoff\|quarantine\|kill`) vs writer `approve\|deny\|undo\|hold\|release_hold\|quarantine\|kill\|release\|close` | writer Q3 | **Backend's vocabulary** is canonical and is also the audit taxonomy verb. Kill switch is its own resource (`/kill-switches`, break-glass per D20), not an action. Writer rewrites runbook table. |
| R26 | Gateway identity: platform credential `SIBYL_GATEWAY_TOKEN` with `gateway:snapshot` (security Q1) vs N tenant keys / N snapshots (backend Q5) | both | **N tenant keys, N snapshot blocks, no cross-tenant credential** (ADR-7). Hosted gateway holds one key per tenant it fronts. Revisit at sidecar packaging (Phase 2). |
| R27 | OTLP success code 200 vs 202 | ai-eng Q5 | 200 on `/v1/otlp/*`, 202 on `/v1/events`. DATAMODEL §6.1 amended. |
| R28 | Observation-gap heartbeat | backend Q8 | Ingest owns it: idle gateways/SDKs send an empty OTLP batch every 10 s. No heartbeat route. |
| R29 | Verdict on hysteresis-resolved alerts (D24) | backend Q7 | `resolved` with `verdict=null` allowed; console keeps an "unverdicted" queue; SLI counts them. D24 is satisfied because a human never closes without a verdict. |
| R30 | Backup retention for erasure certificate: D26 says 7 d, DATAMODEL tenant default 35 d | sec Q7 | **Tenant column default becomes 7** per D26; certificate prints the tenant column. DATAMODEL amended. |
| R31 | Human kill-rate cap | sec Q8 | Adopt the alternative: no numeric cap for OIDC owners; a second tenant-scope kill within 10 min requires a different owner. Break-glass key caps (3/10 min, 6/h) stand. |
| R32 | Chaos knobs location | writer Q4 | Separate simulator service with its own port; control plane exposes nothing demo-only. Docs say `sibyl-sim` CLI. |
| R33 | Offline audit verification | writer Q5 | `sibyl audit verify` in the Apache-2 SDK CLI. `GET /v1/policy/keys` and `/.well-known/sibyl-keys.json` unauthenticated, cached 5 min (sec Q2, ai-eng Q3 fetch-once-and-pin with `next_key`). |
| R34 | Continuity plan shape | writer Q2 | Sub-resource `PUT /agents/{id}/continuity-plan` with ETag/If-Match, as backend modelled. |
| R35 | Tier-1 requires agent-bound keys | sec Q6 | **Confirmed as a hard constraint.** Snapshot builder refuses tier-1 agents reachable only via tenant-level keys. |
| R36 | Four-eyes on human-initiated tier-1 backup-agent failover | backend Q3 | Confirmed; matches D13 clarification. |

## Accepted without conflict
- Tenant lifecycle CLI-only in Phase 1 (backend Q1).
- D22 predicate = data-source edges `classification ∈ {pii, restricted}` or `residency_region` set, or tag `pii` (backend Q6).
- Default scopes on agent-bound keys: `ingest:write routing:read handoff:write` (ai-eng Q4, renamed per R21).
- `/v1/otlp/logs` kept, scoped to the four `event.name`s (ai-eng Q6). `sibyl.checkpoint()` is Phase 1 (ai-eng Q8).
- Human permission strings for SSE/reference pages come from security §3 route table (writer Q6).

## DATAMODEL amendments requested (database-architect to apply at Step 7 start)
1. `idempotency_record` table (63rd), 24 h retention (backend Q4).
2. `ingest_batch_seen` table; `tenant.ingest_rate_limit` column; `events_rejected.reason` += `env_mismatch`, `agent_not_permitted` (ai-eng Q7).
3. `audit_anchors.kind` += `break_glass`; outbox topic `anchor_now` (sec Q5).
4. `api_key.scopes` CHECK re-enumerated to the R21 catalogue; key prefix `sbl_`.
5. `tenant.backup_retention_days` default 35 → 7 (R30). OTLP response 202 → 200 (R27).
6. `agent_id` nullable on `provider.status` / `observation.gap` events (ai-eng, additive in `sibyl-event/1`).

## Open questions for the founder (defaults the council proceeds on)
1. R21 scope rename accepted over the frozen Step 3 names? Default: yes.
2. R26: no platform-level gateway credential even for the Sibyl-hosted gateway (N keys per gateway)? Default: yes.
3. R35: tier-1 agents must use agent-bound keys (onboarding friction vs impersonation defence)? Default: yes.
4. R29: auto-resolved alerts may close with a null verdict plus a follow-up queue? Default: yes.
5. R31: second tenant-wide kill within 10 min needs a different owner, instead of a hard cap? Default: yes.
6. Python SDK first, TypeScript interface only in Phase 1? Default: yes.

## Next
Step 5 — ML approach: ai-engineer leads (contract in `datamodel/ai-engineer.md` §6 and R29 training-set rule); database-architect for feature storage; sre-engineer for health-score SLI; qa-expert for evaluation harness. Waits for the founder's review of Step 4.
