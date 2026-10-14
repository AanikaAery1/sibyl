# Step 4 — APIs + SDK: chair position (2026-10-10)

Inputs: `docs/BRIEF.md`, `docs/council/DECISIONS.md` (D1–D29), `docs/council/architect/ARCHITECTURE.md` (13 ADRs), `docs/council/datamodel/DATAMODEL.md` (62 tables), `datamodel/ai-engineer.md` (event schemas), `datamodel/security-auditor.md` (RBAC, audit taxonomy).

## Chair position
1. **Rename first.** All `vigil*` identifiers become `sibyl*` in this step (D19): `sibyl-event/1`, `sibyl.*` OTel attributes, package `sibyl-sdk`, Python module `sibyl`.
2. **Three API surfaces, one OpenAPI document per surface:**
   - **Gateway data plane** (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`): OpenAI-compatible only (D16). Sibyl-specific behaviour via `X-Sibyl-*` request headers and response headers; never new JSON fields on the OpenAI body.
   - **Control plane** (`/api/v1/...`): tenant-scoped REST + SSE. Resource-oriented, cursor pagination, RFC 9457 problem details, idempotency keys on every POST that creates or transitions state, ETag/If-Match on policy objects.
   - **Ingest** (`/v1/otlp/traces`, `/v1/otlp/logs` and `/v1/events`): OTLP/HTTP protobuf+JSON for SDK/collector, plus a thin JSON `sibyl-event/1` batch endpoint.
3. **SDK** (Python first, TypeScript interface sketched): zero-config `sibyl.init()` that wraps OpenAI/Anthropic clients via OTel GenAI instrumentation; explicit `sibyl.agent(...)` context manager; `sibyl.handoff.packet(...)` helper; never blocks the caller (buffered, bounded, drop-oldest).
4. **AuthZ is per route, enumerated.** Every route lists the required scope from the Step 3 RBAC matrix; API keys carry scopes; the break-glass key (D20) hits exactly one route.
5. **Failover/handoff/kill switch routes are state-machine transitions**, not CRUD: `POST /incidents/{id}/actions` with an action enum, 409 on illegal transition, every call audited.
6. Phase 1 scope only: no `/v1/messages`, no notification routes, no ML routes beyond `GET .../health` and `GET .../risk`.

Members: backend-architect (control-plane + gateway OpenAPI), ai-engineer (SDK + ingest contract), security-auditor (authz per route, threat review of the surface), technical-writer (quickstart). Each writes `docs/council/api/<member>.md`. Chair synthesizes `SYNTHESIS.md` and the consolidated `API.md`.
