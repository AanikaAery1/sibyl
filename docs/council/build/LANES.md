# Step 7 build lanes

Authoritative plan: `docs/council/roadmap/ROADMAP.md` §4 (repo tree, waves, gates) and `roadmap/SYNTHESIS.md` R52–R71. Where ROADMAP's editor used `apps/` paths, this file wins: the simulator lives at `sibyl-sim/`, the console at `console/`.

## Local environment
- Python 3.13 via uv workspace (`make sync`). This network re-signs TLS, so export `UV_SYSTEM_CERTS=1` (the Makefile does). Never disable TLS verification.
- Postgres 17 on `localhost:5433`, superuser `postgres`, trust auth, data in `~/.local/share/sibyl/pg17` (`make db-up` / `make db-down`). The Homebrew Postgres 16 on 5432 belongs to other projects: do not touch it.
- Docker runs via **Colima** (context `colima`; 4 CPU / 8 GB / 60 GB VM built from a local Ubuntu 24.04 image because GitHub release downloads are blocked here). `docker compose` works; images pull from Docker Hub and ghcr.io. Image builds that download packages need the corporate TLS-inspection CA via an optional BuildKit secret (`SIBYL_EXTRA_CA_FILE`, bundle at `~/corp-ca.pem`); never bake it into a layer. Colima autostarts at login (`brew services`); restart with `brew services restart colima`.
- Each lane uses its own database on 5433 named `sibyl_<lane>` (e.g. `sibyl_w0db`). Only the W0-DB lane creates cluster roles (`sibyl_app`, `sibyl_ingest`, `sibyl_worker`, `sibyl_audit`, `sibyl_routing`, `sibyl_migrate`); other lanes must not create roles with these names.

## Rules
1. One directory, one owner per wave. Touch nothing outside your lane's paths. Steward-owned root files (`pyproject.toml`, `uv.lock`, `Makefile`, `.importlinter`) change only at a gate; a lane that needs a dependency adds it to **its own package's** `pyproject.toml` and notes it in its hand-back.
2. TDD: write the failing test first, then the code. Every lane ships tests that pass with `uv run pytest <your paths>`.
3. Lanes never commit or push. The chair commits each lane at the gate after review (D45).
4. Record every assumption made against a frozen contract in your hand-back under "Assumptions / change requests".

## Wave 0: contract freeze (target 4 working days)

| Lane | Owner (council role) | Paths owned | Done when |
|---|---|---|---|
| W0-SCH | ai-engineer | `packages/sibyl-schemas/**` | value sets, JSON Schemas, pydantic models, RFC 8785 canonicaliser, secrets-scrub registry with corpora, golden fixtures; all fixtures validate; scrub corpus 100 % hit, 0 false positives |
| W0-DB | database-architect | `services/control/migrations/**`, `services/control/src/sibyl_control/migrate/**`, `services/control/tests/db/**`, `rules/v1/**` | all Phase 1 tables with Step 4/5 amendments folded (R59); RLS isolation generator, audit-chain, `routing_apply` edge and erasure-cascade-completeness tests green on PG17 |
| W0-KER | backend-architect | `openapi/**`, `services/control/src/sibyl_control/{core,api,worker}/**` (except `migrate/`), `services/control/tests/{core,contract}/**`, `services/gateway/src/sibyl_gateway/policy/**` | OpenAPI complete for Phase 1 and linted; core kernel modules with unit tests; every API module a registered 501 stub; authz red wall + audit-completeness tests generated from OpenAPI (expected red); `PolicyView` protocol frozen (R62) |
| W0-INF | deployment-engineer | `deploy/**`, `ci/**`, `ops/**` | compose (postgres 17, dex with 3 tenants × personas per D29/R56, caddy, service entrypoints with `/healthz`, `sim` profile), statically validated; `ci/` local pipeline script (ruff, import-linter, mypy, pytest + coverage) runnable via `make ci`-ready script; lane worktree helper with port offsets |

**Gate G0:** chair merges lanes, reconciles change requests (scope catalogue in `sibyl_schemas` becomes the single source for `core/authz`), runs the full suite, test-automator + code-reviewer + security-auditor review the merged diff, then commit and the founder's M0 review.

## Status
| Lane | Status |
|---|---|
| Scaffold (steward) | done: uv workspace, five packages, import-linter contracts, Makefile, PG17 dev instance |
| W0-SCH | **merged** to main: `sibyl-schemas` 1.0.0 (Apache-2): 38-scope catalogue, value sets, 12 outbox topics / 2 channels, problem codes, 9 JSON Schemas + pydantic models (three-way agreement on every fixture), RFC 8785 canonicaliser, 18-detector scrubber (65/65 secrets, 0/42 false positives), 118 golden fixtures incl. Ed25519 snapshot vectors; 679 tests, 99 % coverage |
| W0-DB | **merged** to main: 16 plain-SQL migrations, 76 tables (65 tenant + 11 allowlisted), RLS on every tenant table, `audit_append`/`audit_verify` hash chain, `routing_apply` over `state_edge` (560 combinations tested), `tenant_create`, `tenant_key_rotate`, `tenant_key_shred`, erasure cascade + R63 ledger re-apply, outbox with xid8 commit-order reader and 2 NOTIFY channels, rules v1 seed; migration runner (`python -m sibyl_control.migrate`, refuses superuser/edited migrations); 96 DB tests |
| W0-KER | **merged** to main: OpenAPI 3.1 (143 operations / 111 paths, generated from `openapi/sibyl_openapi` with drift check); core kernel (db+set_tenant, authz, `sbl_` keys, problems, idempotency, ETag, paging, rate limit, audit, outbox 12 topics/2 channels, Ed25519 + envelope crypto, BlobStore); 15 API modules as registered 501 stubs; 15 worker loops; `PolicyView`; 718 generated authz/audit cases xfail until wave 1 |
| W0-INF | **merged** to main: compose (postgres, dex, caddy, control ×4, gateway, console, sim profile) runs healthy under Colima; 3 images build through the proxy with build-time-only CA; `ci/run.sh` 7 steps green; backup/restore with R63 re-shred hook |

## Build-phase chair rulings
| # | Ruling |
|---|---|
| B1 | `certifi` (MPL-2.0) accepted as a runtime dependency: used unmodified, MPL copyleft is file-level only. Stays flagged in the licence inventory; any modification needs review. |
| B2 | Native dev ports for control services are 8010/8011/8012 (containers keep 8000–8002); quickstart uses the Caddy URLs https://localhost:8443 (console + API), :8444 (gateway), :8445 (ingest). |
| B4 | Policy snapshot size budget: ≤ 2 MiB **gzipped transfer** and ≤ 3 MiB raw canonical JSON (worst case 2,000 agents = 2.64 MB raw / 39 KB gz). The gateway verifies the Ed25519 signature over the **raw bytes received**, never re-canonicalising, to hold the 20 ms verify budget. |
| B5 | The SDK's `PolicySnapshot.state` uses the seven routing states, not the stub's `failover`/`held` vocabulary. |
| B6 | Synthetic secret fixtures under `packages/sibyl-schemas/fixtures/scrub/` may trip GitHub push protection; handle at first push (which needs the founder's approval anyway) by allowlisting that path, never by weakening the corpus. |
| B7 | The KEK is granted to **ingest** as well as api and worker: ingest envelope-encrypts payload blobs when it writes them (encryption at rest, D7/D12). |
| B8 | Scrubber budget: each detector ≤ 200 ms CPU per MiB (measured ~100 ms); a whole scrub with all decoded views ≤ 6 s CPU per MiB worst case (JSON-escaped + percent-encoded + format characters at once), ~0.26 s per MiB for ordinary text. Accepted: dropping views would reopen known leaks. Matches longer than 16 KiB may leak a tail at a window boundary (no real credential is that long). |
| B9 | Key-set signing: the kernel builds and verifies the signed rotation chain (`core/crypto/signing.py`); the G lane serves it on the key routes and mirrors the verifier in the gateway. |
| B10 | Snapshot verification trusts every key in the accepted key set that is `active` or `retiring` until its `not_after` (schemas reference behaviour), so rotation overlap works; the kernel `KeySetVerifier.public_key` is aligned to this. Key rotation needs a pre-published `next` signing-key state and a history of issued key sets so a freshly pinned gateway can catch up (`/policy/keys?since=<sequence>`). |
| B11 | One DEK-wrap convention lives in `core/crypto` (AAD binds tenant, purpose and version; credential ciphertext AAD binds credential id); lanes R, G, A and I use it. |
| B12 | The gateway holds the key pepper (it authenticates API keys against snapshot entries) and a pinned first signing key; gateway env: `SIBYL_KEY_PEPPER`, `SIBYL_SNAPSHOT_PINNED_KEY_FILE`, `SIBYL_SCRUB_SALT`, `SIBYL_INGEST_KEY`, `SIBYL_DEV_HOSTS`, `SIBYL_GATEWAY_ID`. |
| B13 | Provider-scope kill switches use the provider id as `scope_id`. The operator queue exposes a `completed_despite_failure` counter (queue summary) for demo beat B6. |
| B14 | Jobs infrastructure (job table, `job.requested` event, jobs worker loop, `getJob`) is built now by the integration lane; `verifyProviderCredential` runs as a job (never inline). `generateAgentBom` stays cut to Phase 1.5 (Tier A1). |
| B15 | `@axe-core/playwright` / axe-core (MPL-2.0) accepted as dev/test-only; never bundled. Console ESLint config lives at `console/lint/eslint.flat.mjs` (a local hook protects the standard path). |
| B16 | Under the frozen noisy-OR (r = severity × cap / 100, caps ≤ 30) a single leading rule cannot reach the `"0.60"` band; only rule combinations or a carried degraded/failed band do. Accepted as intended: one weak signal must not drive an automated failover. |
| G0-12 | `audit.exported` stays human/api_key at request time (`export_sha256` null); new `audit.export_completed` (actor system) carries the hash and anchor id. `erasure.blocked_by_hold` allows {system, human, api_key}. |
| B18 | `/api/v1/policy/snapshot` and `/api/v1/policy/keys` are served on the public origin (API-key authenticated / public keys) so the SDK can honour kill switches; only `/api/v1/policy/credentials` (sealed bundle) stays gateway-only. |
| B19 | An undo does **not** clear the pre-emptive breaker (an undo is evidence toward a trip). Clearing is a deliberate operation: `POST /api/v1/agents/{agent_id}/preemptive-breaker/clear` with a reason, scope `routing:override`, step-up, rules group + tenant role, audit `preemptive.breaker_cleared`. |
| B20 | One source for the D36 gate: the deployment setting `SIBYL_PREDICTED_AUTOMATION_BAND` (`Settings.predicted_automation_band`), set only from harness evidence; it is a release criterion, never tenant-tunable, so prediction and the saga both read Settings, not `scoring_config`. |
| B21 | `access.break_glass` allows actors {system, api_key}; key-initiated break-glass records the key. Export anchors made by jobs are published to the BlobStore like loop-made ones. |
| B3 | The On-call Operator is bound in `meridian` and `northstar` only; `sandbox` stays empty except the Platform Admin (onboarding demo). |

## G0 reconciliation list (**done** 2026-10-10: items 1–4, 6 resolved by the G0 integration pass; 5 resolved by the tenant-key routes; 7–9 carried to wave 1)
1. Single sources (canonicaliser **done**: kernel now delegates to `sibyl_schemas.canonical`, byte-identity test added): scope catalogue + role matrix (`core/authz.py`), audit taxonomy (`core/audit.py`), OpenAPI enums (`openapi/sibyl_openapi/enums.py`) and canonicaliser (`core/canonical.py` fallback) all import from `sibyl_schemas`; DB `role_permission` / `audit_action` seeds generated from the same source.
2. Audit taxonomy additions: `erasure.cancelled`, `handoff.lock_extended`, `handoff.claim_released`, `credential.bundle_issued`; human actor allowed on `handoff.created`, `approval.requested`.
3. DB shapes assumed by the kernel: `idempotency_record`, `outbox` (xid8 default), `api_key_lookup(prefix)`, `P0001` + `sibyl:<code>` raises (sent to W0-DB).
4. `x-sibyl-key-scopes` is an array (supersedes API.md §11 single string).
5. ~~`keys:rotate` has no route~~ **resolved (The founder, 2026-10-10)**: `GET /tenant-keys` (new scope `keys:read`, owner + security_admin) and `POST /tenant-keys/{purpose}/rotate` (`keys:rotate`, step-up, idempotent, 6/h, audit `tenant_key.rotated`) added; 145 operations / 113 paths. W0-SCH and W0-DB told to add `keys:read` and a `tenant_key_rotate` function.
6. Move the OpenAPI document into `sibyl-schemas` (R70), load via `importlib.resources`.
7. `jobs` worker loop (BOM, credential probes, audit verify/export, data export) needs an owning lane in wave 1.
8. Containers must set `SIBYL_HTTP_PORT` explicitly (8000 api, 8001 ingest, 8002 worker).
9. Contract suites need a seeded `contract_world` fixture at G1, then xfail → strict.

## G0 chair rulings
| # | Ruling |
|---|---|
| G0-1 | DB errors use SQLSTATE class `SB` + message prefix `sibyl:<code>`; the kernel maps on the prefix, never `P0001`. Transition error code is `invalid_transition`. |
| G0-2 | `idempotency_record` uses column `idempotency_key` and is unpartitioned; the kernel's Postgres store targets the real table. |
| G0-3 | Routing edges added by W0-DB accepted: `undo` inverts every automated edge; operator self-edges for `clear_hold`; `failed_over→failed_over`, `failing_back→failing_back`. |
| G0-4 | Audit widening accepted; break-glass `killswitch.pulled` records actor kind `api_key` with its key id, never `system`. |
| G0-5 | One code for a plain 403: **`forbidden`** stays (kernel + OpenAPI); `access_denied` is removed from schemas before release. |
| G0-6 | **Every** API-key principal (gateway keys included) is audited as actor kind `api_key` with its key id; `system` is reserved for the worker. `failover` gains `actor_key_id`. |
| G0-7 | An agent named as backup in another agent's **active** approved chain cannot be erased until that chain is retired (409 `erasure_blocked_by_chain`, also checked when the erasure request is created). An agent referenced only by **retired** chains is erasable: the step keeps a tombstone (`target_erased = true`, FK nulled). Wave 1 R lane. |
| G0-8 | Idempotent responses: JSON replay is semantically equal, not byte-equal (accepted). Stored bodies are capped at 64 KB; a larger response stores status + headers + body hash only, and a replay returns 409 `idempotent_replay_unavailable`. `principal_kind` is required (no default). Wave 1 A lane. |
| G0-9 | Contract versions bump to **1.1.0** (`CONTRACT_TAG = contracts-v1.1.0`, OpenAPI `info.version`), the version frozen at M0. |
| G0-11 | `access.denied` records the attempting principal's actor kind (`human` or `api_key`); `system` only when the request could not be authenticated. Every action that allowed actor `agent` also allows `api_key` (G0-6 follow-on). |
| G0-10 | Seeds stay hand-written SQL guarded by drift tests for now; generating them from schemas (like `rules_seed`) and diffing the 13 API-only enums against DB CHECKs are wave 1 follow-ups (steward). |

## Wave 1 + G0 fix pass
See `docs/council/build/WAVE1.md` for lane ownership and rules. Reviews: `docs/council/build/reviews/G0-{code,security,tests}.md`.

## Backlog (post-merge API asks, 2026-10-11)
From the console live-wiring lane (C2), not yet built:
1. `order=desc` / `before_seq` on `/audit/events` and `/audit/anchors`.
2. Agent summary/detail: `routing.operator_hold_until`, `health.provisional`, primary provider/model, `continuity.has_plan` (or amend the contract).
3. Embed memberships in `GET /users` (`include=memberships`).
4. Health-snapshot-by-id read (decision record factors behind a routing move).
5. Move `_hysteresis` / `_clamp` out of `factors[]`; `feature_snapshot_ref` nullable; `horizons` may be empty; `/risk` `recommended_action` nullable.
6. `GET /audit/exports/{id}/download` gated by `audit:export`.
7. Expose the deployment key `env` (e.g. in `/auth/me`) so the console drops `SIBYL_KEY_ENV`.
8. OIDC callback/step-up failure redirects back to the console with `?error=oidc_failed`.
9. Optionally revoke earlier sessions on fresh login.

## Wave 3 chair rulings (2026-10-12)
| # | Ruling |
|---|---|
| B23 | `silent_drift` and `model_change` are the only drift alerts; the `drift_cusum` factor is score-only (visible, cap 0, never fires its own alert). |
| B24 | Superseded drift baselines and drift reports are purged 30 days after supersession/creation. |
| B25 | Gateway fallback is same-protocol only; a route with no same-protocol target is refused 400 `sibyl_bad_request` at decision time. No cross-protocol translation. |
| B26 | `gemini` is a provider dialect everywhere (schemas, snapshot schema, DB check, OpenAPI), landed with the PLUG migration. |
| B27 | Merge order for migrations 0018–0022: the last migration that redefines `erasure_cascade()` carries every wave-3 tenant table; pinned scope/operation/path counts are summed at merge. |
| B28 | `X-Sibyl-On-Behalf-Of` accepts `user:<uuid>`, `external:<ref>` or the frozen JSON shape; SDK sends the shorthand; the body field `on_behalf_of` is the frozen object. |
| B29 | Provider naming: gateway events carry the registry provider name; SDK events carry the OpenTelemetry `gen_ai.system` value (`openai`, `anthropic`, `gcp.gen_ai`). Drift keys on the value as received. |
| B30 | Action counter windows are keyed by the stable `policy_id` and survive re-versioning (fail closed: a new version cannot reset a cap). |
| B31 | Backlog: validate that an `on_behalf_of` user exists in the tenant (422 → the hold fails closed); `/action-summary` counts only control-plane decisions, local snapshot blocks are reported by telemetry. |
| B32 | Backlog: a held action naming a deactivated `on_behalf_of` user is refused like an unknown user. |
| B33 | Backlog: gateway and SDK switch to the single key-set follower in `sibyl_schemas.keyset`. |
| B34 | Cold-start cap: a detected failure floor lifts the provisional cap when the agent has a plan, fresh rollups and coverage, and is older than `min_age_days` **or** served ≥ 50 healthy calls in the last hour (`hard_failure_min_ok_1h`). Agents failing since their first call stay capped. |
| B35 | B-08: an outage fully masked by inline fallback is attributed to the primary and reaches `failed` through R4 with a reroute recommendation; no saga is started for a masked outage. |
| B36 | B-09 fixed: `HeldActionStatus.decided_at` and `reason` accept null while pending, so SDK escalations can wait for a human decision. Agent keys need `actions:hold` (quickstart updated). |
| B37 | Discovered (unconfirmed) agents are never routed or failed over until an admin confirms them; the Action Gate, quarantine and kill switch still apply to them. Copy says "never routed or failed over", never "never gated". |
| B38 | Known issue: harness smoke scenarios use wall-clock deadlines and can miss them under heavy CPU load (S-01, S-09 failed during a concurrent CI run and passed when re-run alone). Backlog: run the smoke suite on an isolated runner or scale deadlines by measured tick lag. |
