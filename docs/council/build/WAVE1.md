# Wave 1 + G0 fix pass (started 2026-10-10)

Read `docs/council/build/LANES.md` first (local env, rules, rulings B1–B6, G0-1..G0-10). Authoritative design: `docs/council/api/API.md`, `docs/council/ml/ML.md`, `docs/council/datamodel/DATAMODEL.md`, `docs/council/roadmap/ROADMAP.md` §4–§5, decisions D1–D46. Where docs disagree with merged code, the **code + rulings win**; record the conflict.

## Running lanes
| Lane | Where | Owns (only these paths) |
|---|---|---|
| FIX-DB | main tree | `services/control/migrations/**`, `services/control/src/sibyl_control/migrate/**`, `services/control/tests/db/**`, `rules/v1/**` |
| FIX-KER | main tree | `services/control/src/sibyl_control/{core,api,worker}/**` **except** module dirs owned by wave 1 lanes below, `services/control/tests/{core,contract}/**`, `openapi/**`, `services/gateway/src/sibyl_gateway/policy/**` |
| FIX-SCH | main tree | `packages/sibyl-schemas/**` |
| FIX-INF | main tree | `deploy/**`, `ops/**`, `ci/**` |
| G gateway & snapshot | worktree | `services/gateway/**` (except `src/sibyl_gateway/policy/view.py`, frozen; request changes), `services/control/src/sibyl_control/api/snapshot/**`, `services/control/tests/api/snapshot/**` |
| H health engine | worktree | `services/control/src/sibyl_control/worker/{rollup,scoring,status_poller}/**`, `services/control/tests/worker/{rollup,scoring,status_poller}/**` |
| R registry & policy | worktree | `services/control/src/sibyl_control/api/{registry,policy,credentials}/**`, `services/control/src/sibyl_control/cli/seed.py`, `services/control/tests/api/{registry,policy,credentials}/**`, `services/control/tests/cli/test_seed.py` |
| I ingest & blob | worktree | `services/control/src/sibyl_control/ingest/**`, `services/control/src/sibyl_control/core/blob/{fs.py,s3.py}`, `services/control/tests/ingest/**`, `services/control/tests/core/blob/**` |
| A auth → V reads/SSE | worktree | `services/control/src/sibyl_control/api/{auth,tenancy,keys,reads,sse}/**`, `services/control/src/sibyl_control/cli/{tenant.py,keys.py,__init__.py,__main__.py}`, `services/control/tests/api/{auth,tenancy,keys,reads,sse}/**`, `services/control/tests/cli/{test_tenant.py,test_keys.py}` |
| C console (pulled forward at the founder's request) | worktree | `console/**` (Next.js app, its own package.json/lockfile, Dockerfile, tests) |
| K SDK → D sim doubles | worktree | `packages/sibyl-sdk/**`, `sibyl-sim/src/sibyl_sim/{doubles,status_feed}/**`, `sibyl-sim/tests/{doubles,status_feed}/**` |

## Rules for every lane
1. Touch only your paths. Steward-owned: root `pyproject.toml`, `uv.lock`, `Makefile`, `.importlinter`, `services/control/pyproject.toml`, `api/routers.py`, `api/app.py`, `worker/loops.py`, `worker/main.py` (FIX-KER may edit the last four). Need a dependency, router hook, loop registration or migration column? Write it under "Change requests" in your hand-back; don't edit.
2. Never run `uv lock`, never `ruff format .` or `ruff check --fix .` repo-wide: format and fix **your paths only**.
3. Fix-pass lanes share one working tree: other lanes' tests may fail transiently while they work. Run your own tests while working; run full `UV_SYSTEM_CERTS=1 bash ci/run.sh` at the end and report anything failing outside your paths without fixing it.
4. TDD: failing test first. Every API route you implement must turn its generated authz-wall and audit-completeness cases green (they are `xfail(strict=False)`, so a pass shows as XPASS) and get real handler tests against a migrated PG17 database (own DB name `sibyl_<lane>_<hex>`, dropped after).
5. Wave 1 lanes code against the merged kernel at HEAD `2e5bf1e`. The fix pass will change some kernel internals (idempotency claim fencing, outbox topic validation, audit actor for API keys, object-rule enforcement); use the public helpers (`tenant_tx`, `guard`, `authorize`, `audit_actor`, idempotency store, outbox writer) rather than reimplementing them, so the chair can reconcile at merge.
6. No commits, no pushes. Hand back: files, test counts, XPASS counts for your routes, and "Assumptions / change requests".

## Console design direction (The founder, 2026-10-10)
Apple design language with glassmorphism across the entire application ("macOS Liquid Glass"): light grey-white ground, white surfaces with hairline dividers, frosted glass only where layers overlap, restrained SF-style typography with negative tracking, color reserved for semantic state (health bands, tiers, severities), springy interruptible motion with reduced-motion support. Dark mode intentional, not inverted. The console runs in a labelled **demo-data mode** against the frozen OpenAPI contract until each backend route lands, then switches per route to the real API through its BFF.
