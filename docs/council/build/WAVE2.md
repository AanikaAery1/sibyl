# Wave 2 + integration (started 2026-10-11, main @ fbf2431)

Wave 1 is fully merged. Read `docs/council/build/LANES.md` (env, rulings B1–B15, G0-1..G0-11), `docs/council/build/G0-CHANGES.md` (kernel/DB interfaces), and the design docs (`docs/council/api/API.md`, `ml/ML.md`, `datamodel/DATAMODEL.md`, `roadmap/ROADMAP.md` §4–§7). Code + rulings beat docs where they disagree; record the conflict.

Reuse what exists: kernel (`core/`, `api/deps.py`), the registry lane's handler kit `api/registry/_kit.py` (tenant tx with retry, `audit_lock` first, fenced idempotency, ctx object rules, ETag, cursors, outbox), auth lane's `api/auth/common.py`, health engine extension points `worker/scoring/extensions.py`, ingest, gateway, SDK, `sibyl-sim` doubles.

## Lanes (each in its own worktree off fbf2431)
| Lane | Owns |
|---|---|
| INT-1 integration (backend) | `services/control/migrations/**`, `migrate/**`, `tests/db/**`, `rules/**`, `core/**`, `openapi/**`, `packages/sibyl-schemas/**`, `api/{app,routers,deps,middleware,_stubs,contract}.py`, `api/reads/jobs*.py` (getJob only), `worker/{main,loops}.py`, `worker/jobs/**`, `tests/{core,contract}/**`, `tests/worker/jobs/**`; delegated: the DEK-wrap call sites in `ingest/`, `api/auth/`, `api/registry/`, `api/credentials/`, `api/snapshot/` (B11 only) |
| INT-2 integration (infra) | `deploy/**`, `ci/**`, `ops/backup/**` |
| S saga & operations | `api/{incidents,approvals,killswitch,queue}/**`, `worker/{saga,approvals,failback,handoff}/**`, `tests/api/{incidents,approvals,killswitch,queue}/**`, `tests/worker/{saga,approvals,failback,handoff}/**` |
| P prediction & alert loop | `api/alerts/**`, `worker/{predict,alerts}/**`, `tests/api/alerts/**`, `tests/worker/{predict,alerts}/**` |
| U audit & governance | `api/governance/**`, `worker/housekeeping/**`, `packages/sibyl-sdk/src/sibyl/cli/**`, `packages/sibyl-sdk/tests/cli/**`, `tests/api/governance/**`, `tests/worker/housekeeping/**` |
| M harness | `sibyl-sim/src/sibyl_sim/{harness,actors,oracle,scenarios,golden,reports}/**`, `sibyl-sim/tests/{harness,scenarios}/**`, `sibyl-sim/src/sibyl_sim/doubles/cli.py` (add a `run` subcommand only) |

Paths above are under `services/control/src/sibyl_control/` and `services/control/tests/` unless shown in full.

## Rules
Same as WAVE1.md rules 1–6: own paths only; dependencies, migration columns, router/loop hooks and taxonomy changes go to INT-1 as change requests in your hand-back (INT-1 is running concurrently; the chair reconciles). Never `uv lock`, never repo-wide format. TDD; each route turns its authz-wall/audit cases green and has PG17 handler tests. No commits.
