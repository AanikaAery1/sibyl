# G0 test-quality review (test-automator)

Scope: `git diff 681f181..HEAD` (wave 0 merge plus the G0 single-source pass). Rulings G0-5 to G0-10 are out of scope.
`$SCRATCH` below is this session's scratch directory (a temporary directory). It is ephemeral, which is why the appendix carries the test code.

Method: I read the suites, ran the pipeline's pytest step, and ran **42 mutation probes** in a scratch copy of the repo (`$SCRATCH/mut/base`, with its own `uv` venv; the repo was never edited). For each surviving mutant I wrote a candidate test in the scratch copy. I then checked that the candidate passes on unmodified code and fails on the mutant. I also ran a bypass battery against the secrets scrubber and a differential check across the three JCS canonicalisers.

## Verdict

The suites are mostly structural, and the structural half is strong. The generated RLS sweep, the routing edge matrix, cascade-covers-every-table, drift-vs-schemas and the authz unit tests all killed every mutant aimed at them. The behavioural half has holes in places where a regression would be silent and expensive:

- Tamper detection in `audit_verify` runs two of its four checks (hash recompute and the prev-link) without any test that depends on them.
- Agent-scope erasure is effectively untested. The fixture puts no data on the agent that gets erased.
- 8 of the 9 state machines have no edge test at all. Their triggers can be deleted and the suite stays green.
- The outbox cursor is never paged. Both the tie-break and the ordering can regress.
- With PostgreSQL down, CI still goes green: 101 DB tests are skipped and coverage reports 94 %.
- The xfail wall counts a crashing harness as "expected red".

None of these need new infrastructure. The 19 candidate tests in the appendix kill every surviving mutant except two equivalent ones and add about 1 s of runtime.

## Mutation scoreboard

Harness: `$SCRATCH/probes/{mutants.py,harness.py}`. It applies one textual mutant, runs the named targets with `-x`, then reverts. Results: round 1 used the existing suite; round 2 used the existing suite plus the candidate tests.

| Area | Mutant | Existing suite | With candidate tests |
|---|---|---|---|
| RLS | drop `FORCE ROW LEVEL SECURITY` in `enable_tenant_rls` | killed (`test_rls_structure`) | |
| RLS | `label` policy `USING (true) WITH CHECK (true)` | killed | |
| RLS | `label` policy `WITH CHECK (true)` only | killed | |
| RLS | `api_key` policy `OR current_user LIKE 'sibyl_%'` | killed | |
| RLS | `set_tenant` uses `set_config(..., false)` (session-scoped) | **survived** | killed |
| RLS | materialized view over `agent` granted to `sibyl_app` | **survived** | killed |
| Audit | `audit_verify` skips the `hash = sha256(prev‖env‖detail)` check | **survived** | killed |
| Audit | `audit_verify` skips the `prev_hash = running` link check | **survived** | killed |
| Audit | verify trusts the stored `detail_sha256` | killed | |
| Audit | envelope drops `occurred_at` | killed (Python re-implementation) | |
| Routing | extra edge `killed→active (rule)` in the seed | killed (drift test only) | |
| Routing | `trg_state_edge` lets any `operator` edge through | survived (masked by `routing_apply`'s own check; equivalent today) | survived |
| Machines | `kill_switch` state trigger dropped | **survived** | killed |
| Machines | `erasure_request` state trigger dropped | **survived** | killed |
| Erasure | `events` agent predicate → NULL (agent scope keeps events) | **survived** | killed |
| Erasure | `label` agent predicate → `true` (over-deletion) | killed | |
| Erasure | `erasure_residue` never reports anything | **survived** | killed |
| Erasure | R63 re-apply skips `objects_deleted` for agent scope | **survived** | killed |
| Erasure | a table dropped from `erasure_cascade()` | killed | |
| Outbox | cursor `(xid,id) > (…)` → `xid > …` | **survived** | killed |
| Outbox | `ORDER BY o.xid, o.id` → `ORDER BY o.id` | **survived** | killed |
| Outbox | horizon removed | killed | |
| Idempotency | claim overwrites a live record (`WHERE` → always true) | **survived** | killed |
| Idempotency | `_SELECT` without `FOR UPDATE` | survived (equivalent: the claim re-checks) | survived |
| API keys | hash ignores the last secret character | killed | |
| API keys | `rotating` with NULL grace accepted | **survived** | killed |
| API keys | unknown status (`suspended`, `''`) accepted | **survived** | killed |
| Authz | keys ignore route `key_scopes`; break-glass misuse unchecked; step-up window ignored; future `step_up_at` accepted; ungrouped reachable by a group grant; self rule for anyone | 6/6 killed | |
| Wall | wall harness raises `KeyError` for every request | **survived** (727 "xfailed") | killed with `raises=AssertionError` |
| JCS | `sibyl.jcs` key order reversed | killed (`test_helpers`) | |
| Drift | viewer gains `keys:read`; new value in `RoutingState` / `KillSwitchState` / `ErasureState` | 4/4 killed (schemas / OpenAPI drift) | |
| Drift | the same 3 enum additions with only the DB suite as the judge | **3/3 survived** | (see F12) |

Score on the existing suite: 24 of 42 killed. Of the 18 survivors, 2 are equivalent mutants (operator-edge trigger, `FOR UPDATE`), and 16 reveal a real gap; the candidate tests kill all 16 of those.

## Findings

Severity follows `rules/common/code-review.md`.

### HIGH

**F1. CI goes green when PostgreSQL is down.**
- Where: `services/control/tests/db/conftest.py:111-112` (`pytest.skip`), `services/control/tests/core/test_db_pg.py:43`, `ci/tests/test_backup_restore.py:173`.
- Regression that slips through: everything below. I ran `ci/run.sh --only pytest` with `SIBYL_PG_ADMIN_DSN` pointing at a dead port. Result: 1654 passed, **101 skipped**, coverage **94.37 %** (gate 80). The only failures came from an unrelated Colima mount limit in my scratch path; in the repo, that run would be green. The skip message is only shown with `-rs`, and `ci/run.sh` does not pass `-rs`. A second problem: the backup tests read `SIBYL_TEST_PGPORT`, not `SIBYL_PG_ADMIN_DSN` (`ci/tests/test_backup_restore.py:21`). Pointing the DSN elsewhere therefore does not move them.
- Test to add:
  - `ci/run.sh` exports `SIBYL_CI=1` and runs a `pg_isready` preflight (or adds a `db` step).
  - The DB fixtures call `pytest.fail(...)` instead of `pytest.skip(...)` when `SIBYL_CI=1`.
  - A conftest-level `pytest_sessionfinish` guard fails the run if any test outside an allowlist (`SIBYL_CI_DOCKER_BUILD` opt-in) was skipped.
  - `ci/tests/test_scripts.py` gets a case that runs the pipeline with a dead DSN and asserts a non-zero exit.
  - Unify the knobs: the backup tests derive their port from `SIBYL_PG_ADMIN_DSN`.

**F2. `audit_verify` survives the removal of two of its four checks.**
- Where: `services/control/tests/db/test_audit_chain.py:174-185` (the only hash tamper case), `services/control/migrations/0006_audit.sql:218-233`.
- Regression that slips through:
  - Delete the `hash_mismatch` block and the suite stays green. The only hash tamper is on seq 1, and its successor's `prev_mismatch` at seq 2 also satisfies the test, which accepts either `{1, 2}`. The last row's hash, the one no successor guards, can then be rewritten freely.
  - Delete the `prev_mismatch` block and a self-consistent spliced row (forged `prev_hash`, recomputed `hash`) verifies as `ok`, because the hash check uses the row's own `prev_hash`.
- Test to add: `test_rewritten_hash_of_the_last_row_is_hash_mismatch` and `test_spliced_self_consistent_row_is_prev_mismatch` (appendix). Each asserts the exact `(ok, first_break_seq, kind)` triple; neither accepts "either".

**F3. Agent-scope erasure completeness is vacuous.**
- Where: `services/control/tests/db/test_erasure.py:134-163` and `:278-301`; `services/control/tests/db/fixtures.py:713-731`.
- Regression that slips through: `populate_tenant` writes agent-scoped rows **only for `agent_a`**. All 28 tables with `agent_id` have a row for A; B has rows only in `routing_state` and `routing_transition`. Both agent-scope tests erase **`agent_b`** and then check 4 hand-picked tables. As a result:
  - Changing any agent predicate to NULL (agent erasure keeps the agent's events, payload refs, checkpoints and so on) is invisible.
  - Making the R63 re-apply skip `objects_deleted` for agent scope is invisible.
  - The residue function runs the same predicates as the delete, so it cannot catch either.
- Test to add:
  - `test_agent_erasure_removes_every_row_of_that_agent_and_nothing_of_the_other`: generated over every `agent_id` table. It erases the data-bearing agent, requires a non-vacuous fixture, demands zero rows for the victim and an unchanged count for the bystander.
  - `test_ledger_reapply_of_an_agent_erasure_leaves_no_agent_rows`.
  - `test_every_agent_keyed_table_has_an_agent_predicate`.
  - Long term: give `agent_b` a full row set in the fixture, so both directions are covered.

**F4. 8 of the 9 state machines are untested.**
- Where: `services/control/tests/db/test_invariants.py:553-565` checks only that the machine names are seeded. `test_routing_apply.py` covers routing only.
- Regression that slips through: you can drop `trg_kill_switch_state_edge` or `trg_erasure_request_state_edge` and all 121 DB tests still pass. An erasure can then jump `approved → completed` without `keys_shredded` or `verified`, and a released kill switch can be re-pulled or edited arbitrarily. Routing is safe only because `routing_apply` repeats the check (`0008_routing_failover.sql:635`). That also means the trigger's INSERT branch is never tested on its own.
- Test to add:
  - `test_every_machine_is_wired_to_exactly_one_trigger`: structural, from `pg_trigger` against `state_edge`.
  - `test_every_machine_refuses_every_illegal_update`: generated over every machine. Other user triggers are disabled inside a rolled-back transaction; each illegal target, and each named-trigger edge with a bogus trigger, must raise exactly SB010.
  - Follow-up: force each state, as the routing test does, rather than only the fixture row's current state.

**F5. The outbox cursor is never paged.**
- Where: `services/control/tests/db/test_outbox_cursor.py:36-42` (`_read` always uses `limit 1000`) and `:45-74`.
- Regression that slips through:
  - Changing the keyset to `xid > after_xid` skips the rest of a multi-row transaction on page boundaries.
  - Changing to `ORDER BY id` (uuidv7, insert-time order) skips a lower-xid row that was inserted later.

  Both are silent event loss on the `policy` and `killswitch` topics.
- Test to add:
  - `test_paging_through_one_transaction_with_limit_one_misses_nothing`.
  - `test_cursor_orders_by_commit_xid_not_by_id`, where T1 takes its xid first and inserts last.
  - Also add a `p_topics` filter case; that filter is currently untested.

**F6. A committed tenant context could leak to the next pooled transaction, and no test would notice.**
- Where: `services/control/tests/db/test_rls_isolation.py:85-93`. Every `tx()` in `_check_role` is `rollback=True`, and Postgres reverts a session-level `set_config` on rollback.
- Regression that slips through: change `set_tenant` to session scope, or have the kernel run `SET app.tenant_id`. The next transaction on that pooled connection, for example a pre-tenant `api_key_lookup` path, then runs as the previous tenant. The generated sweep cannot see this.
- Test to add: `test_committed_tenant_context_does_not_survive_the_transaction`. It commits a tenant transaction, then on the same connection asserts that `current_tenant()` is NULL and zero rows are visible. Mirror it at the kernel level: two `tenant_tx` calls on a pool with `max_size=1`.

**F7. Scrubber corpus has no transform variants; real bypasses exist.**
- Where: `packages/sibyl-schemas/tests/test_scrub.py:61-76`; corpus `fixtures/scrub/secrets.jsonl` (3-5 rows per detector).
- Regression that slips through, measured with `$SCRATCH/probes/scrub_bypass.py`:
  - **Tool-call arguments (a JSON string inside JSON, which is how OpenAI tool calls deliver `arguments`)**: `{"payload": "{\"password\": \"Sup3rS3cretValue2024\"}"}` leaks. `generic_secret_kv` cannot cross `\"`.
  - A **truncated PEM** (BEGIN with no END, which is common in cut-off tool output) leaks its whole body.
  - **URL-encoded context** defeats the lookbehinds: `%20sk-…` and `%3Dsbl_live_…`. With the corpus URL-encoded, 42 of 65 secrets leak.
  - **DSN or basic-auth passwords containing `/`** leak completely; a password containing `@` leaks partially.
  - A GCP SA JSON embedded as a string leaks `private_key_id`; a double-escaped PuTTY key leaks.
  - Not covered at all in prose fields: Google `AIza…`, GitLab `glpat-`, HuggingFace `hf_`, Slack webhook URLs, `pwd=`, `passphrase:`, and passwords with spaces.
  - Zero-width characters split keys.
  - False positives in structured fields: base64 image blobs, file paths that embed a hash, and SRI hashes are destroyed by `high_entropy`.
- Test to add: a metamorphic test over the existing corpus. Every secret must still be scrubbed when the text is JSON-escaped, double-JSON-escaped (tool args), URL-encoded around the secret, or converted to CRLF. Plus:
  - a partial-leak assertion (no substring of the secret of 8 or more characters survives);
  - explicit rows for each bypass above, marked `xfail(strict=True)` where the detector contract deliberately excludes them, so a fix is noticed and a decision is recorded;
  - FP rows for base64 media and hashed paths.

### MEDIUM

**F8. The xfail wall masks failures for the wrong reason.**
- Where: `services/control/tests/contract/test_authz_wall.py:15`, `services/control/tests/contract/test_mounted.py:86`.
- Regression that slips through:
  - With `strict=False` and no `raises=`, a harness that raises `KeyError` on every request still reports "730 xfailed" and stays green (demonstrated).
  - From wave 1 on, a route that turns green and then regresses goes back to XFAIL silently.
  - `PROTECTED`, `SCOPED`, `WITH_IDS` and the other sets have no size guard; only the total of 145 is pinned.
  - The wall only tests "no roles → 403". A route wired to the *wrong* scope passes.
- Test to add:
  - `xfail(strict=False, raises=AssertionError)` now. Demonstrated: 574 passed and 730 xfailed on clean code; 727 **failed** with the harness broken.
  - At G1, a checked-in green ledger: ops in the ledger have no marker; all others are `xfail(strict=True, raises=AssertionError)`.
  - A non-xfail test pinning the subset sizes.
  - A generated "all scopes except this route's" principal that must get 403 on every scoped route.

**F9. Idempotency races are untested.**
- Where: `services/control/tests/db/test_kernel_idempotency.py:75-85` is sequential only; `core/idempotency.py:208-221`.
- Regression that slips through: if the claim's `ON CONFLICT … WHERE expired-or-stale` becomes unconditional, two concurrent first uses both get `Fresh` and the side effect runs twice. The mutant passed the whole existing suite.
- Test to add: `test_concurrent_first_use_cannot_both_be_fresh`. A rival connection holds an uncommitted in-progress row. `begin()` runs as a task, and the test polls `pg_stat_activity` for a Lock wait instead of sleeping. After the commit, the outcome must be `InProgress`. Add the stale-reclaim race the same way: two reclaimers, exactly one `Fresh`.

**F10. API key status handling has gaps.**
- Where: `services/control/tests/core/test_apikeys.py:87-110`.
- Regression that slips through: a `rotating` key with `rotation_grace_until IS NULL` would verify forever, and an unknown status (`suspended`, `''`) would verify. Both mutants survived.
- Test to add: `test_rotating_without_grace_and_unknown_statuses_are_refused`, parametrised. Also consider flipping each secret position rather than only index 22 (`:112-121`); that is cheap hygiene, though K1 was already killed.

**F11. SQL `sibyl.jcs` disagrees with RFC 8785 on key order.**
- Where: `services/control/migrations/0001_foundation.sql:69-70` (`COLLATE "C"` gives code-point order, not UTF-16 order); the only test is one ASCII vector at `services/control/tests/db/test_invariants.py:710-713`.
- Regression that slips through: this is already present. On the shared vector file's own `rfc8785-3.2.3-utf16-sorting` document, and on `{"Ａ":1,"😀":2}`, the SQL output differs from `sibyl_schemas.canonical`; `migrate/jcs.py` agrees with the shared canonicaliser. Any audit detail whose object keys mix astral and U+E000–U+FFFF characters gets `audit_canonical_mismatch`, so the write is refused. The two implementations also hash the R63 ledger differently for such keys.
- Test to add: `test_sql_and_migrate_jcs_equal_the_shared_canonicaliser`, parametrised over the integer-only documents in `fixtures/jcs/rfc8785.json` plus astral/PUA, U+2028 and ±2^53−1 cases. Then fix the SQL sort or reject non-BMP keys explicitly.

**F12. Schemas-to-DB CHECK drift covers 7 constraints only.**
- Where: `services/control/tests/db/test_single_source_db.py:104-114`; hand-kept `STATES`/`TRIGGERS` at `services/control/tests/db/test_routing_apply.py:17-37`.
- Regression that slips through: adding a value to `RoutingState`, `KillSwitchState` or `ErasureState` in schemas is caught by the OpenAPI and JSON-Schema drift tests, but the DB suite (3/3 survived) never compares the DB CHECKs for those states. A regenerated OpenAPI plus a stale migration ships a contract the DB rejects. The routing matrix would also silently skip a new state.
- Test to add: generate the parametrisation from `pg_constraint`. Every CHECK of the form `col = ANY (ARRAY[...])` on a column that maps to a schemas value set must equal that set, with a reviewed allowlist. Derive `STATES`/`TRIGGERS` from `sv.RoutingState` and its trigger enum. This overlaps the G0-10 follow-up only for API-only enums; these are schemas enums.

**F13. The RLS inventory only sees schema `sibyl` and tables or partitions.**
- Where: `services/control/tests/db/fixtures.py:756-762` (`relkind IN ('r','p')`, `nspname = 'sibyl'`); `services/control/tests/db/test_rls_isolation.py:226-241`, which checks no role memberships.
- Regression that slips through: a materialized view (no RLS) or a tenant table in another schema, granted to a login role, is invisible. The mutant survived 30 tests. A `GRANT sibyl_audit TO sibyl_app` would let the app `SET ROLE` into the `OR current_user = 'sibyl_audit'` branch of the `api_key` and `session` policies and read every tenant's keys. That case was checked by inspection, not run, because roles are cluster-wide and the security reviewer was using the same cluster.
- Test to add: `test_no_readable_relation_bypasses_rls`, covering every schema and every relkind (r, p, v, m, f) that has `tenant_id` and is readable by a login role. Such a relation must be an RLS-forced tenant table, a `security_invoker` view, or allowlisted. Also add `test_login_roles_are_members_of_nothing`.

**F14. Tail truncation of the audit chain is undetectable.**
- Where: `services/control/migrations/0006_audit.sql:187-244` never consults `audit_anchors.head_hash`.
- Regression that slips through: deleting the last N audit rows still verifies as `ok`, and no test documents the gap.
- Test to add: `xfail(strict=True)` "delete the tail, then verify against the latest anchor, expect a break". It flips to a normal test when anchor verification lands. Without it, the gap is undocumented.

### LOW

**F15. Order-coupled outbox tests.**
- Where: `services/control/tests/db/test_outbox_cursor.py:24-26`, where one module tenant is shared and `test_two_channels…` commits rows into it.
- What happens: running `test_two_channels…` before `test_late_committing…` makes the latter fail (reproduced). It breaks under `-p randomly`, xdist or a reordered `-k`. The fix is a fresh tenant per test.

**F16. Time-based waits.**
- Where: `test_outbox_cursor.py:174` (fixed 0.3 s wait for NOTIFY), `services/control/tests/core/test_worker.py:62-64` (0.1 s sleep, expects 2 or more runs at 0.01 s intervals).
- Fix: poll until the condition holds, with a timeout. Similarly, `services/control/tests/contract/conftest.py:43` freezes `datetime.now()` at import time for "fresh" step-up. After 5 minutes of a strict G1 run, the step-up becomes stale. Inject a clock instead.

**F17. Fixed shared resource names.**
- Where: `ci/tests/test_backup_restore.py:23-24` (`sibyl_w0inf`, `sibyl_w0inf_restore`) and `ci/tests/test_compose_live.py:30-31` (project `sibyl_w0inf_ci`, slot 9 ports).
- What happens: two concurrent `ci/run.sh` runs, from two worktrees or from the chair and a reviewer, drop each other's databases and fight over ports. Suffix the names with a per-run token, as the DB conftest already does.

**F18. Cluster-global side effect not restored in `finally`.**
- Where: `services/control/tests/db/test_migrations.py:111-122` sets `sibyl_app`'s password cluster-wide and resets it outside a `finally`. Move the reset into a fixture.

**F19. The `routing_transition` INSERT trigger is never tested on its own.**
- Equivalent today (mutant P2), but nothing guards it if `routing_apply`'s own check is ever refactored away. Add one test: a direct INSERT of an illegal edge, made as the definer role via `SET ROLE`, raises SB010.

**F20. Equivalent mutant.**
- `FOR UPDATE` on the idempotency `_SELECT` has no observable effect, because the claim's conflict clause re-checks. Either drop the lock or document why it is kept.

## Flakiness, skips, runtime, xfail (summary)

- **Time**: none of the DB tests depend on wall-clock boundaries. Partitions cover 1 period back to 7 days or 2 months ahead, and fixtures use `now()`. The risks are F16.
- **Randomness**: DB names use 6 random bytes; no collisions, and no `sibyl_w0db_*` leftovers on the cluster. Hypothesis is used only for the canonical fixed-point test.
- **DB name / port collisions**: F17.
- **Skips**: one by design (`SIBYL_CI_DOCKER_BUILD`). The silent ones are F1. `test_compose_live` also skips its whole module when `docker info` fails, which makes it the same kind of silent skip if Docker is required in CI.
- **Runtime**: the pytest step took 35.7 s wall-clock (1760 passed / 730 xfailed). Slowest: `test_compose_live` setup 6.1 s, OpenAPI validation 1.8 s, the 2,000-agent snapshot 1.3 s. The DB suites take about 3.6 s in total. The candidate tests add about 1 s. That leaves the R71 10-minute budget with a large margin, so the per-state routing-style matrix for the other 8 machines (F4 follow-up) is affordable.
- **xfail wall**: F8. Today it proves only that the generator runs. It cannot fail.

## Appendix: candidate tests (scratch, verified)

These files live in the scratch copy and were run there: 19 passed on clean code, and they killed the mutants listed above. They are written against the existing fixtures (`conftest.py`, `fixtures.py`, `test_erasure.py` helpers) and can be copied into `services/control/tests/{db,core}/` as-is.

- `test_zz_g0_review.py`: audit (F2), RLS (F6, F13), machines (F4), erasure (F3), outbox (F5), idempotency race (F9)
- `test_zz_g0_review_keys.py`: F10
- `test_zz_g0_review_jcs.py`: F11 (fails today, by design)
- `scrub_bypass.py`: F7 battery; `mutants.py` + `harness.py`: the mutation harness

The full source of each follows.

### `test_zz_g0_review.py`

```python
# ruff: noqa: S608
"""Proposed additions from the G0 test-quality review (scratch only, not in the repo)."""

from __future__ import annotations

import asyncio
import re
import uuid
from typing import Any

import asyncpg
import pytest
from sibyl_control.core.db import Database as KernelDatabase
from sibyl_control.core.idempotency import Fresh, InProgress, PgIdempotencyStore, fingerprint
from sibyl_control.migrate import ledger

from .conftest import LOGIN_ROLES, Conn, Database, app_dsn
from .fixtures import ALLOWLIST, TenantFixture, create_tenant, populate_tenant, tenant_tables
from .test_erasure import KEEP, _ledger_for, _request, _transition

NIL = uuid.UUID(int=0)


# --- audit chain -------------------------------------------------------------------------------

def _tamper(admin: Conn, sql: str, *args: Any) -> None:
    with admin.tx():
        admin.execute("SET LOCAL session_replication_role = replica")
        admin.execute(sql, *args)


def _verify(admin: Conn, tenant: uuid.UUID) -> Any:
    with admin.tx(tenant, rollback=True):
        return admin.fetchrow("SELECT * FROM sibyl.audit_verify($1)", tenant)


def test_rewritten_hash_of_the_last_row_is_hash_mismatch(admin: Conn) -> None:
    tenant = create_tenant(admin, "g0r-tail-hash")
    last = admin.fetchval("SELECT max(seq) FROM sibyl.audit_events WHERE tenant_id = $1", tenant)
    _tamper(admin, "UPDATE sibyl.audit_events SET hash = sha256('x') WHERE tenant_id = $1 AND seq = $2",
            tenant, last)
    r = _verify(admin, tenant)
    assert (r["ok"], r["first_break_seq"], r["kind"]) == (False, last, "hash_mismatch")


def test_spliced_self_consistent_row_is_prev_mismatch(admin: Conn) -> None:
    tenant = create_tenant(admin, "g0r-splice")
    _tamper(
        admin,
        "UPDATE sibyl.audit_events SET prev_hash = sha256('forged'), "
        "hash = sha256(sha256('forged') || envelope_sha256 || detail_sha256) "
        "WHERE tenant_id = $1 AND seq = 1",
        tenant,
    )
    r = _verify(admin, tenant)
    assert (r["ok"], r["first_break_seq"], r["kind"]) == (False, 1, "prev_mismatch")


# --- RLS --------------------------------------------------------------------------------------

def test_committed_tenant_context_does_not_survive_the_transaction(db: Database, admin: Conn) -> None:
    a = populate_tenant(admin, "g0r-guc").tenant_id
    conn = db.connect("sibyl_app")
    try:
        with conn.tx(a):  # committed, like every real request
            assert conn.fetchval("SELECT count(*) FROM sibyl.agent") > 0
        with conn.tx(rollback=True):
            assert conn.fetchval("SELECT sibyl.current_tenant()") is None
            assert conn.fetchval("SELECT count(*) FROM sibyl.agent") == 0
    finally:
        conn.close()


def test_login_roles_are_members_of_nothing(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT m.rolname AS member, r.rolname AS role FROM pg_auth_members am "
        "JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid "
        "WHERE m.rolname = ANY($1::text[])",
        list(LOGIN_ROLES),
    )
    assert [dict(r) for r in rows] == []


def test_no_readable_relation_bypasses_rls(admin: Conn) -> None:
    """Every relation a login role can read, in any schema, that carries tenant data is an
    RLS-forced tenant table (views must be security_invoker; materialized views are refused)."""
    tables = set(tenant_tables(admin))
    rows = admin.fetch(
        "SELECT n.nspname, c.relname, c.relkind::text AS relkind, c.relrowsecurity, c.relforcerowsecurity, "
        "coalesce(c.reloptions, '{}') AS opts FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema') "
        "AND n.nspname NOT LIKE 'pg_toast%' AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid "
        "AND a.attname = 'tenant_id' AND NOT a.attisdropped) "
        "AND EXISTS (SELECT 1 FROM unnest($1::text[]) r WHERE has_table_privilege(r, c.oid, 'SELECT'))",
        list(LOGIN_ROLES),
    )
    bad = []
    for r in rows:
        name = f"{r['nspname']}.{r['relname']}"
        if r["relkind"] in ("r", "p") and r["nspname"] == "sibyl" and r["relname"] in tables | ALLOWLIST:
            continue
        if r["relkind"] == "v" and "security_invoker=true" in r["opts"]:
            continue
        bad.append((name, r["relkind"]))
    assert bad == []


# --- state machines (all nine, not only routing) -------------------------------------------

def _machines(admin: Conn) -> list[tuple[str, str, str]]:
    out = []
    for r in admin.fetch(
        "SELECT c.relname, pg_get_triggerdef(t.oid) AS d FROM pg_trigger t "
        "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid "
        "WHERE p.proname = 'trg_state_edge' AND NOT t.tgisinternal"
    ):
        m = re.search(r"trg_state_edge\('(\w+)', '(\w+)'\)", r["d"])
        out.append((r["relname"], m.group(1), m.group(2)))
    return out


def test_every_machine_is_wired_to_exactly_one_trigger(admin: Conn) -> None:
    wired = [m for _, m, _ in _machines(admin)]
    seeded = {r["machine"] for r in admin.fetch("SELECT DISTINCT machine FROM sibyl.state_edge")}
    assert sorted(wired) == sorted(seeded)


def test_every_machine_refuses_every_illegal_update(admin: Conn) -> None:
    fx = populate_tenant(admin, "g0r-machines")
    wrong, checked = [], 0
    for table, machine, col in _machines(admin):
        if machine == "routing":
            continue  # INSERT-driven; covered exhaustively by test_routing_apply
        edges = admin.fetch("SELECT from_state, to_state, trigger FROM sibyl.state_edge WHERE machine = $1", machine)
        states = {e["to_state"] for e in edges} | {e["from_state"] for e in edges if e["from_state"]}
        with admin.tx(fx.tenant_id, rollback=True):
            admin.execute(f"ALTER TABLE sibyl.{table} DISABLE TRIGGER USER")
            admin.execute(f"ALTER TABLE sibyl.{table} ENABLE TRIGGER {_trigger_name(admin, table)}")
            row = admin.fetchrow(f'SELECT ctid::text AS ctid, "{col}"::text AS s FROM sibyl.{table} WHERE tenant_id = $1 LIMIT 1', fx.tenant_id)
            assert row is not None, table
            legal_from = {(e["to_state"], e["trigger"]) for e in edges if e["from_state"] == row["s"]}
            attempts = [(t, "") for t in sorted(states - {row["s"]} - {t for t, _ in legal_from})]
            attempts += [(t, "zz_bogus") for t, trig in sorted(legal_from) if trig != "*" and t != row["s"]
                         and (t, "*") not in legal_from]
            for target, trig in attempts:
                admin.execute("SAVEPOINT a")
                try:
                    admin.execute("SELECT set_config('app.transition_trigger', $1, true)", trig)
                    admin.execute(f'UPDATE sibyl.{table} SET "{col}" = $1 WHERE ctid = $2::text::tid', target, row["ctid"])
                    wrong.append((machine, row["s"], target, trig, "accepted"))
                except asyncpg.PostgresError as exc:
                    if exc.sqlstate != "SB010":
                        wrong.append((machine, row["s"], target, trig, exc.sqlstate, str(exc)[:120]))
                admin.execute("ROLLBACK TO SAVEPOINT a")
                checked += 1
    assert checked >= 8 and wrong == [], wrong


def _trigger_name(admin: Conn, table: str) -> str:
    return admin.fetchval(
        "SELECT t.tgname FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid "
        "WHERE t.tgrelid = $1::regclass AND p.proname = 'trg_state_edge'", f"sibyl.{table}")


# --- erasure ---------------------------------------------------------------------------------

def _agent_tables(admin: Conn) -> list[str]:
    tables = set(tenant_tables(admin)) - KEEP
    return sorted(
        r["relname"] for r in admin.fetch(
            "SELECT c.relname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'sibyl' "
            "AND a.attname = 'agent_id' AND NOT a.attisdropped AND c.relkind IN ('r','p') "
            "AND NOT c.relispartition") if r["relname"] in tables)


def _per_agent(admin: Conn, fx: TenantFixture, agent: uuid.UUID, tables: list[str]) -> dict[str, int]:
    return {t: admin.fetchval(f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1 AND agent_id = $2",
                              fx.tenant_id, agent) for t in tables}


def test_every_agent_keyed_table_has_an_agent_predicate(admin: Conn) -> None:
    plan = {r["table_name"]: r["agent_predicate"] for r in admin.fetch("SELECT * FROM sibyl.erasure_cascade()")}
    assert [t for t in _agent_tables(admin) if plan.get(t) is None] == []


def test_agent_erasure_removes_every_row_of_that_agent_and_nothing_of_the_other(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, "g0r-erase-agent")
    tables = _agent_tables(admin)
    victim_before = _per_agent(admin, fx, fx.agent_a, tables)
    other_before = _per_agent(admin, fx, fx.agent_b, tables)
    populated = [t for t, n in victim_before.items() if n]
    assert len(populated) >= len(tables) - 2, f"fixture lacks victim rows in {sorted(set(tables) - set(populated))}"
    request = _request(roles["sibyl_app"], fx, "agent", str(fx.agent_a), "gdpr_art17")
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        _transition(worker, fx.tenant_id, request, "executing")
        worker.execute("SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')", request)
        worker.execute("SELECT sibyl.erasure_execute_phase($1, 'derived_purged')", request)
    assert {t: n for t, n in _per_agent(admin, fx, fx.agent_a, tables).items() if n} == {}
    assert _per_agent(admin, fx, fx.agent_b, tables) == other_before


def test_residue_reports_what_is_still_there(admin: Conn, roles: dict[str, Conn]) -> None:
    fx = populate_tenant(admin, "g0r-residue")
    request = _request(roles["sibyl_app"], fx, "tenant", None, "gdpr_art17")
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        _transition(worker, fx.tenant_id, request, "executing")
        residue = {r["table_name"] for r in worker.fetch("SELECT * FROM sibyl.erasure_residue($1)", request)}
    plan = [r["table_name"] for r in admin.fetch(
        "SELECT table_name FROM sibyl.erasure_cascade() WHERE action IN ('delete', 'routing_fn')")]
    populated = {t for t in plan if admin.fetchval(
        f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1", fx.tenant_id)}
    assert populated and residue >= populated


def test_ledger_reapply_of_an_agent_erasure_leaves_no_agent_rows(admin: Conn) -> None:
    fx = populate_tenant(admin, "g0r-reapply-agent")
    tables = _agent_tables(admin)
    other_before = _per_agent(admin, fx, fx.agent_b, tables)
    jsonl = _ledger_for((fx.tenant_id, "agent", str(fx.agent_a)))
    assert admin.fetchval("SELECT sibyl.erasure_reapply_from_ledger($1)", jsonl) == 1
    assert {t: n for t, n in _per_agent(admin, fx, fx.agent_a, tables).items() if n} == {}
    assert _per_agent(admin, fx, fx.agent_b, tables) == other_before


# --- outbox cursor -----------------------------------------------------------------------------

INSERT_OUTBOX = (
    "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, aggregate_id, payload, "
    "idempotency_key) VALUES ($1, 'alert', 'alert.fired', 'alert', $2, '{}', $3) RETURNING id, xid"
)


def _drain(conn: Conn, tenant: uuid.UUID, limit: int) -> list[uuid.UUID]:
    seen, xid, last = [], 0, NIL
    for _ in range(100):
        with conn.tx(tenant, rollback=True):
            page = conn.fetch("SELECT id, xid FROM sibyl.outbox_read($1, $2, $3)", xid, last, limit)
        if not page:
            return seen
        seen += [r["id"] for r in page]
        xid, last = page[-1]["xid"], page[-1]["id"]
    raise AssertionError("cursor did not terminate")


def test_paging_through_one_transaction_with_limit_one_misses_nothing(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "g0r-page")
    app = roles["sibyl_app"]
    with app.tx(tenant):
        ids = [app.fetchrow(INSERT_OUTBOX, tenant, uuid.uuid4(), f"p{i}")["id"] for i in range(3)]
    assert sorted(_drain(app, tenant, 1)) == sorted(ids)


def test_cursor_orders_by_commit_xid_not_by_id(db: Database, admin: Conn, roles: dict[str, Conn]) -> None:
    """Lower xid, higher id: the id-ordered reader would deliver B first and then skip A."""
    tenant = create_tenant(admin, "g0r-order")
    first, second = db.connect("sibyl_app"), db.connect("sibyl_app")
    try:
        tx1 = first.raw.transaction(); first.run(tx1.start())
        first.execute("SELECT sibyl.set_tenant($1)", tenant)
        first.fetchval("SELECT pg_current_xact_id()")  # takes the lower xid now
        tx2 = second.raw.transaction(); second.run(tx2.start())
        second.execute("SELECT sibyl.set_tenant($1)", tenant)
        b = second.fetchrow(INSERT_OUTBOX, tenant, uuid.uuid4(), "b")  # smaller uuidv7 id, higher xid
        a = first.fetchrow(INSERT_OUTBOX, tenant, uuid.uuid4(), "a")
        second.run(tx2.commit()); first.run(tx1.commit())
        assert int(a["xid"]) < int(b["xid"])
        assert _drain(roles["sibyl_app"], tenant, 1) == [a["id"], b["id"]]
    finally:
        first.close(); second.close()


# --- idempotency race ------------------------------------------------------------------------

def test_concurrent_first_use_cannot_both_be_fresh(
    db: Database, kernel_db: KernelDatabase, loop: asyncio.AbstractEventLoop, admin: Conn
) -> None:
    tenant = create_tenant(admin, "g0r-idem-race")
    store, principal, fp = PgIdempotencyStore(kernel_db), uuid.uuid4(), fingerprint(b'{"x":1}')

    async def scenario() -> Any:
        rival = await asyncpg.connect(app_dsn(db))
        try:
            tx = rival.transaction(); await tx.start()
            await rival.execute("SELECT sibyl.set_tenant($1)", tenant)
            await rival.execute(
                "INSERT INTO sibyl.idempotency_record (tenant_id, route, idempotency_key, principal_kind, "
                "principal_id, request_sha256, state, expires_at) VALUES ($1, 'POST /x', 'race', 'user', $2, $3, "
                "'in_progress', clock_timestamp() + interval '1 day')", tenant, principal, fp)
            task = asyncio.ensure_future(store.begin(tenant, principal, "POST /x", "race", fp))
            for _ in range(200):  # wait until begin() is blocked on the rival's row, no sleeps-as-asserts
                waiting = await rival.fetchval(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND wait_event_type = 'Lock'")
                if waiting:
                    break
                await asyncio.sleep(0.01)
            assert not task.done()
            await tx.commit()
            return await asyncio.wait_for(task, 5)
        finally:
            await rival.close()

    outcome = loop.run_until_complete(scenario())
    assert isinstance(outcome, InProgress) and not isinstance(outcome, Fresh)
```

### `test_zz_g0_review_keys.py`

```python
"""Proposed API-key verification additions (scratch only)."""
from __future__ import annotations

import pytest
from sibyl_control.core.apikeys import ApiKeyRejected, RejectReason, generate_api_key, verify_api_key

from .test_apikeys import NOW, PEPPER, lookup_of, record_for


@pytest.mark.parametrize("status", ["rotating", "suspended", "pending", ""])
async def test_rotating_without_grace_and_unknown_statuses_are_refused(status: str) -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    rec = record_for(plaintext, status=status, rotation_grace_until=None)
    with pytest.raises(ApiKeyRejected):
        await verify_api_key(plaintext, lookup_of((plaintext, rec)), PEPPER, now=NOW)


async def test_flipping_any_secret_character_is_bad_secret() -> None:
    real = generate_api_key("live", PEPPER).plaintext
    lookup = lookup_of((real, record_for(real)))
    for i in range(22, len(real)):
        forged = real[:i] + ("A" if real[i] != "A" else "B") + real[i + 1 :]
        with pytest.raises(ApiKeyRejected) as err:
            await verify_api_key(forged, lookup, PEPPER, now=NOW)
        assert err.value.reason in (RejectReason.BAD_SECRET, RejectReason.MALFORMED), i
```

### `test_zz_g0_review_jcs.py`

```python
"""Differential canonicaliser check across the three implementations (scratch only)."""
from __future__ import annotations

import json

import pytest
from sibyl_control.migrate.jcs import canonicalize as migrate_jcs
from sibyl_schemas.canonical import canonicalize as shared
from sibyl_schemas.golden import fixtures_root

from .conftest import Conn

DOCS = json.loads((fixtures_root() / "jcs" / "rfc8785.json").read_text("utf-8"))["documents"]
EXTRA = [
    {"Ａ": 1, "\U0001f600": 2},
    {"labels": {"": "pua", "\U00010000": "astral"}},
    {"s": "  \u007f\u0000"},
    {"n": [0, -0, 9007199254740991, -9007199254740991]},
]


def _integer_only(value) -> bool:
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(_integer_only(v) for v in value.values())
    if isinstance(value, list):
        return all(_integer_only(v) for v in value)
    return True


CASES = [json.loads(d["input"]) for d in DOCS if _integer_only(json.loads(d["input"]))] + EXTRA


@pytest.mark.parametrize("doc", CASES, ids=range(len(CASES)))
def test_sql_and_migrate_jcs_equal_the_shared_canonicaliser(admin: Conn, doc) -> None:
    expected = shared(doc, allow_floats=False).decode()
    assert migrate_jcs(doc) == expected
    assert admin.fetchval("SELECT sibyl.jcs($1::jsonb)", json.dumps(doc)) == expected
```

### `scrub_bypass.py` (run with `uv run python -I scrub_bypass.py`)

```python
"""Bypass battery for sibyl_schemas.scrub (scratch only)."""
import json, urllib.parse
from difflib import SequenceMatcher
from sibyl_schemas.scrub import SecretsScrubber, ScrubField
from sibyl_schemas.golden import fixtures_root

S = SecretsScrubber(b"test-salt-not-a-platform-secret!")
rows = [json.loads(l) for l in (fixtures_root()/"scrub"/"secrets.jsonl").read_text().splitlines() if l.strip()]

def longest_leak(secret, text):
    m = SequenceMatcher(None, secret, text, autojunk=False).find_longest_match(0, len(secret), 0, len(text))
    return m.size

print("== partial leak on corpus (longest surviving substring of secret >= 8) ==")
for r in rows:
    out = S.scrub(r["text"], field=ScrubField(r["field"])).text
    n = longest_leak(r["secret"], out)
    if n >= 8:
        print(r["id"], n, "of", len(r["secret"]))

print("== transformed corpus variants ==")
fails = {}
for r in rows:
    f = ScrubField(r["field"])
    variants = {
        "json_escaped": json.dumps(r["text"]),
        "double_json": json.dumps(json.dumps({"v": r["text"]})),
        "url_encoded": urllib.parse.quote(r["text"], safe=""),
        "crlf": r["text"].replace("\n", "\r\n"),
        "as_tool_args_json": json.dumps({"arg": r["text"]}),
    }
    for name, text in variants.items():
        out = S.scrub(text, field=f).text
        # secret as it appears in the transformed text
        enc = {"json_escaped": json.dumps(r["secret"])[1:-1], "double_json": json.dumps(json.dumps(r["secret"])[1:-1])[1:-1],
               "url_encoded": urllib.parse.quote(r["secret"], safe=""), "crlf": r["secret"].replace("\n", "\r\n"),
               "as_tool_args_json": json.dumps(r["secret"])[1:-1]}[name]
        if enc in out:
            fails.setdefault(name, []).append(r["id"])
for k, v in fails.items():
    print(k, len(v), v)

print("== hand-written bypass cases ==")
cases = [
 ("pem_truncated", "tool_result", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\naNn8M2vYQ7Qd8Ixa1Q==\n", "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn"),
 ("kv_json_escaped", "tool_args", json.dumps({"payload": json.dumps({"password": "Sup3rS3cretValue2024"})}), "Sup3rS3cretValue2024"),
 ("kv_passphrase_spaces", "state", 'password = "correct horse battery staple"', "correct horse battery staple"),
 ("kv_pwd_key", "state", "pwd=Xk9#mQ2$vL7pR4tZ", "Xk9#mQ2$vL7pR4tZ"),
 ("kv_passphrase_key", "state", "passphrase: Xk9mQ2vL7pR4tZw8", "Xk9mQ2vL7pR4tZw8"),
 ("kv_access_token", "state", "ACCESS_TOKEN=Xk9mQ2vL7pR4tZw8yH3", "Xk9mQ2vL7pR4tZw8yH3"),
 ("dsn_slash_in_password", "state", "postgres://app:ab/cd+ef9GhIjK@db.internal:5432/app", "ab/cd+ef9GhIjK"),
 ("dsn_at_in_password", "state", "postgres://app:P@ssw0rd!x9@db.internal:5432/app", "ssw0rd!x9"),
 ("basic_url_slash", "input_messages", "clone https://deploy:gh/Abc123xyz789@git.example.com/repo", "gh/Abc123xyz789"),
 ("aws_secret_env_upper", "input_messages", "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
 ("aws_secret_quoted_json_escaped", "tool_args", json.dumps(json.dumps({"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
 ("google_api_key_prose", "input_messages", "my key is AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY ok", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"),
 ("gitlab_pat_prose", "input_messages", "token glpat-xYz12AbCdEfGhIjKlMnO here", "glpat-xYz12AbCdEfGhIjKlMnO"),
 ("hf_token_prose", "input_messages", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 is mine", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
 ("slack_webhook", "input_messages", "post to https://hooks.slack.com/services/T0ABC1234/B0ABC5678/AbCdEfGhIjKlMnOpQrStUvWx", "AbCdEfGhIjKlMnOpQrStUvWx"),
 ("bearer_lower_header_json", "header", '{"authorization":"bearer abcdEFGH1234ijklMNOP5678"}', "abcdEFGH1234ijklMNOP5678"),
 ("jwt_in_cookie", "header", "Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
 ("openai_zero_width", "input_messages", "sk-proj-Ab3Ab3Ab3​Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3", "Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3Ab3"),
 ("pem_escaped_newlines_generic", "tool_args", json.dumps({"key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oWbWfF0YvSbHoAoGCCqGSM49\n-----END EC PRIVATE KEY-----\n"}), "MHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oWbWfF0YvSbHoAoGCCqGSM49"),
]
for name, field, text, secret in cases:
    res = S.scrub(text, field=ScrubField(field))
    print(("LEAK " if secret in res.text else "ok   ") + name, [f.detector_id for f in res.findings])
```
