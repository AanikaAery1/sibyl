#!/usr/bin/env bash
# Sibyl local CI pipeline (R71: gates run locally in Phase 1; budget <= 10 min).
#
# usage: ci/run.sh [--only step[,step]] [--skip step[,step]] [--fail-fast] [--list]
# steps: sync ruff format imports mypy pytest licences
#
# Runs every step, prints a summary and exits non-zero if any step failed (or stops at
# the first failure with --fail-fast). Outputs land in ci/.out/ (gitignored).
# Env: UV_SYSTEM_CERTS (default 1; this network re-signs TLS, never disable verification),
#      SIBYL_PG_ADMIN_DSN (DB tests; default the PG17 dev cluster on :5433; the pytest step
#        refuses to start unless pg_isready accepts it),
#      SIBYL_REQUIRE_PG / CI (default 1: DB fixtures fail instead of skipping),
#      SIBYL_CI_ALLOW_SKIPS (extra skip-reason regexes for ci/skip_guard.py, one per line),
#      SIBYL_COV_MIN (coverage floor over every test process; default 80),
#      SIBYL_CI_WORKERS (pytest-xdist workers for the main suite; default 6, 0 = serial),
#      SIBYL_CI_PG_SLOTS (free Postgres connections needed to run the smoke scenarios beside
#        the main suite; default 150, else they run after it),
#      SIBYL_CI_PYTEST_ARGS (extra pytest args, passed to both test processes).
set -euo pipefail

export UV_SYSTEM_CERTS="${UV_SYSTEM_CERTS:-1}"
export SIBYL_PG_ADMIN_DSN="${SIBYL_PG_ADMIN_DSN:-postgresql://postgres@localhost:5433/postgres}"
# G0 F1: a DB that is down must turn CI red, never into silently skipped tests.
export SIBYL_REQUIRE_PG="${SIBYL_REQUIRE_PG:-1}"
export CI="${CI:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/ci/.out"
STEPS=(sync ruff format imports mypy pytest licences)
BUDGET_S=600
COV_MIN="${SIBYL_COV_MIN:-80}"

# Typed source trees (mypy) and coverage targets; missing trees are skipped.
SRC_DIRS=(
  packages/sibyl-schemas/src
  packages/sibyl-sdk/src
  packages/sibyl-mcp/src
  services/control/src
  services/gateway/src
  sibyl-sim/src
)
COV_PKGS=(sibyl_schemas sibyl sibyl_mcp sibyl_control sibyl_gateway sibyl_sim)
TEST_DIRS=(packages services sibyl-sim ci/tests)
# The sibyl-sim smoke scenarios run on the wall clock (~4 min whatever the CPU count), so they
# run in their own process beside the xdist suite (R71). Their deadlines scale with measured
# tick lag (B38), so the concurrent load cannot fail them; a host too loaded to judge is a
# harness error, never a pass.
SMOKE_TEST="sibyl-sim/tests/scenarios/test_smoke.py"
WORKERS="${SIBYL_CI_WORKERS:-6}"
# Four in-process stacks hold ~80 connections; beside six xdist workers that needs more than a
# default max_connections=100 cluster has, so they overlap only when the room is there.
PG_SLOTS="${SIBYL_CI_PG_SLOTS:-150}"

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "run.sh: $*" >&2; exit 2; }
contains() { local x="$1"; shift; local y; for y in "$@"; do [[ "$x" == "$y" ]] && return 0; done; return 1; }

only=() skip=() fail_fast=0
split_csv() { local IFS=,; read -r -a _csv <<< "$1"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) split_csv "${2:?--only needs steps}"; only+=("${_csv[@]}"); shift ;;
    --skip) split_csv "${2:?--skip needs steps}"; skip+=("${_csv[@]}"); shift ;;
    --fail-fast) fail_fast=1 ;;
    --list) printf '%s\n' "${STEPS[@]}"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument $1" ;;
  esac
  shift
done
for s in ${only[@]+"${only[@]}"} ${skip[@]+"${skip[@]}"}; do
  contains "$s" "${STEPS[@]}" || die "unknown step '$s' (try --list)"
done

existing() { local d; for d in "$@"; do [[ -d "$ROOT/$d" ]] && printf '%s\n' "$d"; done; }

step_sync() { uv sync --all-packages --locked; }
step_ruff() { uv run ruff check .; }
step_format() { uv run ruff format --check .; }
step_imports() { uv run lint-imports; }
step_mypy() {
  local dirs=()
  while IFS= read -r d; do dirs+=("$d"); done < <(existing "${SRC_DIRS[@]}")
  uv run mypy "${dirs[@]}"
}
pg_isready_bin() {
  if [[ -n "${PGBIN:-}" && -x "$PGBIN/pg_isready" ]]; then echo "$PGBIN/pg_isready"
  elif [[ -x /opt/homebrew/opt/postgresql@17/bin/pg_isready ]]; then echo /opt/homebrew/opt/postgresql@17/bin/pg_isready
  else command -v pg_isready || true; fi
}
preflight_pg() {
  local bin
  bin="$(pg_isready_bin)"
  [[ -n "$bin" ]] || { echo "run.sh: pg_isready not found (set PGBIN)" >&2; return 1; }
  if ! "$bin" -q -t 5 -d "$SIBYL_PG_ADMIN_DSN"; then
    echo "run.sh: PostgreSQL is not accepting connections at SIBYL_PG_ADMIN_DSN" \
      "(${SIBYL_PG_ADMIN_DSN##*@}); start it (make db-up) or point SIBYL_PG_ADMIN_DSN elsewhere" >&2
    return 1
  fi
}
free_pg_slots() {
  local bin psql
  bin="$(pg_isready_bin)"
  psql="$(dirname "$bin")/psql"
  [[ -x "$psql" ]] || psql="$(command -v psql || true)"
  [[ -n "$psql" ]] || { echo 0; return; }
  "$psql" -X -At -d "$SIBYL_PG_ADMIN_DSN" -c \
    "select current_setting('max_connections')::int - count(*) from pg_stat_activity" \
    2>/dev/null || echo 0
}
run_smoke() {
  # shellcheck disable=SC2086
  COVERAGE_FILE="$OUT/.coverage.smoke" uv run pytest -q "$SMOKE_TEST" "${cov[@]}" \
    --cov-report= --junitxml="$OUT/junit-smoke.xml" -rfEs ${SIBYL_CI_PYTEST_ARGS:-} \
    >"$OUT/pytest-smoke.log" 2>&1
}
step_pytest() {
  local tests=() cov=() par=() p rc=0 smoke_rc=0 smoke_pid="" smoke_after=0 slots
  preflight_pg || return 1
  while IFS= read -r d; do tests+=("$d"); done < <(existing "${TEST_DIRS[@]}")
  for p in "${COV_PKGS[@]}"; do cov+=("--cov=$p"); done
  [[ "$WORKERS" != 0 ]] && par=(-n "$WORKERS" --dist loadfile)
  rm -f "$OUT"/junit.xml "$OUT"/junit-smoke.xml "$OUT"/junit-serial.xml "$OUT"/.coverage \
    "$OUT"/.coverage.*
  if [[ -f "$ROOT/$SMOKE_TEST" ]]; then
    slots="$(free_pg_slots)"
    if [[ "$slots" -ge "$PG_SLOTS" ]]; then
      echo "run.sh: smoke scenarios run beside the main suite ($slots free connections)"
      run_smoke &
      smoke_pid=$!
    else
      echo "run.sh: $slots free connections (< $PG_SLOTS): smoke scenarios run after the main suite"
      smoke_after=1
    fi
  fi
  # shellcheck disable=SC2086
  COVERAGE_FILE="$OUT/.coverage.main" uv run pytest -q "${tests[@]}" --ignore="$SMOKE_TEST" \
    -m "not serial" ${par[@]+"${par[@]}"} "${cov[@]}" --cov-report= \
    --junitxml="$OUT/junit.xml" -rfEs ${SIBYL_CI_PYTEST_ARGS:-} || rc=$?
  # Timing-budget tests (marker `serial`: latency bench, scoring perf, ingest throughput, scrub
  # linearity) run alone, so no xdist worker shares the CPU while they measure.
  # shellcheck disable=SC2086
  COVERAGE_FILE="$OUT/.coverage.serial" uv run pytest -q "${tests[@]}" --ignore="$SMOKE_TEST" \
    -m serial "${cov[@]}" --cov-report= \
    --junitxml="$OUT/junit-serial.xml" -rfEs ${SIBYL_CI_PYTEST_ARGS:-} || rc=$?
  if [[ $smoke_after -eq 1 ]]; then
    run_smoke || smoke_rc=$?
    echo "==> pytest: $SMOKE_TEST (after the main suite, exit $smoke_rc)"
    cat "$OUT/pytest-smoke.log"
    [[ $smoke_rc -eq 0 ]] || rc=1
  elif [[ -n "$smoke_pid" ]]; then
    wait "$smoke_pid" || smoke_rc=$?
    echo "==> pytest: $SMOKE_TEST (ran concurrently, exit $smoke_rc)"
    cat "$OUT/pytest-smoke.log"
    [[ $smoke_rc -eq 0 ]] || rc=1
  fi
  # One floor over everything both processes ran (as the single run had).
  uv run coverage combine --data-file="$OUT/.coverage" "$OUT"/.coverage.* >/dev/null || rc=1
  uv run coverage report --data-file="$OUT/.coverage" --show-missing --skip-covered \
    --fail-under="$COV_MIN" || rc=1
  uv run coverage xml --data-file="$OUT/.coverage" -o "$OUT/coverage.xml" -q || rc=1
  uv run python ci/skip_guard.py "$OUT/junit.xml" || rc=1
  uv run python ci/skip_guard.py "$OUT/junit-serial.xml" || rc=1
  if [[ -f "$OUT/junit-smoke.xml" ]]; then
    uv run python ci/skip_guard.py "$OUT/junit-smoke.xml" || rc=1
  elif [[ -n "$smoke_pid" || $smoke_after -eq 1 ]]; then
    echo "run.sh: the smoke process wrote no junit report" >&2; rc=1
  fi
  return "$rc"
}
step_licences() {
  uv export --all-packages --no-dev --no-hashes --no-emit-workspace --frozen \
    --format requirements-txt --output-file "$OUT/runtime-requirements.txt" >/dev/null
  uv run python ci/licences.py \
    --runtime-requirements "$OUT/runtime-requirements.txt" \
    --npm-lock console/package-lock.json \
    --output "$OUT/licences.md" --json "$OUT/licences.json"
}

cd "$ROOT"
mkdir -p "$OUT"
start=$SECONDS
results=() failed=0
for step in "${STEPS[@]}"; do
  if [[ ${#only[@]} -gt 0 ]] && ! contains "$step" "${only[@]}"; then continue; fi
  if [[ ${#skip[@]} -gt 0 ]] && contains "$step" "${skip[@]}"; then continue; fi
  echo "==> $step"
  t0=$SECONDS
  if "step_$step"; then
    results+=("ok    $step ($((SECONDS - t0))s)")
  else
    results+=("FAIL  $step ($((SECONDS - t0))s)")
    failed=1
    [[ $fail_fast -eq 1 ]] && break
  fi
done

total=$((SECONDS - start))
echo
echo "==> summary (${total}s, budget ${BUDGET_S}s)"
printf '  %s\n' "${results[@]}"
[[ $total -gt $BUDGET_S ]] && echo "  WARN  over the R71 10-minute budget"
exit "$failed"
