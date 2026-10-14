# Harness timing, deadlines and CI scheduling (wave 4, lane HARDEN)

## Lag-scaled deadlines (B38)

The product runs on its own wall clock (R45: no clock override). A catalogue deadline such as
`detect: {by_t: 120}` was calibrated on an idle host. Instead of overriding any clock, every run
measures how much slower it actually was (`sibyl_sim/harness/lag.py`, `oracle/timing.py`):

| Measure | How | Effect on a deadline |
|---|---|---|
| `dilation` | product eval loops (rollup, scoring): mean observed period / (nominal interval + 1 s) | multiplies the time after the stimulus |
| `actor_late_s` | p95 lateness of planned arrivals sent before the first chaos step | added |
| `loop_lag_s` | p95 overshoot of the harness event loop (SSE frames are stamped on arrival) | added |
| `data_lag_s` | p95 age of the oldest event beyond the rollup cursor, minus one rollup interval | added |

`deadline = onset + (by_t - onset) x dilation + actor_late_s + loop_lag_s + data_lag_s`, and TTD
gate limits scale the same way. At idle every measure is ~0 and every gate is exactly the
catalogue's. Above `dilation` 2.0 or `data_lag_s` 60 s the run is **inconclusive** (status
`error`, the reason says why): it is never passed. Each run's `summary.timing` records all of it.

What we measured (2026-10-14): under 14 busy processes on a 10-core host (load average 34) the
eval loops kept a 9.8-10.3 s period (dilation 1.0) and actors were late by under 10 ms; every
lag-sensitive deadline passed. The failures seen during concurrent CI runs come from the shared
Postgres instead: the rollup reads only below the cluster-wide commit horizon (R60), so other
suites' open transactions stall the product's data while its loops keep time. `data_lag_s`
measures exactly that.

## Ports and connections

- The doubles' port is part of the seeded world, so each port has its own cached template. Runs
  pick the first free base from a small fixed set (`harness/ports.py`): concurrent CI runs from
  other worktrees no longer collide on 18490-18493.
- One in-process stack holds about 20 connections (four: about 80). A stack that cannot get a
  connection slot at start waits and retries (`start_with_retry`, 4 attempts, 20 s apart).
- Host slots (`harness/hostslots.py`): every `sibyl_sim run` stack on the machine, from any
  worktree, takes one of `SIBYL_SIM_HOST_SLOTS` (default 4) `flock` slots before it boots, so
  concurrent runs queue instead of exhausting the cluster. A lock dies with its process.
- A harness API call whose answer is lost (timeout, refused) is logged as status 0 and never
  ends the persona schedule; a held-action decision sent without an answer is kept as an
  `ambiguous` decision. The harness API client waits 30 s.
- `ci/run.sh` pytest step: the main suite on `SIBYL_CI_WORKERS` (default 6) xdist workers with
  `-m "not serial"`; then the `serial` tests (timing budgets: gateway latency bench, scoring
  perf, ingest throughput, scrub linearity) alone; one coverage floor over all processes and a
  skip guard per junit file.
- `ci/run.sh` runs the smoke scenarios **beside** the xdist suite only when the cluster has
  `SIBYL_CI_PG_SLOTS` (default 150) free connections, otherwise **after** it. The dev cluster's
  default `max_connections=100` gives the sequential path; `-c max_connections=300` on the CI
  Postgres service (SHIP lane) gives the concurrent one.

## Running the catalogue

    uv run python -m sibyl_sim run --smoke --parallel 4 --report out/smoke
    uv run python -m sibyl_sim run --all --parallel 4 --report out/all     # ~75 min at parallel 4

Keep `--parallel` at 4 or below on a `max_connections=100` cluster.
