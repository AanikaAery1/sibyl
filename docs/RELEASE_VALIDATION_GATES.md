# Sibyl security and release-validation gates (October 15, 2026)

This document distinguishes **code committed for review** from **security properties
actually demonstrated**. None of the draft PRs below is a production certification.

## In-progress PRs (in AanikaAery1/sibyl; original MK-JKC/sibyl unchanged)

- [#1 Atomic agent budget ledger](https://github.com/AanikaAery1/sibyl/pull/1):
  adds transactionally locked period and request rows plus PostgreSQL integration tests.
  **Not yet wired into the gateway pre-dispatch path.**
- [#2 Observed monthly spending in policy snapshots](https://github.com/AanikaAery1/sibyl/pull/2):
  replaces hard-coded zero with priced gateway telemetry. Event ingestion is asynchronous
  and can miss unpriced or bypass traffic, so it is reporting, not hard enforcement.
- [#3 Audit verifier header and trusted-terminal checks](https://github.com/AanikaAery1/sibyl/pull/3):
  checks declared export boundaries and optionally a separately pinned terminal
  sequence/hash. Self-reported export boundaries alone do not establish completeness.
- [#4 Sensitive tools fail closed when SDK uninitialized](https://github.com/AanikaAery1/sibyl/pull/4):
  blocks explicitly sensitive decorated and instrumented tools in SDK startup gaps.
  It cannot block uninstrumented processes with direct tool credentials.

## CI: failing baseline, and how to validate forks

The original repository's GitHub Actions CI run 38607693225 (October 14, 2026)
failed. In the logs reviewed, failures included scrubber adversarial timing checks,
gateway concurrent latency checks and a smoke time budget. These are **not**
fixed by relaxing their thresholds. Measure deterministic performance on the
same reference runner, profile hot paths, and separate runner contention from
algorithmic regressions.

The fork has no recorded Actions runs as of October 15, 2026. A maintainer should
open the fork's **Actions** tab, enable workflows if GitHub prompts for permission,
and confirm that each draft pull request triggers the `ci` workflow. The CI gates
include PostgreSQL 17, Python lint/types/tests, console checks and performance
budgets. Locally, use:

```bash
make db-up
make ci
```

Do not merge a PR based only on independently developed unit tests; rerun the full
native repo test suite and inspect coverage, including migration compatibility.

## Hard budget reservations: required end-to-end gate

The budget ledger alone is not enforcement. Before calling it a hard cap:

1. Every billable gateway/provider attempt (including retry and fallback) MUST
   reserve a conservative priced maximum through the shared control plane.
2. The gateway must refuse when pricing is unknown or the budget service is
   unreachable, for configured fail-closed budgets. Never fall back to cached
   telemetry or per-replica counters.
3. Associate one unambiguous idempotency key with each provider attempt. A
   duplicate reservation NEVER permits a second provider dispatch.
4. Settle only on authoritative billable usage; preserve uncertain reservations
   until reconciled. Detect, record and alarm on actual cost > estimated maximum.
5. Exercise concurrent replicas, cancellation, streaming disconnects, delayed
   provider billing, retries, fallback, rollover between UTC months, cap reductions,
   tenant isolation and tampering. Add reconciliation and retention/erasure coverage.
6. Consider policy and configuration changes while requests are in flight, then
   verify costs reported in signed snapshots agree with ledger accounting.
7. Review database grants, RLS and migration/erasure behavior under real PG17.

**Never deploy the ledger migration as an enforcement feature alone.** It is
unwired foundation code until the above controls pass.

## Security testing and audit integrity

- Build an isolated staging deployment; obtain an explicit written testing scope,
  contact and rollback plan. Do not run unapproved penetration tests against a
  live endpoint.
- Test cross-tenant authorization, leaked/revoked credentials, policy freshness,
  Action Gate bypass via direct execution, streaming tool calls, replay and races.
- Audit verification must use independently obtained signing trust and *latest*
  expected sequence/head hash. Truncation with a self-consistent older anchor
  is not detected without this external expectation.
- Commission an independent security review after implementing the fixes;
  classify, remediate and retest findings before release.

## Neural prediction: research gate, not product guarantee

There are no verified local open-weight model checkpoints or independently
labeled real agent trajectories in this workstream. Consequently no neural
predictive capability has been validated. A defensible experiment needs:

- A frozen event schema capturing only observations available **before** an action.
- Consent and privacy review for any sampled production trajectories.
- Independently adjudicated outcome labels, with train/test separation by
  workflow, organization and time to prevent leakage.
- Simple rules and non-neural baselines before activation probes.
- Precision/recall, false-positive rate, calibration, lead time, OOD robustness,
  drift monitoring and confidence intervals across meaningful deployment slices.
- Shadow/advisory mode only until prospective trials establish utility; never
  grant execution authority solely from a neural risk score.

## Release decision

**Current status: NOT production-certified, NOT pen-tested, NOT neuronally
validated, and NOT deployed by this workstream.** Only after CI, integration,
review, independent testing and an approved runbook may a deployment owner
authorize staged rollout, rollback and post-release observation.

## Activating GitHub Actions in a fork

After enabling Actions in a fork, previous pull-request events may not be
replayed automatically. Trigger a fresh **synchronize** event by committing a
meaningful change to a PR branch, or dispatch the `ci` workflow manually in
the fork's **Actions** tab using **Run workflow** and select the target branch.

Check both the `python` and `console` jobs, plus their downloadable reports.
Do not treat an enabled workflow as a passed workflow: a run must actually
complete successfully on the same commit that is proposed for merging.
