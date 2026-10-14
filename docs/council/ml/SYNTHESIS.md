# Step 5 — ML approach: chair synthesis (2026-10-10)

Members: ai-engineer (505 lines, lead: features, health score, prediction rules, Phase 2 learned layer, explainability, EU AI Act risk, worker), database-architect (629, aggregate tables, materialisation, training view, cost model, consolidated amendment DDL), sre-engineer (400, SLI/SLO framing, burn rates, hysteresis, false-failover budget, drills, scoring-layer observability), qa-expert (498, `sibyl-sim` harness, 28 scenarios, acceptance gates, Phase 2 promotion gate). Consolidated: `ML.md`.

## Conflicts surfaced and chair rulings (R37–R51)

| # | Conflict | Members | Ruling |
|---|---|---|---|
| R37 | Quality-proxy signals have no alert rule rows (harness cannot gate silent degradation) | qa Q1 vs ai-eng §1 | ai-engineer's `quality_proxy`, `tool_loop`, `drift_cusum`, `anomaly_score` rule ids are registered; add detected rules R6 refusal share, R7 truncation share, R8 schema-failure share and leading rule L6 refusal trend to the seed table. Silent degradation is gated in Phase 1. |
| R38 | `continuity_plan.rto_s/rpo_s` defaults contradict D23 | sre Q2 | Amend to `rto_s = 900/3600/14400`, `rpo_s = 60/300/900`. |
| R39 | Tier-1 approval timeout 600 s vs 15-min RTO | sre Q3 | Keep 600 s; console warns when `approval_timeout_s > 0.5 × rto_s`. D22 force-hold stands. |
| R40 | Predicted failover on tier 2: immediate vs degrade-then-auto | ai-eng Q6 | `degrade_then_auto` for tier 2 (20 s degraded pause), `auto` for tier 3; both on `continuity_plan.preemptive_mode`. Consistent with D13. |
| R41 | Automation precision gate for `"0.60"` band: release criterion vs tenant tunable | sre Q6, qa Q3 | **Release criterion.** Predicted path on tiers 2–3 fires at `≥ "0.60"` only once `sibyl-sim` shows ≥ 75 % precision / ≥ 60 % recall at 15 m; until then `"0.90"` only. qa's tier-3 floors (0.80/0.60) stand for detection; leading rules get `hysteresis_in ≥ 3`. |
| R42 | Verdict minimums for Phase 2 promotion; `unsure` handling | qa Q4, db Q5, ai-eng Q7 | qa floors adopted (≥ 300 verdicts, ≥ 50/tier, ≥ 100 fp, ≥ 14-day shadow). `unsure` and D33 null verdicts excluded from training. Weak labels admitted with `label_strength ∈ {verdict, outcome, provider_feed}` as a fold feature; operator verdicts are the sole evaluation set. No auto-verdicts; backlog share is an SLI on the model card. |
| R43 | Cross-tenant signals / pooled models | ai-eng Q1, Q2 | No cross-tenant features in Phase 1–2. Per-tenant models; synthetic-trained `sibyl-gbt:0.x` is the day-one shadow, never promoted without the tenant's own verdicts. |
| R44 | `psycopg` 3 is LGPL vs D15 permissive-only | ai-eng Q3 | `asyncpg` (Apache-2) for the worker. Licence inventory notes it. |
| R45 | Sim-time acceleration needs a test-only clock | qa Q2 | No product clock override. Latency scenarios run at 1×; nightly ~90 min accepted. |
| R46 | `sibyl-sim` in the self-hosted bundle | qa Q6 | Dev-only in Phase 1 (R32). Customer drills are a Phase 2 roadmap item behind a real feature flag. |
| R47 | Fourth cause-based page | sre Q4 | Allowed: `SibylRulesCursorStuck` (> 5 min). Four pages total. |
| R48 | Flap-pin direction on tier 3 | sre Q5 | Tier 3: pin at the better band, alert only. Tiers 1–2: pin at the worse band. |
| R49 | Feature snapshot storage | db Q2, Q3, Q4 | `feature_snapshot.doc` to BlobStore with ≤ 2 KB in-row summary; sweep sample rows > 90 d unless referenced. `agent_metrics_5m` materialised. `prediction` written sparsely, 400 d. |
| R50 | Golden/threshold ownership | qa Q5 | Rule and penalty changes: ai-engineer with chair sign-off. Oracle and scenario changes: qa-expert. Threshold edits require dry-run replay first (sre guard rail 7). Recorded in `ML.md`. |
| R51 | Editor reconciliations not covered above (ML.md §10.4) | editor | **Confirmed by chair**: ai-engineer penalty arithmetic (`100 − Σ penalty`) is canonical with sre's six SLI families as the grouping/SLO layer and sre's tier band edges (+4 dead-band); Step 3 rule codes R1–R5/L1–L5 canonical, sre extras become R9 `heartbeat_missing` and L7 `continuity_unverified`, `quality_proxy` = max of R6–R8; ai-engineer seed thresholds with sre's as second tuning candidate; `health_snapshot` write-on-change + 60 s heartbeat (amends R17); abstention ≤ 30 % shadow floor / ≤ 20 % promotion bar; database-architect counter spellings win. |

## Accepted without conflict
- Health score = six SLIs with tier weights; bands map to agent-minute SLOs 99.5 / 99.0 / 98.0 % (sre).
- Very-fast burn pair (15 m / 2 m) is the detected-failure trigger; leading rules can never raise critical on tier 1 alone (sre).
- False-failover budget per 30 d per agent: tier 1 zero automated, tier 2 ≤ 1, tier 3 ≤ 2; seven guard rails incl. per-agent breaker after 2 undone in 7 d (sre).
- `alert_rule.scope='platform'` additive value; `risk_assessment` table + `GET /agents/{id}/risk-assessment` route (ai-eng Q4, Q5).
- LLM-as-judge: Phase 2, tenant-configured OpenAI-compatible endpoint, 1 % sampling, nothing bundled (ai-eng Q8).
- `scoring_config` promotable to seed via `sibyl rules promote` (db Q6). Per-agent `slo_target` deferred to Phase 2; tier defaults suffice (sre Q1).

## DATAMODEL amendments (added to the Step 4 list; database-architect §6 holds consolidated DDL)
`ml_model`, `ml_prediction_shadow`, `risk_assessment`, `agent_metrics_5m`, nine new `agent_metrics_1m` counters, `payload_refs.kind` += `model_artifact|model_card|feature_snapshot`, `alert_rule.scope` += `platform`, `continuity_plan` RTO/RPO defaults (R38), `preemptive_mode`, `label_strength` on labels, rule seed rows R6–R8/L6.

## Open questions for the founder (defaults the council proceeds on)
1. R41: the `"0.60"` automation gate is a release criterion, not a tenant tunable. Default yes.
2. R43: no cross-tenant pooling of signals or models, even anonymised and opt-in, through Phase 2. Default yes.
3. R46: `sibyl-sim` stays dev-only in Phase 1; customer drills are Phase 2. Default yes.
4. R40: tier-2 predicted failover degrades first for 20 s before shifting. Default yes.
5. sre SLO targets 99.5 / 99.0 / 98.0 % agent-minutes by tier as the Phase 1 defaults. Default yes.

## Next
Step 6 — phased roadmap: sprint-prioritizer leads, project-shipper on launch/readiness, chief-architect on sequencing risk, product-manager on scope cut lines. Waits for the founder's review of Step 5.
