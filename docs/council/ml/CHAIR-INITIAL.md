# Step 5 — ML approach: chair position (2026-10-10)

Inputs: `docs/BRIEF.md`, `docs/council/DECISIONS.md` (D1–D35; D6/D13 failover tiers, D24/D33 verdicts, D10 zero budget), `docs/council/datamodel/ai-engineer.md` §6 (ML contract already frozen in Step 3), `docs/council/datamodel/DATAMODEL.md` (health/risk/alert domains), `docs/council/api/API.md` §4 ingest, §5 health/risk routes, §6 state machines.

## Chair position
1. **Phase 1 is rules + statistics, not learned models.** Health score = explainable weighted composite of windowed SLIs (error rate, p95 latency, rate-limit proximity, budget burn, provider status, output-quality proxies). Every score ships with a per-feature contribution list; no black box.
2. **Prediction in Phase 1 = leading-indicator rules** (EWMA trend, CUSUM change-point, rate-limit/budget proximity, provider status feed). These fill the same `prediction` contract that Phase 2 learned models will fill, so the API never changes.
3. **Phase 2 learned layer** trains on the verdict-labelled alert history (D24/D33 is the labelling mechanism). Candidates: gradient-boosted trees on windowed features per agent, with calibration; anomaly detection (isolation forest / seasonal-ESD) for unknown-unknowns. Everything OSS, CPU-only, trainable on one box (D10).
4. **Evaluation harness is a Phase 1 deliverable**: replayable synthetic incident scenarios (20 agents, 3 providers, chaos knobs) with ground truth; metrics = lead time before failure, precision/recall per tier, false-failover rate, time-to-detect. Hysteresis and cooldowns tuned against it.
5. **Feature storage is Postgres**: materialised windowed aggregates (1m/5m/1h) via worker, no feature store product.
6. Output-quality signals (refusal rate, empty/truncated output, schema-validation failure of tool calls, user feedback/outcome events) are first-class features; LLM-as-judge is Phase 2 and tenant-opt-in.

Members: ai-engineer (leads: features, scoring, prediction rules, Phase 2 model plan), database-architect (aggregate tables, retention, query cost), sre-engineer (health score as SLI/SLO, alert hysteresis, burn rates), qa-expert (evaluation harness, scenario catalogue, acceptance thresholds). Each writes `docs/council/ml/<member>.md`. Chair synthesizes `SYNTHESIS.md` + `ML.md`.
