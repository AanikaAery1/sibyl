# Wave 3: plug-and-play agent monitoring, model drift, Sentinel, and the leftovers (chair, 2026-10-12)

The founder's request (2026-10-12): agent monitoring for agentic systems, plug-and-play, that also detects
model drift, and finish the previous tasks. Decisions D50–D52 below. Rulings continue at B23.

## Decisions
- **D50 Plug-and-play monitoring.** One line (`sibyl.instrument()`) or zero code (`sibyl-run app.py`,
  env-configured) auto-detects and instruments the model clients and agent frameworks present:
  OpenAI, Anthropic and Google Gen AI clients; LangChain/LangGraph, OpenAI Agents SDK, CrewAI.
  Multi-agent systems report a **run tree** (parent run, agent-to-agent handoffs, steps). Unknown
  agents seen in telemetry are auto-registered as `discovered` (never routed or failed over until an admin confirms them; Action Gate and kill switch still apply, B37). The gateway speaks native Anthropic Messages and Gemini as well as OpenAI.
- **D51 Model drift detection.** Deterministic and explainable, no LLM in the path:
  1. **Model identity drift**: the served model (`response_model`) or provider fingerprint
     (`system_fingerprint`) changes versus what the agent was served in its baseline, or differs
     from the requested model.
  2. **Behavioural drift**: per agent+model, distributions of output tokens, input tokens, latency,
     refusal share, truncation share, tool-call rate, schema-failure share, error-class mix and
     tool-sequence bigrams, compared to a frozen baseline window with PSI (binned) and
     Jensen–Shannon (categorical), with minimum sample sizes. Every report shows the per-feature
     numbers. Drift is **watch-only**: it raises `silent_drift` / `model_change` alerts and feeds the
     existing `drift_cusum` factor at its seeded cap (0), so drift alone never triggers automation.
  3. **Semantic drift** (purpose drift, injection-like trajectories) is Sentinel's advisory job (D52).
- **D52 Sibyl Sentinel built (advisory).** Opt-in per tenant; runs on the tenant's own Anthropic,
  OpenAI or Gemini key (vaulted with `seal_credential`, egress allowlisted); explains incidents,
  recommends on held actions, reviews sampled trajectories for semantic drift, summarises the fleet.
  It can open `sentinel_finding` alerts (watch only) and attach recommendations; it can never allow,
  block, approve, fail over or change policy. Every finding records provider, model, prompt hash,
  tokens and cost. Respects capture mode (metadata-only tenants send no content). Budget per day.

## Lanes (wave 3A, worktrees; each lane owns only its paths)
| Lane | Owns | Migration |
|---|---|---|
| **DRIFT** | `worker/drift/**`, `api/drift/**`, `sibyl_schemas/models/drift.py`, drift rules catalog entries | `0018_drift.sql` |
| **SENTINEL** | `worker/sentinel/**`, `api/sentinel/**`, `core/llm/**` (provider-neutral adapter), `sibyl_schemas/models/sentinel.py` | `0019_sentinel.sql` |
| **PLUG** | `packages/sibyl-sdk/**`, `sibyl_schemas` event model additions, `ingest/**` mapping, auto-discovery | `0020_run_tree_discovery.sql` |
| **GW-NATIVE** | `services/gateway/**` | none |
| **AG-LIVE** | `api/action_gate/**`, `worker/held_actions/**`, `sibyl_schemas/action_gate.py` request/record models | `0021_action_gate_live.sql` |
| **HARNESS** | `sibyl-sim/**`, `worker/scoring/**`, `worker/predict/**`, `worker/alerts/**` (detection-gap fix only) | none |

Shared files every API lane may append to (chair merges): `openapi/sibyl-api.v1.yaml`, contract
scenarios, `worker/loops.py` (add one `LoopSpec` line), role/scope seeds, audit action enums.
Append only; never reorder or rewrite another lane's entries.

## Cross-lane field names (frozen)
- Event attrs: `system_fingerprint` (string ≤ 128), `parent_run_id` (uuid), `handoff_to_agent`
  (agent ref), `step_index` (int). PLUG writes them; DRIFT reads `attrs->>'system_fingerprint'`.
- Held action on-behalf-of: request field `on_behalf_of` (`{"kind":"user","id":<uuid>}` or
  `{"kind":"external","ref":<string ≤ 128>}`), gateway header `X-Sibyl-On-Behalf-Of`, SDK
  `sibyl.on_behalf_of(...)` context manager. AG-LIVE owns the model; GW-NATIVE and PLUG pass it.
- Alert kinds: `silent_drift`, `model_change` (DRIFT), `sentinel_finding` (SENTINEL).
- New scopes: `drift:read`, `drift:write`, `sentinel:read`, `sentinel:admin`.

## Wave 3B (after 3A merges)
Console: drift view, Sentinel findings and setup, plug-and-play onboarding and run tree, Action
Gate live wiring; e2e/a11y/visual tests and regenerated baselines; INT-3 completion
(`wip/int3-partial`); demo re-seed with role personas; docs and PDFs.

## Rules for every lane
TDD; `make ci`-equivalent green for the packages touched (≥ 80 % coverage); strict contract
scenarios for every new route (authz matrix + audit); RLS on every new tenant table; no LLM in any
enforcement or detection path; fail closed on enforcement; never print secrets; `UV_SYSTEM_CERTS=1`
for uv; never disable TLS. **Do not commit or push**: leave changes in the worktree and hand back a
report listing files, tests run with results, deviations from this spec and open questions.
