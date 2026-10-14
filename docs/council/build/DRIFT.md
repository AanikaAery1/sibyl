# Model drift detection (D51, wave 3 lane DRIFT)

Deterministic, explainable and watch-only. No LLM anywhere in the path. Code: `services/control/src/sibyl_control/worker/drift/` (loop, 60 s), `api/drift/`, migration `0018_drift.sql`, schemas `sibyl_schemas/_enums_drift.py` and `sibyl_schemas/models/drift.py`.

## Unit of comparison
One **baseline** per agent + provider + requested model (`events.model`).
- `collecting`: created when the key is first seen (discovery looks at the last hour).
- `frozen`: once it has at least 500 calls over at least 6 h. It freezes on its oldest 5,000 calls and stores the distributions, the served models (`response_model`) and the fingerprints (`attrs.system_fingerprint`). A collecting baseline that never fills slides its start to stay within 7 days.
- `superseded`: after `POST /agents/{agent_id}/drift/baseline` (scope `drift:write`, audited `drift.baseline_reset`, reason required). The reset starts collecting again from `since`, which defaults to now. A past `since` re-freezes on recent traffic at the next tick. The reset also resolves the key's open drift alerts.

Every 10 min each frozen baseline is compared with the last hour (newest 5,000 calls). Each evaluation writes one immutable `drift_report` that holds every feature's numbers.

## Features and statistics
| Feature | Source | Statistic |
|---|---|---|
| output_tokens, input_tokens, latency_ms | `gen_ai.request` | PSI over the baseline's decile bins (right-closed) |
| refusal, truncation, tool_call share | successful `gen_ai.request` (finish reasons, `quality.refusal`; same derivation as the rollup) | Jensen–Shannon, base 2 |
| error_class mix | all `gen_ai.request` (`ok` or error class) | Jensen–Shannon |
| schema_fail share | `tool.call` (`schema_valid = false` or schema error types), per agent | Jensen–Shannon |
| tool_bigram mix | consecutive `tool.call` names within a task, per agent; top 20 kept, the rest pooled as `__other__` | Jensen–Shannon |

- **PSI:** sum of (a − e)·ln(a/e). Each proportion is floored at 1e-4.
- **JS:** symmetric and bounded to [0, 1].

## Noise floor
Two samples of one distribution differ by chance. Verdicts therefore compare the **excess** = max(0, value − floor) with the thresholds:
- PSI floor = (k − 1)(1/n_baseline + 1/n_window)
- JS floor = (k − 1)(1/n_baseline + 1/n_window) / (8 ln 2)

Each report keeps the value, the floor, the excess, both thresholds, both sample counts and the top 3 movers (bins or categories).

## Minimum samples
- 200 calls in the window for call-based features (deployment default; tenant-tunable).
- 50 tool calls for tool-based features (deployment default; tenant-tunable).
- A feature below its minimum on either side is `insufficient_samples` and never decides a verdict.
- Identity checks need a value seen at least 3 times in the window.

## Thresholds (tenant-tunable since wave 4 HARDEN)
| Statistic | Tunable name | watch default | drift default | Accepted range |
|---|---|---|---|---|
| PSI (numeric) | `psi_watch` / `psi_drift` | 0.10 | 0.25 | 0.01–2.0 |
| JS, two categories (shares) | `js_two_category_watch` / `_drift` | 0.005 | 0.02 | 0.0005–0.5 |
| JS, many categories (error mix, bigrams) | `js_many_category_watch` / `_drift` | 0.05 | 0.10 | 0.005–1.0 |
| Minimum calls in a window | `min_samples_calls` | 200 | | 50–5,000 |
| Minimum tool calls in a window | `min_samples_tools` | 50 | | 10–20,000 |

The report verdict is the worst feature verdict: `none`, `watch` or `drift`.

**Why these ranges.** Below 0.01 PSI on decile bins, or below 0.0005 JS on a share (about a
1 % → 1.5 % move), a threshold sits inside sampling noise. JS is bounded by 1, and a share
cannot move by more than about 0.5 JS. PSI above 2.0 never reads on realistic shifts. The window
loads at most 5,000 calls and 20,000 tool calls, so higher minimums could never be met. Note
that a frozen baseline needs only 500 calls: a call minimum above that baseline's size makes its
call features `insufficient_samples` until the baseline is reset.

**Fallback.** The overrides live in `drift_thresholds` (migration `0026_hardening.sql`): one row
per tenant, RLS, every value nullable. NULL, or no row, means the deployment default
(`worker/drift/config.py` `DEFAULT_CONFIG`). Each value falls back on its own: overriding only
`psi_drift` keeps the default `psi_watch`.

Once per tick, the drift loop resolves the tenant's row onto the deployment config
(`TenantThresholds.apply`). It judges that tenant's verdicts and minimum samples with the
result; other tenants keep the defaults. Each report's `config` records the effective tunable
values (`thresholds`) and the names the tenant overrode (`overrides`). Each feature result
already carries the `watch` and `drift` it was judged with.

As a safeguard, a stored pair whose effective watch is not below its effective drift keeps the
defaults for that statistic, and the loop logs it. The API refuses such a pair, so this can only
happen if a deployment default moves under a stored override.

**API.**
- `GET /drift/thresholds` (scope `drift:read`, every role) returns `values` (per name: `value`,
  `default`, `source` `tenant` | `default`, `minimum`, `maximum`), `version`, `updated_at`,
  `updated_by_user_id` and `watch_only: true`. The ETag is `"<version>"`, or `"0"` before the
  first save.
- `PUT /drift/thresholds` (scope `drift:write`: Owner, Admin, Security admin; no step-up).
  - It needs If-Match: the ETag from GET; `*` or `"0"` for the first write. A stale ETag is a 412
    with the current document.
  - It needs a `reason` of 10–2,000 characters.
  - It replaces the whole override set. A null or omitted field uses the default, so a body with
    only `reason` resets every value. The row is kept with NULLs, so the version keeps counting.
  - These return 422 `validation_failed` with a pointer to the field: a value out of range, a
    string where a number is expected, a fractional minimum, an unknown field, or an effective
    watch ≥ drift for a statistic (an override checked against the other value's default too).
  - It is audited `drift.thresholds_updated` (resource `drift_thresholds`, reason required). The
    detail holds `before` and `after`, each with the eight nullable overrides; thresholds are
    decimal strings because the audit chain is canonical JSON without floats.
  - It emits no outbox or SSE event: config changes are not evented, and the loop reads the row
    on its next tick.

## Model identity
- `served_model_mismatch`: the served model is not the requested model, nor a version-tagged snapshot of it, and the baseline never saw it. `gpt-4o` → `gpt-4o-2024-08-06` matches; `gpt-4o` → `gpt-4o-mini` is a mismatch.
- `new_served_model`: a snapshot of the requested model that the baseline never saw.
- `new_fingerprint`: a fingerprint the baseline never saw. Only checked when the baseline saw fingerprints at all.

## Alerts and hysteresis
- `silent_drift`: raised after 2 consecutive `drift` verdicts. Resolved after 3 consecutive verdicts below `drift`; `watch` counts as clean.
- `model_change`: raised on the first identity finding. Resolved after 3 clean evaluations.
- One live alert per key. Both use the existing alert lifecycle: outbox topic `alert`, audit `alert.fired` (actor `rule`), re-open inside cooldown. A tenant admin can disable either rule.
- Per ruling B23, these two are the **only** drift alerts.

## Watch-only guarantee
- Both rules are kind `leading` with cap 0 in every tier. The saga trigger reads only `detected` alerts, so drift can never start a failover.
- The health engine's `drift_cusum` factor is fed at severity 0.25 (watch) or 0.5 (drift), with cap 0 (B23). The factor is `alert_only` (listed on the health document, penalty 0, weight 0) and `score_only` (no rule hysteresis, so no `drift_cusum` alert).
- As a result, score, band and horizons (r = severity × cap = 0) are unchanged, so drift alone never triggers automation.

## Retention
- Reports: 30 days.
- Superseded baselines: 30 days after supersession (B24), together with any report left on them.
- Both are deleted by the drift loop in batches of 1,000.

## API
`GET /drift` (fleet, paged, with a summary), `GET /agents/{agent_id}/drift`, `GET /drift/reports/{report_id}`, `GET /drift/thresholds` (scope `drift:read`, every role), `POST /agents/{agent_id}/drift/baseline`, `PUT /drift/thresholds` (scope `drift:write`: Owner, Admin, Security admin). The thresholds endpoints are described under Thresholds.
