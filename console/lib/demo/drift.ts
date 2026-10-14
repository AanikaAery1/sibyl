/**
 * Model drift (D51) in demo mode, shaped exactly like the contract (`/drift`,
 * `/agents/{id}/drift`, `/drift/reports/{id}`, `POST /agents/{id}/drift/baseline`).
 *
 * Reports are a pure function of (agent, key, evaluation time, scenario marks): every frozen
 * baseline is evaluated every 10 minutes, plus at the scripted drift beats. Per-feature numbers
 * follow DRIFT.md: noise floor from the bin count and both sample sizes, excess over the floor,
 * watch / drift thresholds, minimum samples (200 calls, 50 tool calls). Watch-only: nothing here
 * touches routing or health.
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type {
  AgentDrift,
  DriftAlertRef,
  DriftBaseline,
  DriftBaselineReset,
  DriftBaselineResetResult,
  DriftFeature,
  DriftFeatureResult,
  DriftIdentityFinding,
  DriftKeySummary,
  DriftReport,
  DriftReportSummary,
  DriftVerdict,
  FleetDriftSummary,
} from "@/lib/api/monitor";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { MINUTE, hexFor, idFor, iso, noise } from "./core";
import { requireScope } from "./actions";
import { servedAt } from "./health";
import { markAt, monitorState } from "./monitor-state";
import { appendAudit, emit, type AgentRt, type World } from "./world";

const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const EVAL_MS = 10 * MINUTE;
const HISTORY = 12;
const MIN_CALLS = 200;
const MIN_TOOLS = 50;
const LN2x8 = 8 * Math.LN2;

export const DRIFT_MARKS = { identity: "drift-identity", behaviour: "drift-behaviour", confirm: "drift-confirm" } as const;

interface FeatureDef {
  feature: DriftFeature;
  statistic: "psi" | "js";
  k: number;
  tool: boolean;
  watch: number;
  drift: number;
}

const FEATURES: readonly FeatureDef[] = [
  { feature: "output_tokens", statistic: "psi", k: 10, tool: false, watch: 0.1, drift: 0.25 },
  { feature: "input_tokens", statistic: "psi", k: 10, tool: false, watch: 0.1, drift: 0.25 },
  { feature: "latency_ms", statistic: "psi", k: 10, tool: false, watch: 0.1, drift: 0.25 },
  { feature: "refusal", statistic: "js", k: 2, tool: false, watch: 0.005, drift: 0.02 },
  { feature: "truncation", statistic: "js", k: 2, tool: false, watch: 0.005, drift: 0.02 },
  { feature: "tool_call", statistic: "js", k: 2, tool: false, watch: 0.005, drift: 0.02 },
  { feature: "error_class", statistic: "js", k: 5, tool: false, watch: 0.05, drift: 0.1 },
  { feature: "schema_fail", statistic: "js", k: 2, tool: true, watch: 0.005, drift: 0.02 },
  { feature: "tool_bigram", statistic: "js", k: 12, tool: true, watch: 0.05, drift: 0.1 },
];

const BASE_N = 5000;

// ── keys and baselines ─────────────────────────────────────────────────────

interface Key {
  rt: AgentRt;
  provider: string;
  model: string;
  /** Number of resets before this baseline (its generation). */
  gen: number;
  primary: boolean;
  since: number;
}

const resetsOf = (w: World, agentId: string) => monitorState(w).driftResets.filter((r) => r.agentId === agentId);

function baselineId(w: World, k: Pick<Key, "rt" | "provider" | "model" | "gen">): string {
  return idFor(`drift-baseline:${w.slug}:${k.rt.spec.slug}:${k.provider}:${k.model}:${k.gen}`);
}

/** A dated snapshot name like the provider returns (`gpt-5` → `gpt-5-2025-08-07`). */
function snapshotOf(model: string): string {
  if (model.startsWith("gpt-5")) return `${model}-2025-08-07`;
  if (model.startsWith("claude")) return `${model}-20250929`;
  return model;
}

function fingerprintsOf(provider: string, slug: string): string[] {
  return provider === "openai" ? [`fp_${hexFor(`fp:${slug}`, 10)}`] : [];
}

function keysAt(w: World, rt: AgentRt, t: number): Key[] {
  if (rt.createdAt > t) return [];
  const resets = resetsOf(w, rt.id).filter((r) => r.at <= t);
  const last = resets.at(-1);
  const gen = resets.length;
  const keys: Key[] = [{ rt, provider: rt.spec.provider, model: rt.spec.model, gen, primary: true, since: last ? last.since : rt.discovered ? rt.createdAt : w.anchorAt - 2 * DAY - 6 * HOUR }];
  const seen = new Set([`${rt.spec.provider}/${rt.spec.model}`]);
  for (const seg of rt.served) {
    if (seg.at > t || !seg.provider || !seg.model || seen.has(`${seg.provider}/${seg.model}`)) continue;
    seen.add(`${seg.provider}/${seg.model}`);
    keys.push({ rt, provider: seg.provider, model: seg.model, gen, primary: false, since: Math.max(seg.at, last?.since ?? 0) });
  }
  return keys;
}

/** Frozen only for an untouched primary key of a registered agent (collecting never freezes inside the demo's hours). */
function isFrozen(k: Key): boolean {
  return k.primary && k.gen === 0 && !k.rt.discovered;
}

function callsBetween(rt: AgentRt, from: number, to: number): number {
  return Math.max(0, Math.floor((rt.spec.rpm * (to - from)) / MINUTE));
}

function baselineOf(w: World, k: Key, t: number): DriftBaseline {
  const id = baselineId(w, k);
  const frozen = isFrozen(k);
  const resets = resetsOf(w, k.rt.id).filter((r) => r.at <= t);
  const last = resets.at(-1);
  const supersedes = k.gen > 0 ? baselineId(w, { ...k, gen: k.gen - 1 }) : null;
  if (frozen) {
    const frozenAt = w.anchorAt - 2 * DAY;
    return {
      id,
      agent_id: k.rt.id,
      provider: k.provider,
      model: k.model,
      state: "frozen",
      window_start: iso(k.since),
      window_end: iso(frozenAt),
      sample_count: BASE_N,
      tool_sample_count: k.rt.spec.sdk ? 3100 : 0,
      frozen_at: iso(frozenAt),
      served_models: [snapshotOf(k.model)],
      fingerprints: fingerprintsOf(k.provider, k.rt.spec.slug),
      features: Object.fromEntries(FEATURES.map((f) => [f.feature, f.statistic === "psi" ? { kind: "numeric", bins: f.k } : { kind: "categorical", categories: f.k }])),
      reset_by_user_id: null,
      reset_reason: null,
      supersedes: null,
      superseded_by: null,
      superseded_at: null,
      last_evaluated_at: iso(lastEvalAt(w, t)),
      created_at: iso(k.since),
    };
  }
  return {
    id,
    agent_id: k.rt.id,
    provider: k.provider,
    model: k.model,
    state: "collecting",
    window_start: iso(k.since),
    window_end: null,
    sample_count: Math.min(BASE_N, callsBetween(k.rt, k.since, t)),
    tool_sample_count: k.rt.spec.sdk ? Math.floor(callsBetween(k.rt, k.since, t) * 0.6) : 0,
    frozen_at: null,
    served_models: [],
    fingerprints: [],
    features: {},
    reset_by_user_id: k.primary ? (last?.userId ?? null) : null,
    reset_reason: k.primary ? (last?.reason ?? null) : null,
    supersedes: k.primary ? supersedes : null,
    superseded_by: null,
    superseded_at: null,
    last_evaluated_at: null,
    created_at: iso(k.since),
  };
}

/** Earlier generations of the primary key, superseded by resets. */
function supersededBaselines(w: World, rt: AgentRt, t: number): DriftBaseline[] {
  const resets = resetsOf(w, rt.id).filter((r) => r.at <= t);
  return resets.map((r, gen) => {
    const k: Key = { rt, provider: rt.spec.provider, model: rt.spec.model, gen, primary: true, since: gen === 0 ? w.anchorAt - 2 * DAY - 6 * HOUR : (resets[gen - 1]?.since ?? r.at) };
    const b = baselineOf(w, k, r.at);
    return { ...b, state: "superseded", superseded_by: baselineId(w, { ...k, gen: gen + 1 }), superseded_at: iso(r.at), last_evaluated_at: b.last_evaluated_at };
  });
}

// ── reports ────────────────────────────────────────────────────────────────

function lastEvalAt(w: World, t: number): number {
  return w.anchorAt + Math.floor((t - w.anchorAt) / EVAL_MS) * EVAL_MS;
}

function evalTimes(w: World, t: number): number[] {
  const last = lastEvalAt(w, t);
  const times = Array.from({ length: HISTORY }, (_, i) => last - (HISTORY - 1 - i) * EVAL_MS);
  for (const id of Object.values(DRIFT_MARKS)) {
    const at = markAt(w, id);
    if (at !== null && at <= t && !times.includes(at)) times.push(at);
  }
  return times.sort((a, b) => a - b);
}

interface Shift {
  /** Excess over the floor as a share of the drift threshold (1 = at the drift line). */
  ratio: number;
  top?: [string, number, number][];
}

/** The scripted story per agent at evaluation time x; everything else sits inside the noise. */
function profile(w: World, rt: AgentRt, x: number): { shifts: Partial<Record<DriftFeature, Shift>>; identity: boolean } {
  const slug = rt.spec.slug;
  const after = (id: string): boolean => {
    const at = markAt(w, id);
    return at !== null && x >= at;
  };
  if (slug === "freight-pricer") {
    return { shifts: { output_tokens: { ratio: 0.56, top: [["p90–p100", 0.1, 0.18], ["p80–p90", 0.1, 0.13], ["p0–p10", 0.1, 0.06]] } }, identity: false };
  }
  if (slug === "sales-copilot" && after(DRIFT_MARKS.identity)) {
    return { shifts: { output_tokens: { ratio: 0.48, top: [["p90–p100", 0.1, 0.17], ["p70–p80", 0.1, 0.13], ["p10–p20", 0.1, 0.07]] }, refusal: { ratio: 0.4, top: [["refused", 0.004, 0.012], ["answered", 0.996, 0.988]] } }, identity: true };
  }
  if (slug === "route-optimizer" && after(DRIFT_MARKS.behaviour)) {
    return {
      shifts: {
        tool_bigram: { ratio: 1.42, top: [["geo.lookup → geo.lookup", 0.08, 0.27], ["route.solve → stops.reorder", 0.31, 0.12], ["stops.reorder → route.solve", 0.22, 0.09]] },
        latency_ms: { ratio: 1.18, top: [["p90–p100", 0.1, 0.24], ["p80–p90", 0.1, 0.15], ["p0–p10", 0.1, 0.04]] },
        tool_call: { ratio: 0.46, top: [["with tool calls", 0.61, 0.74], ["no tool calls", 0.39, 0.26]] },
      },
      identity: false,
    };
  }
  return { shifts: {}, identity: false };
}

function featureAt(w: World, k: Key, f: FeatureDef, x: number, nWindow: number, nTools: number): DriftFeatureResult {
  const n = f.tool ? nTools : nWindow;
  const nBase = f.tool ? (k.rt.spec.sdk ? 3100 : 0) : BASE_N;
  const min = f.tool ? MIN_TOOLS : MIN_CALLS;
  const base = { feature: f.feature, statistic: f.statistic, watch: f.watch, drift: f.drift, n_baseline: nBase, n_window: n };
  if (n < min || nBase < min) {
    return { ...base, status: "insufficient_samples", value: null, noise_floor: 0, excess: null, verdict: "none", contributors: [] };
  }
  const floor = f.statistic === "psi" ? (f.k - 1) * (1 / nBase + 1 / n) : ((f.k - 1) * (1 / nBase + 1 / n)) / LN2x8;
  const shift = profile(w, k.rt, x).shifts[f.feature];
  const jitter = Math.abs(noise(`${k.rt.id}:${f.feature}`, Math.floor(x / EVAL_MS)));
  const excess = shift ? shift.ratio * f.drift * (0.97 + 0.06 * jitter) : f.watch * (0.08 + 0.3 * jitter);
  const verdict: DriftVerdict = excess >= f.drift ? "drift" : excess >= f.watch ? "watch" : "none";
  return {
    ...base,
    status: "ok",
    value: floor + excess,
    noise_floor: floor,
    excess,
    verdict,
    contributors: (shift?.top ?? []).map(([label, b, wv]) => ({ label, baseline: b, window: wv })),
  };
}

const WORST: Readonly<Record<DriftVerdict, number>> = { none: 0, watch: 1, drift: 2 };

function reportAt(w: World, k: Key, x: number): DriftReport {
  const served = servedAt(k.rt, x);
  const onKey = served.provider === k.provider && served.model === k.model;
  // Off its key (failed over, or handed to people) the key only saw the calls before the move.
  const nWindow = onKey ? Math.min(BASE_N, k.rt.spec.rpm * 60) : Math.min(BASE_N, callsBetween(k.rt, x - HOUR, Math.max(x - HOUR, servedSince(k.rt, x))));
  const nTools = k.rt.spec.sdk ? Math.floor(nWindow * 0.6) : 0;
  const features = FEATURES.map((f) => featureAt(w, k, f, x, nWindow, nTools));
  const prof = profile(w, k.rt, x);
  const identity: DriftIdentityFinding[] =
    prof.identity && onKey
      ? [
          { kind: "new_served_model", value: `${k.model}-2026-10-08`, count: Math.min(nWindow, 412), requested_model: k.model },
          { kind: "new_fingerprint", value: `fp_${hexFor(`fp-new:${k.rt.spec.slug}`, 10)}`, count: Math.min(nWindow, 412), requested_model: k.model },
        ]
      : [];
  const evaluated = features.filter((f) => f.status === "ok");
  const verdict = evaluated.reduce<DriftVerdict>((v, f) => (WORST[f.verdict] > WORST[v] ? f.verdict : v), "none");
  const maxRatio = evaluated.reduce((m, f) => Math.max(m, (f.excess ?? 0) / f.drift), 0);
  return {
    id: idFor(`drift-report:${w.slug}:${baselineId(w, k)}:${x}`),
    baseline_id: baselineId(w, k),
    evaluated_at: iso(x),
    verdict,
    behaviour_evaluated: evaluated.length > 0,
    identity_changed: identity.length > 0,
    max_ratio: Math.round(maxRatio * 1000) / 1000,
    sample_count: Math.max(0, nWindow),
    agent_id: k.rt.id,
    provider: k.provider,
    model: k.model,
    window_start: iso(x - HOUR),
    window_end: iso(x),
    tool_sample_count: nTools,
    features,
    identity,
    config: { window_s: 3600, evaluate_every_s: 600, min_calls: MIN_CALLS, min_tool_calls: MIN_TOOLS, silent_drift_after: 2, resolve_after_clean: 3, identity_min_count: 3 },
  };
}

/** When the agent last moved onto what it serves at x (or its creation). */
function servedSince(rt: AgentRt, x: number): number {
  let since = rt.createdAt;
  for (const seg of rt.served) if (seg.at <= x) since = seg.at;
  return since;
}

function reportsFor(w: World, k: Key, t: number): DriftReport[] {
  if (!isFrozen(k)) return [];
  return evalTimes(w, t)
    .filter((x) => x >= w.anchorAt - 2 * DAY)
    .map((x) => reportAt(w, k, x));
}

const summaryOf = (r: DriftReport): DriftReportSummary => ({ id: r.id, baseline_id: r.baseline_id, evaluated_at: r.evaluated_at, verdict: r.verdict, behaviour_evaluated: r.behaviour_evaluated, identity_changed: r.identity_changed, max_ratio: r.max_ratio, sample_count: r.sample_count });

// ── views ──────────────────────────────────────────────────────────────────

function keySummary(w: World, k: Key, t: number): DriftKeySummary {
  const b = baselineOf(w, k, t);
  const latest = reportsFor(w, k, t).at(-1) ?? null;
  return {
    baseline_id: b.id,
    agent_id: k.rt.id,
    agent_name: k.rt.spec.name,
    provider: k.provider,
    model: k.model,
    state: b.state,
    frozen_at: b.frozen_at ?? null,
    sample_count: b.sample_count,
    report_id: latest?.id ?? null,
    evaluated_at: latest?.evaluated_at ?? null,
    verdict: latest ? latest.verdict : null,
    identity_changed: latest?.identity_changed ?? false,
    max_ratio: latest?.max_ratio ?? null,
    drifting_features: (latest?.features ?? []).filter((f) => f.verdict !== "none").map((f) => f.feature),
    created_at: b.created_at,
  };
}

function allKeys(w: World, t: number): Key[] {
  return [...w.agents.values()].flatMap((rt) => keysAt(w, rt, t));
}

export function driftFleet(w: World, t: number, q: URLSearchParams): { rows: DriftKeySummary[]; summary: FleetDriftSummary } {
  const all = allKeys(w, t).map((k) => keySummary(w, k, t));
  const verdict = q.get("verdict");
  const state = q.get("state");
  const agent = q.get("agent_id");
  const rows = all.filter((r) => (!verdict || r.verdict === verdict) && (!state || r.state === state) && (!agent || r.agent_id === agent));
  const open = [...w.alerts.values()].filter((a) => (a.rule_code === "silent_drift" || a.rule_code === "model_change") && a.state !== "resolved").length;
  return {
    rows,
    summary: {
      baselines: all.length,
      collecting: all.filter((r) => r.state === "collecting").length,
      frozen: all.filter((r) => r.state === "frozen").length,
      drift: all.filter((r) => r.verdict === "drift").length,
      watch: all.filter((r) => r.verdict === "watch").length,
      identity_changed: all.filter((r) => r.identity_changed).length,
      open_alerts: open,
    },
  };
}

function alertRefs(w: World, agentId: string): DriftAlertRef[] {
  return [...w.alerts.values()]
    .filter((a) => a.agent_id === agentId && (a.rule_code === "silent_drift" || a.rule_code === "model_change") && a.state !== "resolved")
    .map((a) => ({
      id: a.id,
      rule: a.rule_code as DriftAlertRef["rule"],
      severity: a.severity,
      state: a.state,
      first_fired_at: a.fired_at,
      summary: a.rule_code === "model_change" ? "The provider started serving a model or fingerprint the baseline never saw" : "Behaviour drifted on 2 consecutive evaluations",
    }));
}

/** `history` is newest first, from `since` (inclusive) and at most `limit` reports, as the API pages it. */
export function agentDrift(w: World, rt: AgentRt, t: number, h: { since: number | null; limit: number } = { since: null, limit: 48 }): AgentDrift {
  const keys = keysAt(w, rt, t);
  const reports = keys.map((k) => reportsFor(w, k, t));
  return {
    agent_id: rt.id,
    baselines: [...keys.map((k) => baselineOf(w, k, t)), ...supersededBaselines(w, rt, t)],
    latest: reports.map((r) => r.at(-1)).filter((r): r is DriftReport => Boolean(r)),
    history: reports
      .flatMap((r) => r.map(summaryOf))
      .filter((s) => h.since === null || Date.parse(s.evaluated_at) >= h.since)
      .sort((a, b) => Date.parse(b.evaluated_at) - Date.parse(a.evaluated_at))
      .slice(0, h.limit),
    open_alerts: alertRefs(w, rt.id),
  };
}

export function driftReport(w: World, id: string, t: number): DriftReport {
  for (const k of allKeys(w, t)) {
    const hit = reportsFor(w, k, t).find((r) => r.id === id);
    if (hit) return hit;
  }
  throw notFound("Drift report");
}

export function resetBaseline(w: World, p: BffPrincipal, rt: AgentRt, body: DriftBaselineReset, t: number): DriftBaselineResetResult {
  requireScope(p, "drift:write");
  const reason = typeof body?.reason === "string" ? body.reason.trim() : "";
  if (reason.length < 10) {
    throw new ProblemError(422, "validation_failed", "Reason too short", "Give a reason of at least 10 characters; it is written to the audit log.", { errors: [{ pointer: "/reason", code: "min_length", message: "At least 10 characters" }] });
  }
  const since = body.since ? Date.parse(body.since) : t;
  if (Number.isNaN(since) || since > t) throw new ProblemError(422, "validation_failed", "Bad start time", "`since` must be a timestamp in the past or now.", { errors: [{ pointer: "/since", code: "invalid", message: "Past timestamp" }] });
  const before = keysAt(w, rt, t).filter((k) => k.primary);
  const superseded = before.map((k) => baselineId(w, k));
  const s = monitorState(w);
  s.driftResets = [...s.driftResets, { agentId: rt.id, at: t, since, reason, userId: p.userId, superseded }];
  for (const a of w.alerts.values()) {
    if (a.agent_id === rt.id && (a.rule_code === "silent_drift" || a.rule_code === "model_change") && a.state !== "resolved") {
      w.alerts.set(a.id, { ...a, state: "resolved", resolved_at: iso(t) });
    }
  }
  appendAudit(w, { action: "drift.baseline_reset", actor_type: "human", actor_id: p.userId, resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, reason, detail: { agent_id: rt.id, superseded, since: iso(since), provider: rt.spec.provider, model: rt.spec.model } }, t);
  emit(w, "drift.baseline_reset", { agent_id: rt.id, superseded }, t);
  return { agent_id: rt.id, superseded, baselines: keysAt(w, rt, t).filter((k) => k.primary).map((k) => baselineOf(w, k, t)) };
}
