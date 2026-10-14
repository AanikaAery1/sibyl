/**
 * Phase 1 health score, as specified in ML.md §3 (rules/v1). Pure functions: the demo store
 * uses them to produce sibyl-health/1 documents whose arithmetic is real, and the console
 * uses `scoreArithmetic` to render the decision record. The worker is the authority in live
 * mode; nothing here is ever sent back to the API.
 *
 * score = clamp(100 − Σ penalty_i, 0, 100), penalty_i = cap_i(tier) × severity_i
 */
import type { Band } from "@/lib/api/types";
import type { FactorDirection, HealthFactor, RuleKind } from "@/lib/api/documents";

export type Tier = 1 | 2 | 3;

export type ProviderStatusLevel =
  | "operational"
  | "maintenance"
  | "degraded_performance"
  | "partial_outage"
  | "major_outage"
  | "unknown";

export interface Signals {
  errorRate: number;
  p95Ms: number;
  modelClass: "small" | "large" | "reasoning";
  consecutiveFailures: number;
  providerStatus: ProviderStatusLevel;
  rateLimitHeadroom: number;
  toolLoopRatio: number;
  qualityProxy: number;
  fallbackShare: number;
  latencyTrendRatio: number;
}

interface RuleSpec {
  rule: string;
  kind: RuleKind;
  cap: Readonly<Record<Tier, number>>;
}

const RULES = {
  error_rate: { rule: "error_rate", kind: "detected", cap: { 1: 50, 2: 40, 3: 30 } },
  p95_latency: { rule: "p95_latency", kind: "detected", cap: { 1: 30, 2: 25, 3: 20 } },
  consecutive_failures: { rule: "consecutive_failures", kind: "detected", cap: { 1: 60, 2: 50, 3: 40 } },
  provider_status: { rule: "provider_status", kind: "detected", cap: { 1: 60, 2: 60, 3: 60 } },
  tool_loop: { rule: "tool_loop", kind: "detected", cap: { 1: 30, 2: 25, 3: 20 } },
  quality_proxy: { rule: "quality_proxy", kind: "detected", cap: { 1: 25, 2: 20, 3: 15 } },
  ratelimit_proximity: { rule: "ratelimit_proximity", kind: "leading", cap: { 1: 25, 2: 20, 3: 15 } },
  fallback_pressure: { rule: "fallback_pressure", kind: "leading", cap: { 1: 30, 2: 25, 3: 20 } },
  latency_trend: { rule: "latency_trend", kind: "leading", cap: { 1: 15, 2: 10, 3: 8 } },
} as const satisfies Record<string, RuleSpec>;

const ERROR_RATE_T: Readonly<Record<Tier, number>> = { 1: 0.05, 2: 0.1, 3: 0.2 };
const CONSECUTIVE_T: Readonly<Record<Tier, number>> = { 1: 3, 2: 3, 3: 5 };
const HEADROOM_T: Readonly<Record<Tier, number>> = { 1: 0.15, 2: 0.1, 3: 0.1 };
const FALLBACK_T: Readonly<Record<Tier, number>> = { 1: 0.1, 2: 0.2, 3: 0.25 };
const LATENCY_T: Readonly<Record<Signals["modelClass"], number>> = { small: 5000, large: 20000, reasoning: 60000 };
const STATUS_SEVERITY: Readonly<Record<ProviderStatusLevel, number>> = {
  operational: 0,
  unknown: 0,
  maintenance: 0.15,
  degraded_performance: 0.33,
  partial_outage: 0.58,
  major_outage: 1,
};

/** Band entry thresholds per tier (ML §3.4): healthy ≥, watch ≥, degraded ≥, else failed. */
export const BAND_EDGES: Readonly<Record<Tier, { healthy: number; watch: number; degraded: number }>> = {
  1: { healthy: 85, watch: 70, degraded: 45 },
  2: { healthy: 80, watch: 65, degraded: 40 },
  3: { healthy: 75, watch: 55, degraded: 30 },
};

const clamp01 = (x: number): number => Math.min(1, Math.max(0, x));
const round1 = (x: number): number => Math.round(x * 10) / 10;
const pct = (x: number): string => `${Math.round(x * 1000) / 10}%`;

function aboveSeverity(x: number, t: number, s: number): number {
  return clamp01((x - t) / (s - t));
}
function belowSeverity(x: number, t: number): number {
  return clamp01((t - x) / t);
}
function countSeverity(n: number, t: number): number {
  return clamp01((n - t + 1) / t);
}

function factor(
  spec: RuleSpec,
  tier: Tier,
  severity: number,
  value: number | string,
  threshold: number | string,
  direction: FactorDirection,
  explanation: string,
  evidence: string,
): HealthFactor {
  const cap = spec.cap[tier];
  return {
    rule: spec.rule,
    weight: cap / 100,
    penalty: Math.round(cap * severity),
    value,
    threshold,
    direction,
    kind: spec.kind,
    explanation,
    evidence,
    ...(spec.kind === "leading" ? { horizon_s: 900 } : {}),
  };
}

export interface ScoreResult {
  score: number;
  band: Band;
  factors: HealthFactor[];
  penaltySum: number;
  floor: string | null;
}

/** Evaluate every seed rule; returns factors with a non-zero penalty, sorted by penalty desc. */
export function scoreAgent(agentId: string, tier: Tier, s: Signals): ScoreResult {
  const ev = (q: string): string => `/events?agent_id=${agentId}&${q}`;
  const all: HealthFactor[] = [];

  const tErr = ERROR_RATE_T[tier];
  all.push(
    factor(
      RULES.error_rate,
      tier,
      aboveSeverity(s.errorRate, tErr, 3 * tErr),
      round4(s.errorRate),
      tErr,
      "above",
      `Error rate ${pct(s.errorRate)} over the last 5 minutes (threshold ${pct(tErr)}, saturates at ${pct(3 * tErr)})`,
      ev("status=error"),
    ),
  );

  const tLat = LATENCY_T[s.modelClass];
  all.push(
    factor(
      RULES.p95_latency,
      tier,
      aboveSeverity(s.p95Ms, tLat, 2 * tLat),
      Math.round(s.p95Ms),
      tLat,
      "above",
      `p95 latency ${(s.p95Ms / 1000).toFixed(1)} s (threshold ${tLat / 1000} s for ${s.modelClass} models)`,
      ev("metric=p95_ms"),
    ),
  );

  const tCons = CONSECUTIVE_T[tier];
  all.push(
    factor(
      RULES.consecutive_failures,
      tier,
      countSeverity(s.consecutiveFailures, tCons),
      s.consecutiveFailures,
      tCons,
      "above",
      `${s.consecutiveFailures} consecutive failed calls (threshold ${tCons})`,
      ev("status=error&consecutive=1"),
    ),
  );

  all.push(
    factor(
      RULES.provider_status,
      tier,
      STATUS_SEVERITY[s.providerStatus],
      s.providerStatus,
      "operational",
      "equals",
      `Provider status feed reports ${s.providerStatus.replaceAll("_", " ")}`,
      "/providers?status=1",
    ),
  );

  all.push(
    factor(
      RULES.tool_loop,
      tier,
      aboveSeverity(s.toolLoopRatio, 0.5, 1),
      round4(s.toolLoopRatio),
      0.5,
      "above",
      `Tool-call sequence repeats ${pct(s.toolLoopRatio)} of the time with more than 20 calls in 5 minutes`,
      ev("event_type=tool.call"),
    ),
  );

  all.push(
    factor(
      RULES.quality_proxy,
      tier,
      clamp01(s.qualityProxy),
      round4(s.qualityProxy),
      0,
      "above",
      `Output-quality proxy (max of refusal, truncation and schema-failure severities) at ${pct(s.qualityProxy)}`,
      ev("event_type=gen_ai.response"),
    ),
  );

  const tHead = HEADROOM_T[tier];
  all.push(
    factor(
      RULES.ratelimit_proximity,
      tier,
      belowSeverity(s.rateLimitHeadroom, tHead),
      round4(s.rateLimitHeadroom),
      tHead,
      "below",
      `Rate-limit headroom ${pct(s.rateLimitHeadroom)} (threshold ${pct(tHead)}); projected exhaustion inside 15 minutes`,
      ev("metric=ratelimit_remaining"),
    ),
  );

  const tFb = FALLBACK_T[tier];
  all.push(
    factor(
      RULES.fallback_pressure,
      tier,
      aboveSeverity(s.fallbackShare, tFb, 3 * tFb),
      round4(s.fallbackShare),
      tFb,
      "above",
      `Inline fallback and breaker share ${pct(s.fallbackShare)} (threshold ${pct(tFb)})`,
      ev("route=fallback"),
    ),
  );

  all.push(
    factor(
      RULES.latency_trend,
      tier,
      aboveSeverity(s.latencyTrendRatio, 1.5, 3),
      round1(s.latencyTrendRatio),
      1.5,
      "rising",
      `p95 latency trending ${round1(s.latencyTrendRatio)}× its 1-hour baseline`,
      ev("metric=p95_ms&trend=1"),
    ),
  );

  const factors = all.filter((f) => (f.penalty ?? 0) > 0).sort((a, b) => (b.penalty ?? 0) - (a.penalty ?? 0));
  const penaltySum = factors.reduce((acc, f) => acc + (f.penalty ?? 0), 0);
  const score = Math.max(0, Math.min(100, 100 - penaltySum));

  const floor =
    countSeverity(s.consecutiveFailures, tCons) >= 1
      ? "consecutive_failures at full severity"
      : s.errorRate >= 0.5
        ? "error_rate ≥ 50% with enough samples"
        : null;
  const band = floor ? "failed" : bandFor(tier, score);
  return { score, band, factors, penaltySum, floor };
}

export function bandFor(tier: Tier, score: number): Band {
  const e = BAND_EDGES[tier];
  if (score >= e.healthy) return "healthy";
  if (score >= e.watch) return "watch";
  if (score >= e.degraded) return "degraded";
  return "failed";
}

function round4(x: number): number {
  return Math.round(x * 10000) / 10000;
}

/**
 * Split a stored factor list into the rules a person reads and the worker's bookkeeping. The
 * live worker appends `_hysteresis` (band state) and, when 100 − Σ penalty < 0, `_clamp` (the
 * amount added back), so its identity is `100 − Σ penalty + clamp = score` (qa §3.2).
 * Rules inside their threshold (penalty 0) are not penalties and are not listed.
 */
export function splitFactors(factors: readonly HealthFactor[]): { rules: HealthFactor[]; clamp: number } {
  const rules = factors.filter((f) => !f.rule.startsWith("_") && (f.penalty ?? 0) > 0).sort((a, b) => (b.penalty ?? 0) - (a.penalty ?? 0));
  const clamp = factors.filter((f) => f.rule === "_clamp").reduce((a, f) => a + (f.penalty ?? 0), 0);
  return { rules, clamp };
}

/** Does `100 − Σ penalty + clamp = score` hold? Without a stored clamp, a sum over 100 clamps to 0. */
export function scoreChecks(rules: readonly HealthFactor[], clamp: number, score: number): boolean {
  const sum = rules.reduce((a, f) => a + (f.penalty ?? 0), 0);
  const added = clamp || (sum > 100 ? sum - 100 : 0);
  return 100 - sum + added === score;
}

/** "100 − (28 + 10 + 4) = 58 → degraded" (ML §6.1); handles the clamp case honestly. */
export function scoreArithmetic(factors: readonly HealthFactor[], score: number, band: Band): string {
  const penalties = factors.filter((f) => !f.rule.startsWith("_")).map((f) => f.penalty ?? 0).filter((p) => p > 0);
  if (penalties.length === 0) return `100 − 0 = ${score} → ${band}`;
  const sum = penalties.reduce((a, b) => a + b, 0);
  const terms = penalties.length === 1 ? `${penalties[0]}` : `(${penalties.join(" + ")})`;
  if (sum > 100) return `100 − ${terms} = ${100 - sum}, clamped to ${score} → ${band}`;
  return `100 − ${terms} = ${score} → ${band}`;
}

export const RULE_LABEL: Readonly<Record<string, string>> = {
  error_rate: "Error rate",
  p95_latency: "p95 latency",
  consecutive_failures: "Consecutive failures",
  provider_status: "Provider status",
  tool_loop: "Tool loop",
  quality_proxy: "Output quality",
  ratelimit_proximity: "Rate-limit headroom",
  fallback_pressure: "Fallback pressure",
  latency_trend: "Latency trend",
  budget_proximity: "Budget proximity",
};

export function ruleLabel(rule: string): string {
  return RULE_LABEL[rule] ?? rule.replaceAll("_", " ");
}
