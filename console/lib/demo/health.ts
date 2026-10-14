/**
 * Signals → health for demo mode. Signals are a pure function of the agent's served
 * provider over time, that provider's status timeline and any scripted anomaly, so the
 * score history, the metrics sparklines and the factor list always agree with each other.
 */
import "server-only";
import type { HealthDocument, HealthPrediction } from "@/lib/api/documents";
import type { HealthPoint, MetricBucket, RecommendedAction } from "@/lib/api/types";
import { scoreAgent, type ProviderStatusLevel, type ScoreResult, type Signals, type Tier } from "@/lib/health/scoring";
import { MINUTE, hexFor, idFor, iso, noise } from "./core";
import type { ProviderSlug } from "./fixtures";
import type { AgentRt, World } from "./world";

export function providerStatusAt(w: World, provider: ProviderSlug, t: number): ProviderStatusLevel {
  let status: ProviderStatusLevel = "operational";
  for (const seg of w.providerStatus[provider]) if (seg.at <= t) status = seg.status;
  return status;
}

export function servedAt(rt: AgentRt, t: number): { provider: ProviderSlug | null; model: string | null } {
  let cur: { provider: ProviderSlug | null; model: string | null } = { provider: rt.spec.provider, model: rt.spec.model };
  for (const seg of rt.served) if (seg.at <= t) cur = { provider: seg.provider, model: seg.model };
  return cur;
}

function anomalyActive(rt: AgentRt, kind: string, t: number): { from: number } | null {
  for (const an of rt.anomalies) {
    if (an.kind === kind && an.from <= t && (an.to === null || t < an.to)) return { from: an.from };
  }
  return null;
}

const RAMP_MS = 120_000;

export function signalsAt(w: World, rt: AgentRt, t: number): Signals {
  const bucket = Math.floor(t / 10_000);
  const n = (k: string): number => noise(`${rt.id}:${k}`, bucket);
  const served = servedAt(rt, t);
  const s: Signals = {
    errorRate: Math.max(0, rt.spec.baseErr * (1 + 0.35 * n("err"))),
    p95Ms: rt.spec.baseP95 * (1 + 0.08 * n("lat")),
    modelClass: rt.spec.modelClass,
    consecutiveFailures: 0,
    providerStatus: "operational",
    rateLimitHeadroom: (rt.spec.headroom ?? 0.42) * (1 + 0.06 * n("rl")),
    toolLoopRatio: 0.05,
    qualityProxy: 0,
    fallbackShare: 0.01,
    latencyTrendRatio: (rt.spec.trend ?? 1) + 0.05 * n("trend"),
  };
  if (!served.provider) return s;

  const status = providerStatusAt(w, served.provider, t);
  s.providerStatus = status;
  if (status === "major_outage" || status === "partial_outage") {
    const full = status === "major_outage";
    s.errorRate = full ? 1 : 0.42;
    s.consecutiveFailures = full ? 12 : 4;
    s.p95Ms = rt.spec.baseP95 * (full ? 0.35 : 1.8);
    s.fallbackShare = full ? 0.9 : 0.4;
  } else if (status === "degraded_performance") {
    s.errorRate = rt.spec.baseErr + 0.03 + 0.01 * n("deg");
    s.p95Ms = rt.spec.baseP95 * 2.4;
    s.latencyTrendRatio = 2.3 + 0.1 * n("trend2");
    s.fallbackShare = 0.12;
  }

  if (anomalyActive(rt, "tool_loop", t)) {
    s.toolLoopRatio = 0.86;
    s.qualityProxy = 0.35;
  }
  if (anomalyActive(rt, "latency", t)) {
    s.p95Ms = rt.spec.baseP95 * 1.85;
    s.latencyTrendRatio = 2.2;
    s.errorRate = 0.068;
  }
  const ramp = anomalyActive(rt, "ratelimit_ramp", t);
  if (ramp) {
    const p = Math.min(1, (t - ramp.from) / RAMP_MS);
    s.rateLimitHeadroom = 0.32 - p * 0.285;
    s.fallbackShare = 0.02 + p * 0.1;
    s.errorRate = rt.spec.baseErr + p * 0.012;
  }
  return s;
}

export function scoreAt(w: World, rt: AgentRt, t: number): ScoreResult {
  return scoreAgent(rt.id, rt.spec.tier as Tier, signalsAt(w, rt, t));
}

const PROVISIONAL_MS = 30 * MINUTE;

function recommended(r: ScoreResult, tier: number): RecommendedAction {
  const top = r.factors[0]?.rule;
  if (!top || r.band === "healthy") return "none";
  if (top === "provider_status" || top === "error_rate" || top === "consecutive_failures") return "reroute_to_fallback";
  if (top === "ratelimit_proximity") return tier === 1 ? "await_approval" : "throttle";
  if (top === "tool_loop") return tier === 1 ? "await_approval" : "quarantine";
  if (top === "quality_proxy") return tier === 1 ? "handoff" : "watch";
  return "watch";
}

function prediction(r: ScoreResult, horizon: "15m" | "1h" | "24h"): HealthPrediction {
  const leading = r.factors.filter((f) => f.kind === "leading").map((f) => f.rule);
  const detected = r.factors.some((f) => f.kind === "detected" && (f.penalty ?? 0) >= 20);
  let band: HealthPrediction["probability_band"] = "0.05";
  if (r.band === "failed" || (detected && horizon === "15m")) band = "0.90";
  else if (leading.length > 0) band = horizon === "24h" ? "0.25" : "0.60";
  else if (r.band === "watch") band = "0.25";
  return {
    probability_band: band,
    source: "rules/v1",
    confidence: leading.length > 0 || detected ? "medium" : "low",
    contributing_rules: leading.length > 0 ? leading : r.factors.slice(0, 2).map((f) => f.rule),
    predicted_failure_mode: band === "0.05" ? null : r.factors[0]?.rule === "tool_loop" ? "infinite_loop" : "provider_outage",
  };
}

export function healthDocAt(w: World, rt: AgentRt, t: number): HealthDocument {
  const r = scoreAt(w, rt, t);
  const bucket = Math.floor(t / 10_000);
  const provisional = t - rt.createdAt < PROVISIONAL_MS || rt.discovered;
  const fifteen = prediction(r, "15m");
  return {
    schema: "sibyl-health/1",
    health_snapshot_id: idFor(`hs:${rt.id}:${bucket}`),
    tenant_id: w.tenantId,
    agent_id: rt.id,
    computed_at: iso(bucket * 10_000),
    window: { start: iso(bucket * 10_000 - 5 * MINUTE), end: iso(bucket * 10_000), grain_s: 300 },
    score: r.score,
    status: provisional && (r.band === "degraded" || r.band === "failed") ? "watch" : r.band,
    provisional: {
      flag: provisional,
      events_seen: provisional ? Math.min(49, Math.round((t - rt.createdAt) / 2000)) : 1200 + Math.round(rt.spec.rpm * 60),
      events_needed: 50,
      observation_coverage: provisional ? 0.4 : 0.97,
    },
    factors: r.factors,
    horizons: { "15m": fifteen, "1h": prediction(r, "1h"), "24h": prediction(r, "24h") },
    predicted_failure_mode: fifteen.predicted_failure_mode ?? null,
    recommended_action: recommended(r, rt.spec.tier),
    feature_snapshot_ref: `fs_${idFor(`fs:${rt.id}:${bucket}`)}`,
    policy_version: w.routingVersion,
    routing_state: rt.routing.state,
  };
}

export function healthHistory(w: World, rt: AgentRt, from: number, to: number, stepMs: number): HealthPoint[] {
  const out: HealthPoint[] = [];
  const start = Math.max(from, rt.createdAt);
  for (let t = Math.floor(start / stepMs) * stepMs; t <= to; t += stepMs) {
    const r = scoreAt(w, rt, t);
    out.push({ evaluated_at: iso(t), score: r.score, band: r.band, provisional: t - rt.createdAt < PROVISIONAL_MS });
  }
  return out;
}

export function metricsSeries(w: World, rt: AgentRt, from: number, to: number, stepMs: number): MetricBucket[] {
  const out: MetricBucket[] = [];
  const grain = stepMs >= 3_600_000 ? "1h" : stepMs >= 900_000 ? "15m" : stepMs >= 300_000 ? "5m" : "1m";
  for (let t = Math.floor(Math.max(from, rt.createdAt) / stepMs) * stepMs; t <= to; t += stepMs) {
    const s = signalsAt(w, rt, t);
    const served = servedAt(rt, t);
    const live = served.provider !== null && !(rt.routing.state === "killed" && t >= rt.routing.state_since);
    const requests = live ? Math.max(0, Math.round(rt.spec.rpm * (stepMs / MINUTE) * (1 + 0.12 * noise(`${rt.id}:rpm`, t / stepMs)))) : 0;
    const errors = Math.round(requests * Math.min(1, s.errorRate));
    const tokensIn = requests * (900 + Math.round(200 * noise(`${rt.id}:tin`, t)));
    const tokensOut = requests * (260 + Math.round(60 * noise(`${rt.id}:tout`, t)));
    out.push({
      bucket_start: iso(t),
      grain,
      provider: served.provider,
      model: served.model,
      requests,
      errors,
      tokens_in: tokensIn,
      tokens_out: tokensOut,
      cost_usd: (requests * rt.spec.costPerCall).toFixed(4),
      p50_ms: requests ? Math.round(s.p95Ms * 0.46) : null,
      p95_ms: requests ? Math.round(s.p95Ms) : null,
      p99_ms: requests ? Math.round(s.p95Ms * 1.45) : null,
    });
  }
  return out;
}

export const traceId = (name: string): string => hexFor(`trace:${name}`, 32);
export const spanId = (name: string): string => hexFor(`span:${name}`, 16);
