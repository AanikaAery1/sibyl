/**
 * Agent-detail data helpers shared by the server page and the client view (pure; unit-tested).
 *
 * Live and demo differ in two places: the API's health history defaults to the oldest rows of a
 * 3-day window, so live asks for the last hour at 1-minute steps; and the API returns one metric
 * row per bucket per provider/model, so rows are folded into one point per bucket here.
 */
import type { MetricBucket } from "@/lib/api/types";

const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;
export const PAGE_MAX = 200;

export interface AgentPaths {
  base: string;
  health: string;
  routing: string;
  plan: string;
  chains: string;
  metrics: string;
  history: string;
  transitions: string;
  alerts: string;
  incidents: string;
}

/** `nowMs` is floored to the minute so the SWR key stays stable for a minute at a time. */
export function agentPaths(agentId: string, mode: "demo" | "live", nowMs: number): AgentPaths {
  const id = encodeURIComponent(agentId);
  const base = `/agents/${id}`;
  const from = new Date(Math.floor((nowMs - HOUR_MS) / MINUTE_MS) * MINUTE_MS).toISOString();
  return {
    base,
    health: `${base}/health`,
    routing: `${base}/routing`,
    plan: `${base}/continuity-plan`,
    chains: `${base}/fallback-chains?status=approved`,
    metrics: `${base}/metrics?grain=1m&limit=${PAGE_MAX}`,
    history: mode === "live" ? `${base}/health/history?from=${encodeURIComponent(from)}&step=1m&limit=${PAGE_MAX}` : `${base}/health/history`,
    transitions: `${base}/routing/transitions?limit=12`,
    alerts: `/alerts?agent_id=${id}&limit=10&include_suppressed=true`,
    incidents: `/incidents?agent_id=${id}&limit=5`,
  };
}

/** One point per bucket: requests and errors add up; latency takes the slowest provider's p95. */
export function foldBuckets(rows: readonly MetricBucket[]): MetricBucket[] {
  const byStart = new Map<string, MetricBucket>();
  for (const r of rows) {
    const prev = byStart.get(r.bucket_start);
    if (!prev) {
      byStart.set(r.bucket_start, { ...r, provider: null, model: null });
      continue;
    }
    const p95 = [prev.p95_ms, r.p95_ms].filter((x): x is number => typeof x === "number");
    byStart.set(r.bucket_start, { ...prev, requests: prev.requests + r.requests, errors: prev.errors + r.errors, p95_ms: p95.length ? Math.max(...p95) : null });
  }
  return [...byStart.values()].sort((a, b) => Date.parse(a.bucket_start) - Date.parse(b.bucket_start));
}

/** The approved chain in force: the newest approved one (the API lists oldest first). */
export function chainInForce<T extends { status?: string; created_at?: string }>(chains: readonly T[] | undefined): T | null {
  const approved = (chains ?? []).filter((c) => !c.status || c.status === "approved");
  return approved.at(-1) ?? null;
}
