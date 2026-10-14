/** Agent detail paths and metric folding (lib/agent-data.ts). */
import { expect, test } from "@playwright/test";
import type { MetricBucket } from "@/lib/api/types";
import { agentPaths, chainInForce, foldBuckets } from "@/lib/agent-data";

const NOW = Date.parse("2026-10-11T10:30:42Z");

test("live asks for the last hour of history at 1-minute steps; demo keeps its default", () => {
  const live = agentPaths("a 1", "live", NOW);
  expect(live.history).toBe("/agents/a%201/health/history?from=2026-10-11T09%3A30%3A00.000Z&step=1m&limit=200");
  expect(agentPaths("a1", "demo", NOW).history).toBe("/agents/a1/health/history");
});

test("both modes ask for a full hour of metrics, approved chains and suppressed member alerts", () => {
  const p = agentPaths("a1", "live", NOW);
  expect(p.metrics).toBe("/agents/a1/metrics?grain=1m&limit=200");
  expect(p.chains).toBe("/agents/a1/fallback-chains?status=approved");
  expect(p.alerts).toContain("include_suppressed=true");
});

const row = (start: string, requests: number, errors: number, p95: number | null, provider: string): MetricBucket => ({ bucket_start: start, grain: "1m", provider, model: "m", requests, errors, p95_ms: p95 });

test("rows for the same bucket fold into one point, in time order", () => {
  const out = foldBuckets([row("2026-10-11T10:01:00Z", 5, 1, 900, "openai"), row("2026-10-11T10:00:00Z", 2, 0, null, "openai"), row("2026-10-11T10:01:00Z", 3, 0, 1200, "anthropic")]);
  expect(out.map((r) => [r.bucket_start, r.requests, r.errors, r.p95_ms])).toEqual([
    ["2026-10-11T10:00:00Z", 2, 0, null],
    ["2026-10-11T10:01:00Z", 8, 1, 1200],
  ]);
});

test("the chain in force is the newest approved one", () => {
  expect(chainInForce([{ status: "approved", id: 1 }, { status: "draft", id: 2 }, { status: "approved", id: 3 }])).toEqual({ status: "approved", id: 3 });
  expect(chainInForce([])).toBeNull();
  expect(chainInForce(undefined)).toBeNull();
});
