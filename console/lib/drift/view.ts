/**
 * Model drift (D51) display logic, pure and unit-tested: vocabulary, tones, number formatting,
 * fleet filtering and ordering, and the served-model history an agent's drift tab shows.
 * Drift is watch-only: nothing here (or anywhere in the console) turns a verdict into an action.
 */
import type { Tone } from "@/lib/labels";
import type { AgentDrift, DriftFeature, DriftFeatureResult, DriftIdentityKind, DriftKeySummary, DriftStatistic, DriftVerdict, FleetDriftSummary } from "@/lib/api/monitor";

export const WATCH_ONLY_COPY = "Drift is watch-only: it raises silent_drift and model_change alerts for a person to look at and never triggers a failover on its own.";

export const FEATURE_LABEL: Readonly<Record<DriftFeature, string>> = {
  output_tokens: "Output tokens",
  input_tokens: "Input tokens",
  latency_ms: "Latency",
  refusal: "Refusal share",
  truncation: "Truncation share",
  tool_call: "Tool-call rate",
  schema_fail: "Schema failures",
  error_class: "Error mix",
  tool_bigram: "Tool sequences",
};

export const STAT_LABEL: Readonly<Record<DriftStatistic, string>> = { psi: "PSI", js: "Jensen–Shannon" };

export const VERDICT_LABEL: Readonly<Record<DriftVerdict, string>> = { none: "No drift", watch: "Watch", drift: "Drift" };

/** Colour carries meaning only: calm when nothing moved, amber on watch, orange on drift. */
export const VERDICT_TONE: Readonly<Record<DriftVerdict, Tone>> = { none: "quiet", watch: "watch", drift: "degraded" };

export const IDENTITY_LABEL: Readonly<Record<DriftIdentityKind, string>> = {
  served_model_mismatch: "Served a different model",
  new_served_model: "New model snapshot",
  new_fingerprint: "New provider fingerprint",
};

export const IDENTITY_HELP: Readonly<Record<DriftIdentityKind, string>> = {
  served_model_mismatch: "The provider answered with a model that is neither the one requested nor a dated snapshot of it.",
  new_served_model: "A dated snapshot of the requested model that the baseline never saw.",
  new_fingerprint: "The provider's system fingerprint changed: same model name, different serving stack.",
};

export const BASELINE_STATE_LABEL = { collecting: "Collecting", frozen: "Frozen", superseded: "Superseded" } as const;

/** Statistic values are small (PSI ~0.01–0.5, JS ~0.001–0.2): keep enough digits to compare with thresholds. */
export function formatStat(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return "—";
  if (v === 0) return "0";
  const abs = Math.abs(v);
  if (abs >= 1) return v.toFixed(2);
  if (abs >= 0.01) return v.toFixed(3);
  return v.toFixed(4);
}

/** Excess over the drift threshold as a 0..1 bar fill (1 = at the drift line); null when undecided. */
export function excessFill(f: Pick<DriftFeatureResult, "excess" | "drift" | "status">): number | null {
  if (f.status !== "ok" || f.excess === null || f.excess === undefined || f.drift <= 0) return null;
  return Math.max(0, Math.min(1, f.excess / f.drift));
}

/** The watch line on the same 0..1 scale. */
export function watchMark(f: Pick<DriftFeatureResult, "watch" | "drift">): number {
  return f.drift > 0 ? Math.max(0, Math.min(1, f.watch / f.drift)) : 0;
}

export function featureStatusText(f: Pick<DriftFeatureResult, "status" | "n_baseline" | "n_window">): string | null {
  if (f.status === "insufficient_samples") return `Not enough samples (${f.n_window ?? 0} in window)`;
  if (f.status === "invalid_baseline") return "Baseline has no distribution for this feature";
  return null;
}

export type DriftFilter = "all" | "drift" | "watch" | "identity" | "collecting";

export interface DriftQuery {
  filter: DriftFilter;
  q: string;
}

export function parseDriftQuery(params: { get: (k: string) => string | null }): DriftQuery {
  const f = params.get("filter");
  const filter: DriftFilter = f === "drift" || f === "watch" || f === "identity" || f === "collecting" ? f : "all";
  return { filter, q: (params.get("q") ?? "").trim() };
}

export function matchesFilter(row: DriftKeySummary, filter: DriftFilter): boolean {
  switch (filter) {
    case "drift":
      return row.verdict === "drift";
    case "watch":
      return row.verdict === "watch";
    case "identity":
      return Boolean(row.identity_changed);
    case "collecting":
      return row.state === "collecting";
    default:
      return true;
  }
}

const RANK: Readonly<Record<string, number>> = { drift: 0, watch: 2, none: 3 };

/** Worst first: drift, identity change, watch, no drift, then baselines still collecting. */
export function rankOf(row: DriftKeySummary): number {
  if (row.state === "collecting") return 5;
  if (row.verdict === "drift") return 0;
  if (row.identity_changed) return 1;
  return RANK[row.verdict ?? "none"] ?? 4;
}

export function filterAndSort(rows: readonly DriftKeySummary[], query: DriftQuery): DriftKeySummary[] {
  const q = query.q.toLowerCase();
  return rows
    .filter((r) => matchesFilter(r, query.filter))
    .filter((r) => !q || `${r.agent_name ?? ""} ${r.provider} ${r.model}`.toLowerCase().includes(q))
    .sort((a, b) => rankOf(a) - rankOf(b) || (b.max_ratio ?? 0) - (a.max_ratio ?? 0) || (a.agent_name ?? "").localeCompare(b.agent_name ?? ""));
}

/** The API's summary when present, else counted from the rows (a page without `summary`). */
export function summaryOf(rows: readonly DriftKeySummary[], given?: FleetDriftSummary): FleetDriftSummary {
  if (given) return given;
  return {
    baselines: rows.length,
    collecting: rows.filter((r) => r.state === "collecting").length,
    frozen: rows.filter((r) => r.state === "frozen").length,
    drift: rows.filter((r) => r.verdict === "drift").length,
    watch: rows.filter((r) => r.verdict === "watch").length,
    identity_changed: rows.filter((r) => r.identity_changed).length,
  };
}

/** Worst verdict per agent for the fleet tile hint (identity change shown even when behaviour is calm). */
export interface AgentDriftHint {
  verdict: DriftVerdict;
  identity: boolean;
}

export function hintsByAgent(rows: readonly DriftKeySummary[]): Map<string, AgentDriftHint> {
  const out = new Map<string, AgentDriftHint>();
  const order: Readonly<Record<DriftVerdict, number>> = { none: 0, watch: 1, drift: 2 };
  for (const r of rows) {
    if (r.state !== "frozen") continue;
    const cur = out.get(r.agent_id) ?? { verdict: "none" as DriftVerdict, identity: false };
    const v = r.verdict ?? "none";
    out.set(r.agent_id, { verdict: order[v] > order[cur.verdict] ? v : cur.verdict, identity: cur.identity || Boolean(r.identity_changed) });
  }
  return out;
}

export interface ServedRow {
  kind: "model" | "fingerprint";
  value: string;
  /** In the frozen baseline (seen before), or new in the latest window. */
  seen: "baseline" | "new";
  finding: DriftIdentityKind | null;
  count: number | null;
  provider: string;
  requested: string;
}

/** Served models and fingerprints per key: the baseline's, then anything new the latest report found. */
export function servedHistory(d: AgentDrift): ServedRow[] {
  const rows: ServedRow[] = [];
  const live = d.baselines.filter((b) => b.state !== "superseded");
  for (const b of live) {
    for (const m of b.served_models ?? []) rows.push({ kind: "model", value: m, seen: "baseline", finding: null, count: null, provider: b.provider, requested: b.model });
    for (const f of b.fingerprints ?? []) rows.push({ kind: "fingerprint", value: f, seen: "baseline", finding: null, count: null, provider: b.provider, requested: b.model });
  }
  for (const r of d.latest) {
    for (const i of r.identity) {
      rows.push({ kind: i.kind === "new_fingerprint" ? "fingerprint" : "model", value: i.value, seen: "new", finding: i.kind, count: i.count, provider: r.provider, requested: i.requested_model });
    }
  }
  return rows;
}

/** The fleet list every drift surface reads (sidebar badge, fleet tiles, /drift). */
export const DRIFT_FLEET_PATH = "/drift?limit=200";

/** `GET /agents/{id}/drift` history page size: the API's default, its maximum, and the step "show more" adds. */
export const DRIFT_HISTORY = { default: 48, max: 500, step: 48 } as const;

export type DriftHistoryRange = "recent" | "24h" | "7d";
export const DRIFT_RANGE_HOURS: Readonly<Record<DriftHistoryRange, number | null>> = { recent: null, "24h": 24, "7d": 168 };

/** An agent's drift with its history paged: reports evaluated at or after `since`, the latest `limit`. */
export function agentDriftPath(agentId: string, h: { since?: string | null; limit?: number } = {}): string {
  const p = new URLSearchParams();
  if (h.since) p.set("since", h.since);
  const limit = Math.min(DRIFT_HISTORY.max, Math.max(1, h.limit ?? DRIFT_HISTORY.default));
  if (limit !== DRIFT_HISTORY.default) p.set("limit", String(limit));
  const qs = p.toString();
  return `/agents/${agentId}/drift${qs ? `?${qs}` : ""}`;
}

/** More history may exist when a page came back full and the cap is not reached. */
export const driftHistoryHasMore = (returned: number, limit: number): boolean => returned >= limit && limit < DRIFT_HISTORY.max;
