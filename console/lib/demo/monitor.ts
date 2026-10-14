/**
 * Wave 3 in the demo: the meridian scenario beats for runs, discovery, drift and Sentinel, and
 * the contract routes they are served on (merged into handlers.ts and scenario.ts).
 *
 *   0:21   claims run: the payout call is blocked inside the run tree
 *   0:46   claims run hands off to an unknown payout agent (discovered); its transfer is held
 *   0:48   Sentinel explains the claims-triage failover (advisory)
 *   0:50   Sentinel reviews the ₹75,000 hold for the approver (advisory)
 *   0:52   sales copilot: OpenAI serves a new gpt-5 snapshot and fingerprint → model_change
 *   0:56   a CrewAI service reports an unregistered agent (discovered)
 *   1:36   Sentinel reviews the held refund
 *   1:40   route optimizer: tool sequences and latency drift (first drift verdict)
 *   1:50   second consecutive drift verdict → silent_drift (watch-only)
 *   2:00   Sentinel reads sampled route-optimizer runs (semantic drift, no purpose change)
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type { DriftBaselineReset, SentinelConfigPut, SentinelExplain, SentinelFeedbackBody } from "@/lib/api/monitor";
import { agentId } from "./fixtures";
import { fireAlert } from "./ops";
import { agentDetail } from "./views";
import { agentDrift, driftFleet, driftReport, resetBaseline, DRIFT_MARKS } from "./drift";
import { explain, getFinding, listFindings, putSentinelConfig, rateFinding, scheduledDriftReview, scheduledHeldReview, scheduledIncidentExplanation, sentinelConfigView, testSentinel } from "./sentinel";
import { blockedPayoutRun, claimAgent, discoverCrm, heldPayoutRun, listEvents, listRunsAt, runAt, traceOf } from "./runs";
import { monitorState } from "./monitor-state";
import { page } from "./page";
import { requireScope } from "./actions";
import type { DemoRequest, DemoResult } from "./handlers";
import type { World } from "./world";

const mark = (w: World, id: string, at: number): void => {
  monitorState(w).marks.set(id, at);
};

const rt = (w: World, slug: string) => w.agents.get(agentId(w.slug, slug)) ?? null;

export const MONITOR_BEATS = [
  { at: 21, id: "run-blocked", label: "Run tree: the claims run's payout call is blocked in-run", run: (w: World, at: number) => blockedPayoutRun(w, at) },
  { at: 46, id: "run-handoff", label: "Claims run hands off to an unknown payout agent (discovered)", run: (w: World, at: number) => heldPayoutRun(w, at) },
  { at: 48, id: "sentinel-incident", label: "Sentinel explains the claims-triage failover (advisory)", run: (w: World, at: number) => scheduledIncidentExplanation(w, "claims-triage", at) },
  { at: 50, id: "sentinel-held", label: "Sentinel reviews the ₹75,000 hold for the approver (advisory)", run: (w: World, at: number) => scheduledHeldReview(w, "clm-204871-pay-1", at) },
  {
    at: 52,
    id: DRIFT_MARKS.identity,
    label: "Sales copilot: a new gpt-5 snapshot is served (model_change, watch-only)",
    run: (w: World, at: number) => {
      mark(w, DRIFT_MARKS.identity, at);
      fireAlert(w, rt(w, "sales-copilot"), { rule: "model_change", severity: "warning", at });
    },
  },
  { at: 56, id: "discover-crm", label: "An unregistered CrewAI agent appears in telemetry (discovered)", run: (w: World, at: number) => discoverCrm(w, at) },
  { at: 96, id: "sentinel-refund", label: "Sentinel reviews the held refund (advisory)", run: (w: World, at: number) => scheduledHeldReview(w, "rfd-C-88266", at) },
  { at: 100, id: DRIFT_MARKS.behaviour, label: "Route optimizer: tool sequences and latency drift", run: (w: World, at: number) => mark(w, DRIFT_MARKS.behaviour, at) },
  {
    at: 110,
    id: DRIFT_MARKS.confirm,
    label: "Second drift verdict in a row: silent_drift alert (watch-only)",
    run: (w: World, at: number) => {
      mark(w, DRIFT_MARKS.confirm, at);
      fireAlert(w, rt(w, "route-optimizer"), { rule: "silent_drift", severity: "warning", at });
    },
  },
  { at: 120, id: "sentinel-drift", label: "Sentinel reads sampled route-optimizer runs (semantic drift)", run: (w: World, at: number) => scheduledDriftReview(w, "route-optimizer", at) },
] as const;

type Handler = (r: DemoRequest) => DemoResult | unknown;

const agentOr404 = (r: DemoRequest) => {
  const a = r.w.agents.get(r.params.agent_id ?? "");
  if (!a) throw notFound("Agent");
  return a;
};

/** `GET /agents/{id}/drift` history: `since` (reports evaluated at or after) and `limit` (default 48, max 500). */
function historyQuery(q: URLSearchParams): { since: number | null; limit: number } {
  const bad = (pointer: string, message: string): ProblemError => new ProblemError(422, "validation_failed", "Bad history query", message, { errors: [{ pointer, code: "invalid", message }] });
  const rawSince = q.get("since");
  const since = rawSince === null ? null : Date.parse(rawSince);
  if (since !== null && Number.isNaN(since)) throw bad("/since", "An RFC 3339 timestamp.");
  const rawLimit = q.get("limit");
  const limit = rawLimit === null ? 48 : Number(rawLimit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw bad("/limit", "An integer from 1 to 500.");
  return { since, limit };
}

export const MONITOR_ROUTES: Record<string, Partial<Record<string, Handler>>> = {
  "/drift": {
    GET: (r) => {
      requireScope(r.principal, "drift:read");
      const { rows, summary } = driftFleet(r.w, r.t, r.query);
      return { ...page(rows, r.query), summary };
    },
  },
  "/drift/reports/{report_id}": {
    GET: (r) => {
      requireScope(r.principal, "drift:read");
      return driftReport(r.w, r.params.report_id ?? "", r.t);
    },
  },
  "/agents/{agent_id}/drift": {
    GET: (r) => {
      requireScope(r.principal, "drift:read");
      return agentDrift(r.w, agentOr404(r), r.t, historyQuery(r.query));
    },
  },
  "/agents/{agent_id}/drift/baseline": {
    POST: (r) => ({ status: 201, body: resetBaseline(r.w, r.principal, agentOr404(r), (r.body ?? {}) as DriftBaselineReset, r.t) }),
  },
  "/agents/{agent_id}/claim": {
    POST: (r) => agentDetail(r.w, claimAgent(r.w, r.principal, r.params.agent_id ?? "", r.t), r.t),
  },
  "/sentinel/config": {
    GET: (r) => {
      requireScope(r.principal, "sentinel:read");
      const cfg = sentinelConfigView(r.w, r.t);
      // `"0"` before the first save (saved versions start at 1), so If-Match is uniform.
      return { status: 200, body: cfg, headers: { ETag: `"${cfg.version}"` } };
    },
    PUT: (r) => {
      const { config, etag } = putSentinelConfig(r.w, r.principal, (r.body ?? {}) as SentinelConfigPut, r.ifMatch ?? null, r.t);
      return { status: 200, body: config, headers: { ETag: etag } };
    },
  },
  "/sentinel/config/test": { POST: (r) => testSentinel(r.w, r.principal, r.t) },
  "/sentinel/findings": { GET: (r) => page(listFindings(r.w, r.principal, r.query), r.query) },
  "/sentinel/findings/{finding_id}": { GET: (r) => getFinding(r.w, r.principal, r.params.finding_id ?? "") },
  "/sentinel/findings/{finding_id}/feedback": {
    POST: (r) => rateFinding(r.w, r.principal, r.params.finding_id ?? "", ((r.body ?? {}) as SentinelFeedbackBody).feedback, r.t),
  },
  "/sentinel/explain": { POST: (r) => ({ status: 201, body: explain(r.w, r.principal, (r.body ?? {}) as SentinelExplain, r.t) }) },
  "/events": { GET: (r) => page(listEvents(r.w, r.principal, r.query, r.t), r.query) },
  "/runs": { GET: (r) => page(listRunsAt(r.w, r.principal, r.query, r.t), r.query) },
  "/runs/{run_id}": { GET: (r) => runAt(r.w, r.principal, r.params.run_id ?? "", r.t) },
  "/traces/{trace_id}": { GET: (r) => traceOf(r.w, r.principal, r.params.trace_id ?? "", r.t) },
};
