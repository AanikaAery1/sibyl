/**
 * Demo-mode implementations of the control-plane routes the console uses, keyed by the
 * OpenAPI path template. Responses are shaped exactly like the contract; console-only
 * helper fields ride under `x_console` and are never relied on for live routes.
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type {
  AlertAction,
  ApiKeyCreate,
  CapturePolicyCreate,
  HandoffTaskAction,
  IncidentActionBody,
  IncidentCreate,
  KillSwitchCreate,
  TenantKeyPurpose,
} from "@/lib/api/types";
import { PERSONAS } from "@/lib/auth/personas";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { MINUTE, iso } from "./core";
import { alertAction, createIncident, handoffAction, incidentAction, pullKill, releaseKill, requireScope } from "./actions";
import { createApiKey, createCapturePolicy, createExport, exportView, revokeApiKey, rotateApiKey, rotateTenantKey, tamperedCheck, verifyAudit } from "./admin";
import { healthDocAt, healthHistory, metricsSeries } from "./health";
import { packetHash } from "./packets";
import { appendAudit, type World } from "./world";
import { page } from "./page";
import { ACTION_GATE_ROUTES } from "./action-gate";
import { MONITOR_ROUTES } from "./monitor";
import { EXTERNAL_MONITOR_ROUTES } from "./external-monitors";
import { agentDetail, agentSummary, fleetHealth, incidentView, providersView, routingState } from "./views";

export interface DemoRequest {
  method: string;
  params: Record<string, string>;
  query: URLSearchParams;
  body: unknown;
  principal: BffPrincipal;
  w: World;
  t: number;
  /** `If-Match` as sent (wave 3: Sentinel config PUT). */
  ifMatch?: string | null;
}

export interface DemoResult {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

type Handler = (r: DemoRequest) => DemoResult | unknown;

const ok = (body: unknown, status = 200): DemoResult => ({ status, body });


const agentOr404 = (r: DemoRequest) => {
  const rt = r.w.agents.get(r.params.agent_id ?? "");
  if (!rt) throw notFound("Agent");
  return rt;
};

const body = <T>(r: DemoRequest): T => (r.body ?? {}) as T;

const ROUTES: Record<string, Partial<Record<string, Handler>>> = {
  "/auth/me": {
    GET: ({ principal: p, w }) => ({
      user: { id: p.userId, email: PERSONAS.find((x) => x.id === p.personaId)?.email, display_name: PERSONAS.find((x) => x.id === p.personaId)?.fullName, status: "active" },
      tenant: tenantView(w),
      memberships: w.memberships.filter((m) => m.user_id === p.userId),
      scopes: p.scopes,
      step_up_valid_until: p.stepUpUntil ? iso(p.stepUpUntil) : null,
    }),
  },
  "/tenant": { GET: ({ w }) => tenantView(w) },
  "/fleet/health": { GET: ({ w, t }) => fleetHealth(w, t) },
  "/providers": { GET: ({ w, t, query }) => page(providersView(w, t), query) },
  "/agents": {
    GET: ({ w, t, query }) => {
      const tier = query.get("tier");
      const band = query.get("band");
      const state = query.get("routing_state");
      const lifecycle = query.get("lifecycle");
      const q = query.get("q")?.toLowerCase();
      const items = [...w.agents.values()]
        .map((rt) => agentSummary(w, rt, t))
        .filter((a) => (!tier || String(a.tier) === tier) && (!band || a.health.band === band) && (!state || a.routing.state === state) && (!lifecycle || a.lifecycle === lifecycle) && (!q || a.slug.includes(q) || a.name.toLowerCase().includes(q)));
      return page(items, query);
    },
  },
  "/agents/{agent_id}": { GET: (r) => agentDetail(r.w, agentOr404(r), r.t) },
  "/agents/{agent_id}/health": { GET: (r) => healthDocAt(r.w, agentOr404(r), r.t) },
  "/agents/{agent_id}/health/history": {
    GET: (r) => {
      const to = r.query.get("to") ? Date.parse(r.query.get("to") ?? "") : r.t;
      const from = r.query.get("from") ? Date.parse(r.query.get("from") ?? "") : to - 60 * MINUTE;
      if (to - from > 3 * 24 * 60 * MINUTE) throw new ProblemError(422, "range_too_wide", "Range too wide", "History covers at most 3 days.");
      return page(healthHistory(r.w, agentOr404(r), from, to, MINUTE), new URLSearchParams({ limit: "200" }));
    },
  },
  "/agents/{agent_id}/metrics": {
    GET: (r) => {
      const grain = r.query.get("grain") ?? "1m";
      const step = grain === "1h" ? 60 * MINUTE : grain === "15m" ? 15 * MINUTE : grain === "5m" ? 5 * MINUTE : MINUTE;
      const to = r.query.get("to") ? Date.parse(r.query.get("to") ?? "") : r.t;
      const from = r.query.get("from") ? Date.parse(r.query.get("from") ?? "") : to - 60 * MINUTE;
      return page(metricsSeries(r.w, agentOr404(r), from, to, step), new URLSearchParams({ limit: "200" }));
    },
  },
  "/agents/{agent_id}/risk": {
    GET: (r) => {
      const h = healthDocAt(r.w, agentOr404(r), r.t);
      const hz = (k: "15m" | "1h" | "24h", s: number) => ({ horizon_s: s, probability_band: h.horizons[k].probability_band, confidence: h.horizons[k].confidence, contributing_rules: h.horizons[k].contributing_rules ?? [] });
      return { agent_id: h.agent_id, evaluated_at: h.computed_at, horizons: { "15m": hz("15m", 900), "1h": hz("1h", 3600), "24h": hz("24h", 86400) }, predicted_failure_mode: h.predicted_failure_mode, recommended_action: h.recommended_action ?? "none", leading_rules_firing: h.factors.filter((f) => f.kind === "leading").map((f) => f.rule), rules_source: "rules/v1" };
    },
  },
  "/agents/{agent_id}/routing": { GET: (r) => routingState(r.w, agentOr404(r)) },
  "/agents/{agent_id}/routing/transitions": {
    GET: (r) => {
      const rt = agentOr404(r);
      return page(r.w.transitions.filter((x) => x.agent_id === rt.id).reverse(), r.query);
    },
  },
  "/agents/{agent_id}/continuity-plan": {
    GET: (r) => {
      const plan = r.w.plans.get(agentOr404(r).id);
      if (!plan) throw new ProblemError(404, "plan_missing", "No continuity plan", "This agent has no continuity plan yet; failover cannot run until it has one.");
      return { status: 200, body: plan, headers: { ETag: `"${plan.row_version}"` } };
    },
  },
  "/agents/{agent_id}/fallback-chains": {
    GET: (r) => {
      const chain = r.w.chains.get(agentOr404(r).id);
      return page(chain ? [chain] : [], r.query);
    },
  },
  "/incidents": {
    GET: ({ w, t, query, principal }) => {
      const agent = query.get("agent_id");
      const open = query.get("open");
      const items = [...w.incidents.values()]
        .filter((i) => (!agent || i.agent_id === agent) && (open !== "true" || (i.state !== "done" && i.state !== "cancelled") || isIncidentLive(w, i.agent_id, i.id)))
        .sort((a, b) => b.created_at - a.created_at)
        .map((i) => incidentView(w, i, principal, t));
      return page(items, query);
    },
    POST: (r) => {
      const { inc, status } = createIncident(r.w, r.principal, body<IncidentCreate>(r), r.t);
      return ok(incidentView(r.w, inc, r.principal, r.t), status);
    },
  },
  "/incidents/{incident_id}": {
    GET: (r) => {
      const inc = r.w.incidents.get(r.params.incident_id ?? "");
      if (!inc) throw notFound("Incident");
      return incidentView(r.w, inc, r.principal, r.t);
    },
  },
  "/incidents/{incident_id}/actions": {
    POST: (r) => incidentView(r.w, incidentAction(r.w, r.principal, r.params.incident_id ?? "", body<IncidentActionBody>(r), r.t), r.principal, r.t),
  },
  "/approvals": {
    GET: ({ w, query }) => page([...w.approvals.values()].filter((a) => !query.get("state") || a.state === query.get("state")).reverse(), query),
  },
  "/kill-switches": {
    GET: ({ w, query }) => page([...w.killSwitches.values()].filter((k) => !query.get("state") || k.state === query.get("state")).reverse(), query),
    POST: (r) => ok(pullKill(r.w, r.principal, body<KillSwitchCreate>(r), r.t), 201),
  },
  "/kill-switches/{kill_switch_id}/release": {
    POST: (r) => releaseKill(r.w, r.principal, r.params.kill_switch_id ?? "", body<{ reason?: string }>(r).reason, r.t),
  },
  "/queue": {
    GET: (r) => {
      if (!r.principal.scopes.includes("queue:act")) requireScope(r.principal, "agents:read");
      const state = r.query.get("state");
      const items = [...r.w.tasks.values()]
        .filter((x) => (state ? state.split(",").includes(x.state) : x.state === "queued" || x.state === "claimed") && (r.query.get("mine") !== "true" || x.claimed_by === r.principal.userId))
        .sort((a, b) => a.priority - b.priority || Date.parse(a.deadline_at) - Date.parse(b.deadline_at))
        .map((x) => ({ id: x.id, agent_id: x.agent_id, incident_id: x.incident_id, state: x.state, priority: x.priority, summary: x.summary, failure_mode: x.failure_mode, fidelity: x.fidelity, deadline_at: x.deadline_at, claimed_by: x.claimed_by, created_at: x.created_at }));
      return { ...page(items, r.query), x_console: { completed_despite_failure: r.w.completedDespiteFailure } };
    },
  },
  "/handoff-tasks/{task_id}": {
    GET: (r) => {
      const task = r.w.tasks.get(r.params.task_id ?? "");
      if (!task) throw notFound("Handoff task");
      return task;
    },
  },
  "/handoff-tasks/{task_id}/packet": {
    GET: (r) => {
      requireScope(r.principal, "packets:read");
      const packet = r.w.packets.get(r.params.task_id ?? "");
      if (!packet) throw notFound("Packet");
      if (r.principal.roles.includes("auditor")) {
        appendAudit(r.w, { action: "data.revealed", actor_type: "human", actor_id: r.principal.userId, resource_type: "handoff_packet", resource_id: r.params.task_id ?? null, detail: { kind: "packet" } }, r.t);
      }
      return { status: 200, body: packet, headers: { ETag: `"${packetHash(packet)}"` } };
    },
  },
  "/handoff-tasks/{task_id}/actions": {
    POST: (r) => handoffAction(r.w, r.principal, r.params.task_id ?? "", body<HandoffTaskAction>(r), r.t),
  },
  "/alerts": {
    GET: (r) => {
      const state = r.query.get("state");
      const unverdicted = r.query.get("unverdicted") === "true";
      const agent = r.query.get("agent_id");
      const items = [...r.w.alerts.values()]
        .filter((a) => (!state || state.split(",").includes(a.state)) && (!agent || a.agent_id === agent) && (!unverdicted || (a.state === "resolved" && a.verdict === null)))
        .sort((a, b) => Date.parse(b.fired_at) - Date.parse(a.fired_at));
      return page(items, r.query);
    },
  },
  "/alerts/{alert_id}": {
    GET: (r) => {
      const a = r.w.alerts.get(r.params.alert_id ?? "");
      if (!a) throw notFound("Alert");
      return a;
    },
  },
  "/alerts/{alert_id}/actions": { POST: (r) => alertAction(r.w, r.principal, r.params.alert_id ?? "", body<AlertAction>(r), r.t) },
  "/provider-incidents": { GET: ({ w, query }) => page([...w.providerIncidents.values()].reverse(), query) },
  "/audit/events": {
    GET: (r) => {
      requireScope(r.principal, "audit:read");
      const action = r.query.get("action");
      const actorType = r.query.get("actor_type");
      const resource = r.query.get("resource_id");
      // occurred_after / occurred_before / agent_id / order as the API (occurred_at, else recorded_at).
      const after = r.query.get("occurred_after") ? Date.parse(r.query.get("occurred_after") ?? "") : null;
      const before = r.query.get("occurred_before") ? Date.parse(r.query.get("occurred_before") ?? "") : null;
      const agent = r.query.get("agent_id");
      const at = (e: (typeof r.w.audit)[number]): number => Date.parse(e.occurred_at ?? e.recorded_at);
      const detailOf = (e: (typeof r.w.audit)[number]): Record<string, unknown> => (e.detail ?? {}) as Record<string, unknown>;
      const chain = r.query.get("order") === "asc" ? [...r.w.audit] : [...r.w.audit].reverse();
      const items = chain.filter(
        (e) =>
          (!action || e.action.startsWith(action)) &&
          (!actorType || e.actor_type === actorType) &&
          (!resource || e.resource_id === resource || detailOf(e).incident_id === resource || detailOf(e).failover_id === resource || detailOf(e).agent_id === resource) &&
          (after === null || at(e) > after) &&
          (before === null || at(e) < before) &&
          (!agent || (e.resource_type === "agent" && e.resource_id === agent) || detailOf(e).agent_id === agent),
      );
      return page(items, r.query);
    },
  },
  "/audit/anchors": {
    GET: (r) => {
      requireScope(r.principal, "audit:read");
      return page([...r.w.anchors].reverse(), r.query);
    },
  },
  "/audit/verifications": { POST: (r) => verifyAudit(r.w, r.principal, body<{ from_seq?: number; to_seq?: number }>(r), r.t) },
  "/audit/exports": { POST: (r) => ok(createExport(r.w, r.principal, body<{ from_seq?: number; to_seq?: number; format?: "jsonl" | "csv" }>(r), r.t), 202) },
  "/audit/exports/{export_id}": {
    GET: (r) => {
      requireScope(r.principal, "audit:export");
      return exportView(r.w, r.params.export_id ?? "", r.t);
    },
  },
  "/capture-policies": {
    GET: (r) => page(r.w.capturePolicies.filter((c) => r.query.get("include_superseded") === "true" || !c.superseded_by), r.query),
    POST: (r) => ok(createCapturePolicy(r.w, r.principal, body<CapturePolicyCreate>(r), r.t), 201),
  },
  "/api-keys": {
    GET: (r) => {
      if (!r.principal.scopes.includes("apikeys:manage")) requireScope(r.principal, "apikeys:manage_agent");
      return page([...r.w.apiKeys].reverse(), r.query);
    },
    POST: (r) => ok(createApiKey(r.w, r.principal, body<ApiKeyCreate>(r), r.t), 201),
  },
  "/api-keys/{key_id}/revoke": { POST: (r) => revokeApiKey(r.w, r.principal, r.params.key_id ?? "", body<{ reason?: string }>(r).reason, r.t) },
  "/api-keys/{key_id}/rotate": { POST: (r) => ok(rotateApiKey(r.w, r.principal, r.params.key_id ?? "", r.t), 201) },
  "/tenant-keys": {
    GET: (r) => {
      requireScope(r.principal, "keys:read");
      return page([...r.w.tenantKeys].sort((a, b) => a.purpose.localeCompare(b.purpose) || b.version - a.version), r.query);
    },
  },
  "/tenant-keys/{purpose}/rotate": {
    POST: (r) => rotateTenantKey(r.w, r.principal, (r.params.purpose ?? "payload") as TenantKeyPurpose, body<{ reason?: string }>(r).reason, r.t),
  },
  ...ACTION_GATE_ROUTES,
  ...MONITOR_ROUTES,
  ...EXTERNAL_MONITOR_ROUTES,
  "/users": {
    GET: (r) => {
      if (!r.principal.scopes.includes("users:manage")) requireScope(r.principal, "tenant:read");
      return page(r.w.users.map((u) => ({ ...u, memberships: r.w.memberships.filter((m) => m.user_id === u.id) })), r.query);
    },
  },
};

function tenantView(w: World) {
  return {
    id: w.tenantId,
    slug: w.slug,
    name: w.name,
    status: "active" as const,
    region_declared: w.region,
    unknown_agent_fail_mode: "open" as const,
    hold_on_incident: false,
    raw_retention_days: 30,
    audit_retention_days: 400,
    backup_retention_days: 7,
    routing_version: w.routingVersion,
    graph_version: 12,
    limits: { max_agents: 2000, ingest_rate_limit: 500, ingest_burst: 5000 },
  };
}

function isIncidentLive(w: World, agentId: string, incidentId: string): boolean {
  const rt = w.agents.get(agentId);
  if (!rt) return false;
  const last = w.transitions.find((x) => x.id === rt.routing.last_transition_id);
  return last?.failover_id === incidentId && rt.routing.state !== "active";
}

/** Demo-only extra: what a tampered copy looks like to the verifier. */
export function demoTamperCheck(w: World) {
  return tamperedCheck(w);
}

/** Match `/agents/abc/health` against the templates above. */
export function matchRoute(path: string): { template: string; params: Record<string, string> } | null {
  const parts = path.split("/").filter(Boolean);
  for (const template of Object.keys(ROUTES)) {
    const tp = template.split("/").filter(Boolean);
    if (tp.length !== parts.length) continue;
    const params: Record<string, string> = {};
    let matched = true;
    for (let i = 0; i < tp.length; i++) {
      const seg = tp[i] ?? "";
      const val = parts[i] ?? "";
      if (seg.startsWith("{")) params[seg.slice(1, -1)] = decodeURIComponent(val);
      else if (seg !== val) {
        matched = false;
        break;
      }
    }
    if (matched) return { template, params };
  }
  return null;
}

export function demoHandle(req: Omit<DemoRequest, "params">, path: string): DemoResult {
  const m = matchRoute(path);
  if (!m) throw new ProblemError(404, "not_found", "Not found", `No demo route for ${path}.`);
  const handler = ROUTES[m.template]?.[req.method];
  if (!handler) throw new ProblemError(405, "method_not_allowed", "Method not allowed", `${req.method} is not supported on ${m.template}.`);
  const out = handler({ ...req, params: m.params });
  if (out && typeof out === "object" && "status" in out && "body" in out && typeof (out as DemoResult).status === "number") return out as DemoResult;
  return { status: 200, body: out };
}

export function hasDemoRoute(path: string, method: string): boolean {
  const m = matchRoute(path);
  return Boolean(m && ROUTES[m.template]?.[method]);
}
