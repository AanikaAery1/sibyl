/**
 * External monitors (D53) and the unified findings feed in demo mode, served on the contract
 * paths: register (key shown once), pause/resume with If-Match, revoke (terminal), issue a key,
 * add a signed webhook (secret shown once), send a test delivery, and `GET /findings` merging
 * Sentinel's findings with the monitors'. Everything here is advisory: nothing changes routing,
 * holds or policies.
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type { ApiKeyCreated } from "@/lib/api/types";
import type { Finding, FindingFeedback, Monitor, MonitorCreate, MonitorCreated, MonitorKeyCreate, MonitorPatch, MonitorRevoke, MonitorWebhookCreated, WebhookCreate, WebhookTestResult } from "@/lib/api/external-monitors";
import type { SentinelFinding } from "@/lib/api/monitor";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { MINUTE, iso, tokenFor } from "./core";
import { requireScope } from "./actions";
import { page } from "./page";
import { monitorState } from "./monitor-state";
import { rateFinding } from "./sentinel";
import { extState, type MonitorRec } from "./external-monitors-state";
import { appendAudit, nextId, type World } from "./world";
import type { DemoRequest, DemoResult } from "./handlers";

const DAY = 24 * 60 * MINUTE;
const EVENT_TYPES = new Set(["alert.fired", "alert.updated", "alert.resolved", "incident.updated", "action.held", "action.decided", "action.expired", "drift.detected", "run.failed"]);
const NAME_RE = /^[^\x00-\x1f\x7f]{1,128}$/;

type Handler = (r: DemoRequest) => DemoResult | unknown;

const invalid = (pointer: string, message: string): ProblemError => new ProblemError(422, "validation_failed", "Not saved", message, { errors: [{ pointer, code: "invalid", message }] });

function requireAnyScope(p: BffPrincipal, ...scopes: Parameters<typeof requireScope>[1][]): void {
  if (scopes.some((s) => p.scopes.includes(s))) return;
  requireScope(p, scopes[0] ?? "monitors:admin");
}

function checkReason(reason: unknown, required: boolean): string | null {
  const r = typeof reason === "string" ? reason.trim() : "";
  if (!r && !required) return null;
  if (r.length < 10 || r.length > 2000) throw invalid("/reason", "A reason of 10 to 2,000 characters.");
  return r;
}

// ── Views ───────────────────────────────────────────────────────────────────

function monitorView(w: World, m: MonitorRec, t: number): Monitor {
  const mine = [...extState(w).findings.values()].filter((f) => f.monitor_id === m.id);
  const recent = mine.filter((f) => t - Date.parse(f.created_at) <= DAY && Date.parse(f.created_at) <= t);
  const last = mine.map((f) => f.created_at).sort().at(-1) ?? null;
  return { ...m, keys: m.state === "revoked" ? [] : m.keys, findings_24h: recent.length, last_finding_at: last };
}

const etag = (m: MonitorRec): string => `"${m.version ?? 1}"`;

function monitorOr404(r: DemoRequest): MonitorRec {
  const m = extState(r.w).monitors.get(r.params.monitor_id ?? "");
  if (!m) throw notFound("Monitor");
  return m;
}

function requireActive(m: MonitorRec): void {
  if (m.state === "revoked") throw new ProblemError(409, "not_active", "Monitor revoked", "A revoked monitor cannot get new keys or webhooks.");
}

function save(w: World, m: MonitorRec): MonitorRec {
  extState(w).monitors.set(m.id, m);
  return m;
}

/** Sentinel's own record in the unified shape (provenance fields it alone has stay on /sentinel). */
export function sentinelAsFinding(f: SentinelFinding): Finding {
  const out = (f.body?.output ?? {}) as Record<string, unknown>;
  const advice = out.advice === "approve" || out.advice === "deny" || out.advice === "needs_more_info" ? out.advice : null;
  const confidence = out.confidence === "low" || out.confidence === "medium" || out.confidence === "high" ? out.confidence : null;
  return {
    id: f.id,
    source: "sentinel",
    monitor_id: null,
    monitor_name: null,
    kind: f.kind,
    subject_kind: f.subject_kind,
    subject_id: f.subject_id ?? null,
    agent_id: f.agent_id ?? null,
    severity: f.severity,
    summary: f.summary,
    body: f.body,
    recommendation: f.recommendation ?? null,
    advice,
    confidence,
    provider: f.provider,
    model: f.model,
    trigger: f.trigger ?? null,
    tokens_in: f.tokens_in ?? null,
    tokens_out: f.tokens_out ?? null,
    cost_usd: f.cost_usd ?? null,
    alert_id: f.alert_id ?? null,
    feedback: f.feedback ?? null,
    feedback_by_user_id: f.feedback_by_user_id ?? null,
    feedback_at: f.feedback_at ?? null,
    created_at: f.created_at,
    advisory: true,
  };
}

function allFindings(w: World, t: number): Finding[] {
  const sentinel = [...monitorState(w).findings.values()].map(sentinelAsFinding);
  const external = [...extState(w).findings.values()].filter((f) => Date.parse(f.created_at) <= t);
  return [...sentinel, ...external].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
}

function listFindings(r: DemoRequest): Finding[] {
  requireScope(r.principal, "sentinel:read");
  const q = r.query;
  const eq = (k: string, v: string | null | undefined): boolean => !q.get(k) || q.get(k) === v;
  const since = q.get("since") ? Date.parse(q.get("since") ?? "") : null;
  return allFindings(r.w, r.t).filter(
    (f) => eq("source", f.source) && eq("monitor_id", f.monitor_id) && eq("kind", f.kind) && eq("subject_kind", f.subject_kind) && eq("subject_id", f.subject_id) && eq("agent_id", f.agent_id) && eq("severity", f.severity) && (since === null || Date.parse(f.created_at) >= since),
  );
}

function findingOr404(r: DemoRequest): Finding {
  requireScope(r.principal, "sentinel:read");
  const f = allFindings(r.w, r.t).find((x) => x.id === r.params.finding_id);
  if (!f) throw notFound("Finding");
  return f;
}

function rate(r: DemoRequest): Finding {
  const f = findingOr404(r);
  const feedback = ((r.body ?? {}) as { feedback?: FindingFeedback }).feedback;
  if (feedback !== "useful" && feedback !== "not_useful" && feedback !== "wrong") throw invalid("/feedback", "useful | not_useful | wrong");
  if (f.source === "sentinel") return sentinelAsFinding(rateFinding(r.w, r.principal, f.id, feedback, r.t));
  const next: Finding = { ...f, feedback, feedback_by_user_id: r.principal.userId, feedback_at: iso(r.t) };
  extState(r.w).findings.set(f.id, next);
  appendAudit(r.w, { action: "finding.feedback_recorded", actor_type: "human", actor_id: r.principal.userId, resource_type: "finding", resource_id: f.id, detail: { feedback, source: "external", monitor_id: f.monitor_id } }, r.t);
  return next;
}

// ── Mutations ───────────────────────────────────────────────────────────────

function issueKey(w: World, p: BffPrincipal, m: MonitorRec, body: MonitorKeyCreate, t: number): { rec: MonitorRec; created: ApiKeyCreated } {
  const name = (body.name ?? `${m.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 60)}-key`).trim();
  if (!name || name.length > 80) throw invalid("/name", "A key name of 1 to 80 characters.");
  const env = body.env ?? "test";
  const id = nextId(w, "monitor-key");
  const prefix = tokenFor(`prefix:${id}`, 12);
  const secret = `sbl_${env}_${prefix}_${tokenFor(`secret:${id}`, 43)}`;
  const expires = body.expires_at ?? iso(t + 365 * DAY);
  const created: ApiKeyCreated = { id, name, env, prefix, scopes: ["monitor:read", "findings:write"], agent_id: null, status: "active", expires_at: expires, last_used_at: null, last_used_ip_hash: null, rotated_from_id: null, rotation_grace_until: null, created_by: p.userId, created_at: iso(t), secret };
  const rec = { ...m, keys: [...m.keys, { id, name, prefix, env, status: "active" as const, expires_at: expires, last_used_at: null, created_at: iso(t) }] };
  appendAudit(w, { action: "api_key.created", actor_type: "human", actor_id: p.userId, resource_type: "api_key", resource_id: id, resource_ref: name, detail: { scopes: created.scopes, monitor_id: m.id, prefix } }, t);
  return { rec, created };
}

function createMonitor(r: DemoRequest): DemoResult {
  requireScope(r.principal, "monitors:admin");
  const b = (r.body ?? {}) as MonitorCreate;
  const name = typeof b.name === "string" ? b.name.trim() : "";
  if (!NAME_RE.test(name)) throw invalid("/name", "A name of 1 to 128 characters without control characters.");
  if (b.kind !== "mcp" && b.kind !== "webhook" && b.kind !== "api") throw invalid("/kind", "mcp | webhook | api");
  const rate = b.rate_limit_per_min ?? 60;
  if (!Number.isInteger(rate) || rate < 1 || rate > 600) throw invalid("/rate_limit_per_min", "1 to 600 per minute.");
  const all = b.all_groups ?? true;
  const groups = [...new Set(b.group_ids ?? [])];
  const known = new Set(extState(r.w).groups.map((g) => g.id));
  if (!all && (groups.length === 0 || groups.some((g) => !known.has(g)))) throw invalid("/group_ids", "Pick agent groups that exist, or watch all groups.");
  const reason = checkReason(b.reason, false);
  if ([...extState(r.w).monitors.values()].some((m) => m.state !== "revoked" && m.name.toLowerCase() === name.toLowerCase())) {
    throw new ProblemError(409, "conflict", "Name taken", "An unrevoked monitor already has this name.");
  }
  const id = nextId(r.w, "monitor");
  let rec: MonitorRec = {
    id,
    name,
    kind: b.kind,
    description: b.description?.trim() || null,
    owner_user_id: b.owner_user_id ?? r.principal.userId,
    all_groups: all,
    group_ids: all ? [] : groups,
    state: "active",
    rate_limit_per_min: rate,
    version: 1,
    keys: [],
    webhooks: [],
    created_by_user_id: r.principal.userId,
    revoked_at: null,
    revoke_reason: null,
    created_at: iso(r.t),
    updated_at: iso(r.t),
    advisory: true,
  };
  appendAudit(r.w, { action: "monitor.registered", actor_type: "human", actor_id: r.principal.userId, resource_type: "monitor", resource_id: id, resource_ref: name, reason, detail: { kind: b.kind, all_groups: all, group_ids: rec.group_ids, rate_limit_per_min: rate } }, r.t);
  let apiKey: ApiKeyCreated | null = null;
  if (b.issue_key !== false) {
    const out = issueKey(r.w, r.principal, rec, { env: b.key_env ?? "test", ...(b.key_expires_at ? { expires_at: b.key_expires_at } : {}) }, r.t);
    rec = out.rec;
    apiKey = out.created;
  }
  save(r.w, rec);
  const body: MonitorCreated = { ...monitorView(r.w, rec, r.t), api_key: apiKey };
  return { status: 201, body, headers: { ETag: etag(rec) } };
}

function patchMonitor(r: DemoRequest): DemoResult {
  requireScope(r.principal, "monitors:admin");
  const m = monitorOr404(r);
  if (!r.ifMatch) throw new ProblemError(428, "precondition_required", "If-Match required", "Send the monitor version you edited (If-Match).");
  if (r.ifMatch !== etag(m)) throw new ProblemError(412, "precondition_failed", "Changed by someone else", "The monitor changed since you opened it. Reload, then apply your change again.");
  if (m.state === "revoked") throw new ProblemError(409, "invalid_transition", "Monitor revoked", "A revoked monitor is terminal.");
  const b = (r.body ?? {}) as MonitorPatch;
  if (!b || Object.keys(b).length === 0) throw invalid("/", "Change at least one field.");
  if (b.state !== undefined && b.state !== "active" && b.state !== "paused") throw invalid("/state", "active | paused");
  if (b.name !== undefined && !NAME_RE.test(b.name.trim())) throw invalid("/name", "A name of 1 to 128 characters.");
  if (b.rate_limit_per_min !== undefined && (!Number.isInteger(b.rate_limit_per_min) || b.rate_limit_per_min < 1 || b.rate_limit_per_min > 600)) throw invalid("/rate_limit_per_min", "1 to 600 per minute.");
  const reason = checkReason(b.reason, false);
  const next: MonitorRec = {
    ...m,
    ...(b.name !== undefined ? { name: b.name.trim() } : {}),
    ...(b.description !== undefined ? { description: b.description } : {}),
    ...(b.state !== undefined ? { state: b.state } : {}),
    ...(b.rate_limit_per_min !== undefined ? { rate_limit_per_min: b.rate_limit_per_min } : {}),
    ...(b.all_groups !== undefined ? { all_groups: b.all_groups, group_ids: b.all_groups ? [] : [...new Set(b.group_ids ?? [])] } : {}),
    version: (m.version ?? 1) + 1,
    updated_at: iso(r.t),
  };
  save(r.w, next);
  const changed = Object.keys(b).filter((k) => k !== "reason");
  appendAudit(r.w, { action: "monitor.updated", actor_type: "human", actor_id: r.principal.userId, resource_type: "monitor", resource_id: m.id, resource_ref: next.name, reason, detail: { changed, state: next.state } }, r.t);
  return { status: 200, body: monitorView(r.w, next, r.t), headers: { ETag: etag(next) } };
}

function revokeMonitor(r: DemoRequest): Monitor {
  requireScope(r.principal, "monitors:admin");
  const m = monitorOr404(r);
  if (m.state === "revoked") throw new ProblemError(409, "invalid_transition", "Already revoked", "This monitor is already revoked.");
  const reason = checkReason(((r.body ?? {}) as MonitorRevoke).reason, true);
  const next: MonitorRec = {
    ...m,
    state: "revoked",
    keys: m.keys.map((k) => ({ ...k, status: "revoked" as const })),
    webhooks: m.webhooks.map((h) => ({ ...h, state: "disabled" as const, disabled_reason: "Monitor revoked", updated_at: iso(r.t) })),
    revoked_at: iso(r.t),
    revoke_reason: reason,
    version: (m.version ?? 1) + 1,
    updated_at: iso(r.t),
  };
  save(r.w, next);
  appendAudit(r.w, { action: "monitor.revoked", actor_type: "human", actor_id: r.principal.userId, resource_type: "monitor", resource_id: m.id, resource_ref: m.name, reason, detail: { keys_revoked: m.keys.length, webhooks_disabled: m.webhooks.length } }, r.t);
  return monitorView(r.w, next, r.t);
}

function addKey(r: DemoRequest): DemoResult {
  requireScope(r.principal, "monitors:admin");
  const m = monitorOr404(r);
  requireActive(m);
  const body = (r.body ?? {}) as MonitorKeyCreate;
  checkReason(body.reason, false);
  const { rec, created } = issueKey(r.w, r.principal, m, body, r.t);
  save(r.w, { ...rec, version: (m.version ?? 1) + 1, updated_at: iso(r.t) });
  return { status: 201, body: created };
}

function addWebhook(r: DemoRequest): DemoResult {
  requireScope(r.principal, "monitors:admin");
  const m = monitorOr404(r);
  requireActive(m);
  const b = (r.body ?? {}) as WebhookCreate;
  const raw = typeof b.url === "string" ? b.url.trim() : "";
  let url: URL | null = null;
  try {
    url = new URL(raw);
  } catch {
    url = null;
  }
  if (!url || url.protocol !== "https:" || raw.length < 8 || raw.length > 2048) throw invalid("/url", "An https URL.");
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.)/.test(url.hostname) || url.hostname.endsWith(".internal") || url.hostname.endsWith(".local")) {
    throw new ProblemError(422, "base_url_not_allowlisted", "Address not allowed", "Webhooks go to public https addresses on the egress allowlist only.");
  }
  const events = [...new Set(b.event_types ?? [])];
  if (!events.length || events.some((e) => !EVENT_TYPES.has(e))) throw invalid("/event_types", "Pick at least one known event type.");
  const reason = checkReason(b.reason, false);
  const id = nextId(r.w, "webhook");
  const hook = { id, monitor_id: m.id, url: raw, event_types: events, state: "enabled" as const, consecutive_failures: 0, last_delivery_at: null, last_delivery_status: null, last_response_code: null, disabled_reason: null, created_at: iso(r.t), updated_at: iso(r.t) };
  save(r.w, { ...m, webhooks: [...m.webhooks, hook], version: (m.version ?? 1) + 1, updated_at: iso(r.t) });
  appendAudit(r.w, { action: "monitor.updated", actor_type: "human", actor_id: r.principal.userId, resource_type: "monitor", resource_id: m.id, resource_ref: m.name, reason, detail: { webhook_added: id, host: url.hostname, event_types: events } }, r.t);
  const body: MonitorWebhookCreated = { ...hook, secret: `whsec_${tokenFor(`whsec:${r.w.slug}:${id}`, 43)}` };
  return { status: 201, body };
}

function testWebhook(r: DemoRequest): WebhookTestResult {
  requireScope(r.principal, "monitors:admin");
  const m = monitorOr404(r);
  requireActive(m);
  const h = m.webhooks.find((x) => x.id === r.params.webhook_id);
  if (!h) throw notFound("Webhook");
  if (h.state !== "enabled") throw new ProblemError(409, "not_active", "Webhook disabled", "Enable the webhook before testing it.");
  // The demo receiver: the held-actions hook is mid-outage (503); everything else answers 202.
  const failing = h.last_delivery_status === "retrying" || h.last_delivery_status === "dead";
  const result: WebhookTestResult = failing ? { ok: false, http_status: 503, error: "http_error", latency_ms: 412, delivery_id: nextId(r.w, "delivery") } : { ok: true, http_status: 202, error: null, latency_ms: 184, delivery_id: nextId(r.w, "delivery") };
  appendAudit(r.w, { action: "webhook.tested", actor_type: "human", actor_id: r.principal.userId, resource_type: "monitor", resource_id: m.id, resource_ref: m.name, detail: { webhook_id: h.id, ok: result.ok, http_status: result.http_status, error: result.error, latency_ms: result.latency_ms } }, r.t);
  return result;
}

// ── Routes ──────────────────────────────────────────────────────────────────

export const EXTERNAL_MONITOR_ROUTES: Record<string, Partial<Record<string, Handler>>> = {
  "/agent-groups": {
    GET: (r) => {
      requireScope(r.principal, "agents:read");
      return page(extState(r.w).groups, r.query);
    },
  },
  "/monitors": {
    GET: (r) => {
      requireAnyScope(r.principal, "monitors:admin", "sentinel:read");
      const state = r.query.get("state");
      const kind = r.query.get("kind");
      const rows = [...extState(r.w).monitors.values()]
        .filter((m) => (!state || m.state === state) && (!kind || m.kind === kind))
        .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
        .map((m) => monitorView(r.w, m, r.t));
      return page(rows, r.query);
    },
    POST: createMonitor,
  },
  "/monitors/{monitor_id}": {
    GET: (r) => {
      requireAnyScope(r.principal, "monitors:admin", "sentinel:read");
      const m = monitorOr404(r);
      return { status: 200, body: monitorView(r.w, m, r.t), headers: { ETag: etag(m) } };
    },
    PATCH: patchMonitor,
  },
  "/monitors/{monitor_id}/revoke": { POST: revokeMonitor },
  "/monitors/{monitor_id}/keys": { POST: addKey },
  "/monitors/{monitor_id}/webhooks": { POST: addWebhook },
  "/monitors/{monitor_id}/webhooks/{webhook_id}/test": { POST: testWebhook },
  "/findings": { GET: (r) => page(listFindings(r), r.query) },
  "/findings/{finding_id}": { GET: findingOr404 },
  "/findings/{finding_id}/feedback": { POST: rate },
};
