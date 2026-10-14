/**
 * External monitors (D53) in the demo: per-world state, the meridian seed (three registered
 * monitors and one revoked, agent groups, a few advisory findings) and the scenario beats where
 * monitors report during the outage. Seeds use stable `idFor` names and anchor-relative times,
 * like monitor-state.ts, so a rebuilt world (seek, reset) is identical.
 *
 *   0:40   PagerDuty bridge (webhook) flags the claims-triage error burst as an anomaly
 *   0:55   Claude ops reviewer (MCP) reviews the ₹75,000 hold: deny, new payee (advisory)
 */
import "server-only";
import type { AgentGroup, Finding, Monitor, MonitorKey, MonitorWebhook } from "@/lib/api/external-monitors";
import { PERSONAS } from "@/lib/auth/personas";
import { MINUTE, idFor, iso, tokenFor } from "./core";
import { agentId } from "./fixtures";
import { appendAudit, emit, type World } from "./world";

const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** A monitor as stored: the view adds `findings_24h` and `last_finding_at`. */
export type MonitorRec = Omit<Monitor, "findings_24h" | "last_finding_at">;

export interface ExternalMonitorState {
  monitors: Map<string, MonitorRec>;
  findings: Map<string, Finding>;
  groups: AgentGroup[];
}

const g = globalThis as typeof globalThis & { __sibylExtMonitorStates?: WeakMap<World, ExternalMonitorState> };
const STATES: WeakMap<World, ExternalMonitorState> = (g.__sibylExtMonitorStates ??= new WeakMap<World, ExternalMonitorState>());

const ADMIN_ID = PERSONAS.find((p) => p.id === "admin")?.userId ?? "";

export const groupId = (w: World, slug: string): string => idFor(`agent-group:${w.slug}:${slug}`);
export const monitorIdOf = (w: World, slug: string): string => idFor(`monitor:${w.slug}:${slug}`);

export function extState(w: World): ExternalMonitorState {
  const cur = STATES.get(w);
  if (cur) return cur;
  const s: ExternalMonitorState = { monitors: new Map(), findings: new Map(), groups: [] };
  STATES.set(w, s);
  if (w.slug === "meridian") seedMeridian(w, s);
  return s;
}

export function monitorKey(w: World, monitorSlug: string, name: string, env: "live" | "test", createdAt: number, lastUsed: number | null): MonitorKey {
  const id = idFor(`monitor-key:${w.slug}:${monitorSlug}:${name}`);
  return { id, name, prefix: tokenFor(`prefix:${id}`, 12), env, status: "active", expires_at: iso(createdAt + 365 * DAY), last_used_at: lastUsed === null ? null : iso(lastUsed), created_at: iso(createdAt) };
}

function hook(w: World, monitorSlug: string, n: number, o: Omit<MonitorWebhook, "id" | "monitor_id">): MonitorWebhook {
  return { id: idFor(`webhook:${w.slug}:${monitorSlug}:${n}`), monitor_id: monitorIdOf(w, monitorSlug), ...o };
}

interface FindingDraft {
  key: string;
  monitor: string;
  kind: Finding["kind"];
  subject_kind: Finding["subject_kind"];
  subject_id: string | null;
  agent_id: string | null;
  severity: Finding["severity"];
  summary: string;
  body: Record<string, unknown>;
  recommendation: string | null;
  advice?: Finding["advice"];
  confidence: Finding["confidence"];
  provider: string | null;
  model: string | null;
  at: number;
}

export function externalFinding(w: World, s: ExternalMonitorState, d: FindingDraft): Finding {
  const m = s.monitors.get(monitorIdOf(w, d.monitor));
  return {
    id: idFor(`external-finding:${w.slug}:${d.key}`),
    source: "external",
    monitor_id: m?.id ?? null,
    monitor_name: m?.name ?? null,
    kind: d.kind,
    subject_kind: d.subject_kind,
    subject_id: d.subject_id,
    agent_id: d.agent_id,
    severity: d.severity,
    summary: d.summary,
    body: d.body,
    recommendation: d.recommendation,
    advice: d.advice ?? null,
    confidence: d.confidence,
    provider: d.provider,
    model: d.model,
    trigger: "external",
    tokens_in: null,
    tokens_out: null,
    cost_usd: null,
    alert_id: null,
    feedback: null,
    feedback_by_user_id: null,
    feedback_at: null,
    created_at: iso(d.at),
    advisory: true,
  };
}

function seedMeridian(w: World, s: ExternalMonitorState): void {
  const a = w.anchorAt;
  s.groups = [
    { id: groupId(w, "claims"), slug: "claims-payouts", name: "Claims & payouts", description: "Claims triage, payouts and invoice reconciliation", parent_group_id: null, owner_user_id: ADMIN_ID, created_at: iso(a - 60 * DAY) },
    { id: groupId(w, "logistics"), slug: "logistics", name: "Logistics", description: "Dispatch, routing and order intake", parent_group_id: null, owner_user_id: ADMIN_ID, created_at: iso(a - 60 * DAY) },
    { id: groupId(w, "customer"), slug: "customer-service", name: "Customer service", description: "Chat, returns and the support inbox", parent_group_id: null, owner_user_id: ADMIN_ID, created_at: iso(a - 60 * DAY) },
  ];
  const base = { owner_user_id: ADMIN_ID, created_by_user_id: ADMIN_ID, advisory: true as const, revoked_at: null, revoke_reason: null };
  const monitors: MonitorRec[] = [
    {
      ...base,
      id: monitorIdOf(w, "claude-ops"),
      name: "Claude ops reviewer",
      kind: "mcp",
      description: "Claude Desktop on the on-call laptop, running sibyl-mcp. Second opinion on held payouts and incident timelines.",
      all_groups: true,
      group_ids: [],
      state: "active",
      rate_limit_per_min: 60,
      version: 2,
      keys: [monitorKey(w, "claude-ops", "claude-desktop-oncall", "live", a - 12 * DAY, a - 4 * MINUTE)],
      webhooks: [],
      created_at: iso(a - 12 * DAY),
      updated_at: iso(a - 3 * DAY),
    },
    {
      ...base,
      id: monitorIdOf(w, "pagerduty"),
      name: "PagerDuty bridge",
      kind: "webhook",
      description: "Receives signed alert and incident events, pages the claims on-call and files an anomaly finding when a burst looks unusual.",
      all_groups: false,
      group_ids: [groupId(w, "claims"), groupId(w, "logistics")],
      state: "active",
      rate_limit_per_min: 120,
      version: 4,
      keys: [monitorKey(w, "pagerduty", "pd-bridge", "live", a - 30 * DAY, a - 9 * MINUTE)],
      webhooks: [
        hook(w, "pagerduty", 1, { url: "https://events.pagerduty.example/integration/sibyl/enqueue", event_types: ["alert.fired", "alert.resolved", "incident.updated"], state: "enabled", consecutive_failures: 0, last_delivery_at: iso(a - 7 * MINUTE), last_delivery_status: "delivered", last_response_code: 202, disabled_reason: null, created_at: iso(a - 30 * DAY), updated_at: iso(a - 7 * MINUTE) }),
        hook(w, "pagerduty", 2, { url: "https://hooks.meridian-logistics.example/sibyl/held-actions", event_types: ["action.held", "action.decided", "action.expired"], state: "enabled", consecutive_failures: 3, last_delivery_at: iso(a - 18 * MINUTE), last_delivery_status: "retrying", last_response_code: 503, disabled_reason: null, created_at: iso(a - 21 * DAY), updated_at: iso(a - 18 * MINUTE) }),
      ],
      created_at: iso(a - 30 * DAY),
      updated_at: iso(a - 5 * DAY),
    },
    {
      ...base,
      id: monitorIdOf(w, "nightly-audit"),
      name: "Nightly audit script",
      kind: "api",
      description: "A cron job on the finance VM: reads the day's runs and spend through the REST API and files cost findings.",
      all_groups: true,
      group_ids: [],
      state: "paused",
      rate_limit_per_min: 30,
      version: 5,
      keys: [monitorKey(w, "nightly-audit", "finance-cron", "live", a - 45 * DAY, a - 9 * HOUR)],
      webhooks: [],
      created_at: iso(a - 45 * DAY),
      updated_at: iso(a - 2 * HOUR),
    },
    {
      ...base,
      id: monitorIdOf(w, "slack-relay"),
      name: "Legacy Slack relay",
      kind: "webhook",
      description: "Posted alerts into #ops-alerts before the PagerDuty bridge.",
      all_groups: true,
      group_ids: [],
      state: "revoked",
      rate_limit_per_min: 60,
      version: 7,
      keys: [],
      webhooks: [hook(w, "slack-relay", 1, { url: "https://hooks.slack.example/services/T000/B000/relay", event_types: ["alert.fired"], state: "disabled", consecutive_failures: 0, last_delivery_at: iso(a - 20 * DAY), last_delivery_status: "delivered", last_response_code: 200, disabled_reason: "Monitor revoked", created_at: iso(a - 90 * DAY), updated_at: iso(a - 19 * DAY) })],
      created_at: iso(a - 90 * DAY),
      updated_at: iso(a - 19 * DAY),
      revoked_at: iso(a - 19 * DAY),
      revoke_reason: "Replaced by the PagerDuty bridge; the Slack channel is archived.",
    },
  ];
  for (const m of monitors) s.monitors.set(m.id, m);

  const seeded: FindingDraft[] = [
    {
      key: "nightly-cost",
      monitor: "nightly-audit",
      kind: "cost",
      subject_kind: "fleet",
      subject_id: null,
      agent_id: null,
      severity: "info",
      summary: "Yesterday's model spend was ₹41,870, 6% over the 7-day average; the report writer accounts for most of the rise.",
      body: { spend_inr: 41870, seven_day_avg_inr: 39490, top_movers: ["Report writer +₹1,940 (longer weekly report)", "Claims triage +₹410"], window: "2026-10-09" },
      recommendation: "Cap the report writer's output tokens or move it to gpt-5-mini for the draft pass.",
      confidence: "high",
      provider: null,
      model: null,
      at: a - 9 * HOUR,
    },
    {
      key: "claude-order-intake",
      monitor: "claude-ops",
      kind: "quality",
      subject_kind: "agent",
      subject_id: agentId(w.slug, "order-intake"),
      agent_id: agentId(w.slug, "order-intake"),
      severity: "warning",
      summary: "Order intake repeats the same slot search before booking; 3 of the last 20 runs booked a slot the customer did not ask for.",
      body: { evidence: ["Runs retry tms.slot_search up to 37 times with identical arguments", "3 of 20 bookings differ from the requested delivery window"], checked_runs: 20, purpose_unchanged: true },
      recommendation: "Add a retry cap to the slot-search tool and have the agent confirm the window when the first choice is full.",
      confidence: "medium",
      provider: "anthropic",
      model: "claude-opus-4-1",
      at: a - 2 * HOUR,
    },
  ];
  for (const d of seeded) {
    const f = externalFinding(w, s, d);
    s.findings.set(f.id, f);
  }
}

function record(w: World, s: ExternalMonitorState, f: Finding, at: number): void {
  s.findings.set(f.id, f);
  appendAudit(w, { action: "finding.submitted", actor_type: "api_key", actor_id: null, resource_type: "finding", resource_id: f.id, resource_ref: f.monitor_name ?? null, detail: { source: "external", monitor_id: f.monitor_id, kind: f.kind, subject_kind: f.subject_kind, subject_id: f.subject_id, severity: f.severity, advisory: true } }, at);
  emit(w, "finding.submitted", { finding_id: f.id, kind: f.kind, subject_id: f.subject_id, agent_id: f.agent_id, source: "external" }, at);
}

function pagerDutyAnomaly(w: World, at: number): void {
  const s = extState(w);
  const agent = agentId(w.slug, "claims-triage");
  record(
    w,
    s,
    externalFinding(w, s, {
      key: "pd-claims-burst",
      monitor: "pagerduty",
      kind: "anomaly",
      subject_kind: "agent",
      subject_id: agent,
      agent_id: agent,
      severity: "warning",
      summary: "Claims triage error burst matches the Anthropic outage pattern; paged the claims on-call (incident PD-48213).",
      body: { pagerduty_incident: "PD-48213", escalation_policy: "Claims on-call", correlated_agents: 7, note: "Same second as six other Anthropic agents; provider-side, not this agent." },
      recommendation: "No action on the agent; follow the provider incident. The page auto-resolves when Sibyl resolves the alert.",
      confidence: "high",
      provider: null,
      model: null,
      at,
    }),
    at,
  );
}

function claudeHeldReview(w: World, at: number): void {
  const s = extState(w);
  const held = [...w.heldActions.values()].find((h) => h.call_id === "clm-204871-pay-1");
  if (!held) return;
  record(
    w,
    s,
    externalFinding(w, s, {
      key: "claude-held-payout",
      monitor: "claude-ops",
      kind: "held_action_review",
      subject_kind: "held_action",
      subject_id: held.id,
      agent_id: held.agent_id,
      severity: "warning",
      summary: "Payout of ₹75,000 goes to an account first seen today; the surveyor's estimate matches but the payee bank changed since the last claim.",
      body: { checked: ["Claim CLM-204871 surveyor estimate: ₹75,000", "Previous payouts to this transporter used XXXXXXXX2210 (HDFC)", "Account XXXXXXXX0937 (ICICI) first seen today"], risks: ["Changed beneficiary account on an irreversible transfer"] },
      recommendation: "Call the transporter on the number in the vendor master (not the one in the claim) to confirm the new account before approving.",
      advice: "deny",
      confidence: "medium",
      provider: "anthropic",
      model: "claude-opus-4-1",
      at,
    }),
    at,
  );
}

export const EXTERNAL_MONITOR_BEATS = [
  { at: 40, id: "monitor-pd-anomaly", label: "PagerDuty bridge (external monitor) flags the claims-triage error burst (advisory)", run: (w: World, at: number) => pagerDutyAnomaly(w, at) },
  { at: 55, id: "monitor-claude-held", label: "Claude ops reviewer (external monitor, MCP) reviews the ₹75,000 hold (advisory)", run: (w: World, at: number) => claudeHeldReview(w, at) },
] as const;
