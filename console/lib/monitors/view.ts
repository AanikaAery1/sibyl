/**
 * External monitors (D53) and the unified findings feed: display, form and snippet logic, pure
 * and unit-tested. A monitor is any outside agent (an MCP assistant, a webhook receiver, a
 * script on the REST API) that reads fleet metadata with a monitor-bound key and writes
 * **advisory** findings. Like Sentinel, it never allows, blocks, approves, fails over or changes
 * policy. Everything a monitor writes (summary, body, recommendation) is untrusted text.
 */
import type { Tone } from "@/lib/labels";
import type {
  Finding,
  FindingKind,
  FindingSource,
  FindingSubjectKind,
  Monitor,
  MonitorCreate,
  MonitorKind,
  MonitorState,
  MonitorWebhook,
  WebhookCreate,
  WebhookDeliveryStatus,
  WebhookEventType,
  WebhookTestResult,
} from "@/lib/api/external-monitors";

type ApiKeyEnv = NonNullable<MonitorCreate["key_env"]>;

// ── Paths ───────────────────────────────────────────────────────────────────

export const MONITORS_PATH = "/monitors?limit=100";
export const monitorPath = (id: string): string => `/monitors/${encodeURIComponent(id)}`;
export const AGENT_GROUPS_PATH = "/agent-groups?limit=200";

export type SourceFilter = FindingSource | null;

/** `GET /findings` for the Sentinel page: both sources unless one is picked. */
export function findingsFeedPath(opts: { source?: SourceFilter; kind?: FindingKind | null; monitorId?: string | null; limit?: number } = {}): string {
  const q = new URLSearchParams({ limit: String(opts.limit ?? 100) });
  if (opts.source) q.set("source", opts.source);
  if (opts.kind) q.set("kind", opts.kind);
  if (opts.monitorId) q.set("monitor_id", opts.monitorId);
  return `/findings?${q.toString()}`;
}

/** The findings about one incident or held action, newest first (the decision screens). */
export const subjectFindingsPath = (kind: "incident" | "held_action", id: string): string => `/findings?subject_kind=${kind}&subject_id=${encodeURIComponent(id)}&limit=10`;

export const findingPath = (id: string): string => `/findings/${encodeURIComponent(id)}`;

export function sourceOf(v: string | null | undefined): SourceFilter {
  return v === "sentinel" || v === "external" ? v : null;
}

// ── Labels ──────────────────────────────────────────────────────────────────

export const MONITOR_KIND_LABEL: Readonly<Record<MonitorKind, string>> = { mcp: "MCP", webhook: "Webhook", api: "REST API" };

export const MONITOR_KIND_HELP: Readonly<Record<MonitorKind, string>> = {
  mcp: "An MCP-capable assistant (Claude Desktop, Claude Code, an Agent SDK app) runs sibyl-mcp with the monitor key.",
  webhook: "Sibyl pushes signed events (alerts, incidents, held actions, drift, failed runs) to your receiver; it reports back with the key.",
  api: "A script or service polls the REST API (or the Python SDK's monitor client) and submits findings.",
};

export const MONITOR_STATE_LABEL: Readonly<Record<MonitorState, string>> = { active: "Active", paused: "Paused", revoked: "Revoked" };
export const MONITOR_STATE_TONE: Readonly<Record<MonitorState, Tone>> = { active: "healthy", paused: "watch", revoked: "quiet" };

export const DELIVERY_LABEL: Readonly<Record<WebhookDeliveryStatus, string>> = { delivered: "Delivered", retrying: "Retrying", dead: "Dead-lettered" };
export const DELIVERY_TONE: Readonly<Record<WebhookDeliveryStatus, Tone>> = { delivered: "healthy", retrying: "degraded", dead: "failed" };

export const EVENT_TYPES: readonly WebhookEventType[] = ["alert.fired", "alert.updated", "alert.resolved", "incident.updated", "action.held", "action.decided", "action.expired", "drift.detected", "run.failed"];

export const EVENT_LABEL: Readonly<Record<WebhookEventType, string>> = {
  "alert.fired": "Alert fired",
  "alert.updated": "Alert updated",
  "alert.resolved": "Alert resolved",
  "incident.updated": "Incident updated",
  "action.held": "Action held",
  "action.decided": "Held action decided",
  "action.expired": "Held action expired",
  "drift.detected": "Drift detected",
  "run.failed": "Run failed",
};

export const FINDING_KIND_LABEL: Readonly<Record<FindingKind, string>> = {
  incident_explanation: "Incident explanation",
  held_action_review: "Held-action review",
  semantic_drift: "Semantic drift review",
  fleet_summary: "Fleet summary",
  anomaly: "Anomaly",
  safety: "Safety",
  quality: "Quality",
  cost: "Cost",
  other: "Other",
};

export const FINDING_SUBJECT_LABEL: Readonly<Record<FindingSubjectKind, string>> = { incident: "Incident", held_action: "Held action", agent: "Agent", run: "Run", fleet: "Fleet" };

export const MONITOR_ADVISORY_COPY = "Monitors are advisory only. A monitor reads fleet metadata and reports findings; it never allows, blocks, approves, fails over or changes a policy. People and deterministic rules decide.";

/** "Sentinel" or "Monitor: <name>" (the name is display text, never markup). */
export function sourceLabel(f: Pick<Finding, "source" | "monitor_name">): string {
  if (f.source === "sentinel") return "Sentinel";
  const name = plainText(f.monitor_name ?? "", 128).trim();
  return `Monitor: ${name || "unnamed"}`;
}

/** Where a finding's subject lives in the console (runs included, unlike Sentinel's own). */
export function findingSubjectHref(f: Pick<Finding, "subject_kind" | "subject_id" | "agent_id">): string | null {
  const id = f.subject_id ?? null;
  switch (f.subject_kind) {
    case "incident":
      return id ? `/incidents/${id}` : null;
    case "held_action":
      return id ? `/held-actions/${id}` : null;
    case "run":
      return id ? `/runs/${id}` : null;
    case "agent": {
      const agent = id ?? f.agent_id ?? null;
      return agent ? `/agents/${agent}` : null;
    }
    default:
      return "/fleet";
  }
}

/** For the decision screens: the newest Sentinel finding and the newest of each monitor (at most 3). */
export function latestBySource(rows: readonly Finding[]): { sentinel: Finding | null; external: Finding[] } {
  const sentinel = rows.find((f) => f.source === "sentinel") ?? null;
  const seen = new Set<string>();
  const external = rows.filter((f) => {
    if (f.source !== "external") return false;
    const key = f.monitor_id ?? f.id;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { sentinel, external: external.slice(0, 3) };
}

// ── Untrusted text ──────────────────────────────────────────────────────────

// Bidi overrides/isolates (Trojan Source-style reordering) and C0/C1 controls other than \t \n.
const UNSAFE_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩]/g;
const MAX_TEXT = 4000;

/**
 * Monitor-written text for display: plain text only (React escapes it; it is never parsed as
 * HTML or markdown), with direction overrides and control characters removed and the length
 * capped so one finding cannot swamp a screen.
 */
export function plainText(v: unknown, max = MAX_TEXT): string {
  const s = typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
  const clean = s.replace(UNSAFE_CHARS, "");
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

export interface ExternalBodyRow {
  key: string;
  label: string;
  text: string | null;
  items: string[] | null;
  flag: boolean | null;
}

const MAX_ROWS = 40;
const MAX_ITEMS = 50;

function humanize(key: string): string {
  const k = plainText(key, 80).replaceAll("_", " ").trim();
  return k ? `${k[0]?.toUpperCase()}${k.slice(1)}` : "Detail";
}

function scalarText(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return plainText(v);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return plainText(JSON.stringify(v, null, 2));
  } catch {
    return "—";
  }
}

/**
 * A monitor's free-form `body` as labelled rows of plain text: strings, numbers and booleans as
 * they are, lists of scalars as lists, anything nested as indented JSON text. A Sentinel-shaped
 * body (`{output: {...}}`) is read from `output`.
 */
export function externalBodyRows(body: Record<string, unknown> | null | undefined): ExternalBodyRow[] {
  if (!body || typeof body !== "object" || Array.isArray(body)) return [];
  const inner = body.output;
  const src = inner && typeof inner === "object" && !Array.isArray(inner) ? (inner as Record<string, unknown>) : body;
  return Object.entries(src)
    .filter(([k]) => k !== "summary" && k !== "severity")
    .slice(0, MAX_ROWS)
    .map(([k, v]) => {
      const row: ExternalBodyRow = { key: k, label: humanize(k), text: null, items: null, flag: null };
      if (typeof v === "boolean") return { ...row, flag: v };
      if (Array.isArray(v) && v.every((x) => x === null || typeof x !== "object")) return { ...row, items: v.slice(0, MAX_ITEMS).map(scalarText) };
      return { ...row, text: scalarText(v) };
    });
}

// ── Monitor list and detail ─────────────────────────────────────────────────

export type WebhookHealth = WebhookDeliveryStatus | "pending" | "disabled" | "none";

/** The worst delivery state across a monitor's webhooks (what the list row shows). */
export function webhookHealth(hooks: readonly Pick<MonitorWebhook, "state" | "last_delivery_status">[]): WebhookHealth {
  if (!hooks.length) return "none";
  const enabled = hooks.filter((h) => h.state === "enabled");
  if (!enabled.length) return "disabled";
  const rank: Record<WebhookHealth, number> = { dead: 5, retrying: 4, disabled: 3, pending: 2, delivered: 1, none: 0 };
  return enabled.map((h): WebhookHealth => h.last_delivery_status ?? "pending").reduce((a, b) => (rank[b] > rank[a] ? b : a), "none");
}

export const WEBHOOK_HEALTH_LABEL: Readonly<Record<WebhookHealth, string>> = { ...DELIVERY_LABEL, pending: "No delivery yet", disabled: "Disabled", none: "No webhooks" };
export const WEBHOOK_HEALTH_TONE: Readonly<Record<WebhookHealth, Tone>> = { ...DELIVERY_TONE, pending: "quiet", disabled: "quiet", none: "quiet" };

/** "All agent groups", or the watched groups by name (ids the caller cannot name stay counted). */
export function watchedLabel(m: Pick<Monitor, "all_groups" | "group_ids">, names: ReadonlyMap<string, string>): string {
  if (m.all_groups) return "All agent groups";
  if (!m.group_ids.length) return "No groups";
  const named = m.group_ids.map((g) => names.get(g)).filter((n): n is string => Boolean(n));
  const unnamed = m.group_ids.length - named.length;
  if (!named.length) return `${m.group_ids.length} ${m.group_ids.length === 1 ? "group" : "groups"}`;
  return unnamed ? `${named.join(", ")} + ${unnamed} more` : named.join(", ");
}

export interface MonitorCounts {
  total: number;
  active: number;
  paused: number;
  revoked: number;
  findings24h: number;
  failingWebhooks: number;
}

export function monitorCounts(rows: readonly Monitor[]): MonitorCounts {
  return rows.reduce<MonitorCounts>(
    (c, m) => ({
      total: c.total + 1,
      active: c.active + (m.state === "active" ? 1 : 0),
      paused: c.paused + (m.state === "paused" ? 1 : 0),
      revoked: c.revoked + (m.state === "revoked" ? 1 : 0),
      findings24h: c.findings24h + (m.findings_24h ?? 0),
      failingWebhooks: c.failingWebhooks + m.webhooks.filter((h) => h.state === "enabled" && (h.last_delivery_status === "retrying" || h.last_delivery_status === "dead")).length,
    }),
    { total: 0, active: 0, paused: 0, revoked: 0, findings24h: 0, failingWebhooks: 0 },
  );
}

export type StateFilter = MonitorState | "all";

/** Revoked monitors are kept for the record but hidden unless asked for. */
export function filterMonitors(rows: readonly Monitor[], state: StateFilter): Monitor[] {
  return rows.filter((m) => (state === "all" ? true : m.state === state)).sort((a, b) => Number(a.state === "revoked") - Number(b.state === "revoked") || Date.parse(b.created_at) - Date.parse(a.created_at));
}

/** `If-Match` for the PATCH: the ETag the GET answered with, else the version (`"<version>"`). */
export function monitorIfMatch(m: Pick<Monitor, "version"> | null | undefined, etag: string | null): string {
  if (etag) return etag;
  return `"${m?.version ?? 1}"`;
}

// ── Register form ───────────────────────────────────────────────────────────

export const MIN_REASON = 10;
const NAME_RE = /^[^\x00-\x1f\x7f]{1,128}$/;

export interface RegisterForm {
  name: string;
  kind: MonitorKind;
  description: string;
  allGroups: boolean;
  groupIds: string[];
  rateLimit: string;
  reason: string;
}

export const EMPTY_REGISTER: RegisterForm = { name: "", kind: "mcp", description: "", allGroups: true, groupIds: [], rateLimit: "60", reason: "" };

export type RegisterErrors = Partial<Record<"name" | "description" | "groups" | "rateLimit" | "reason", string>>;

export function validateRegister(f: RegisterForm): RegisterErrors {
  const e: RegisterErrors = {};
  const name = f.name.trim();
  if (!name) e.name = "Name the monitor.";
  else if (!NAME_RE.test(name)) e.name = "At most 128 characters, no control characters.";
  if (f.description.length > 2000) e.description = "At most 2,000 characters.";
  if (!f.allGroups && f.groupIds.length === 0) e.groups = "Pick at least one agent group, or watch all of them.";
  if (!f.allGroups && f.groupIds.length > 64) e.groups = "At most 64 groups.";
  const rate = Number(f.rateLimit);
  if (!/^\d{1,3}$/.test(f.rateLimit.trim()) || rate < 1 || rate > 600) e.rateLimit = "A whole number of findings per minute, 1 to 600.";
  if (f.reason.trim().length < MIN_REASON) e.reason = `At least ${MIN_REASON} characters; it goes to the audit log.`;
  return e;
}

export function toCreate(f: RegisterForm, keyEnv: ApiKeyEnv): MonitorCreate {
  const description = f.description.trim();
  return {
    name: f.name.trim(),
    kind: f.kind,
    description: description || null,
    all_groups: f.allGroups,
    ...(f.allGroups ? {} : { group_ids: [...new Set(f.groupIds)] }),
    rate_limit_per_min: Number(f.rateLimit.trim()),
    issue_key: true,
    key_env: keyEnv,
    reason: f.reason.trim(),
  };
}

// ── Webhook form ────────────────────────────────────────────────────────────

export interface WebhookForm {
  url: string;
  events: WebhookEventType[];
  reason: string;
}

export const EMPTY_WEBHOOK: WebhookForm = { url: "", events: ["alert.fired", "incident.updated", "action.held"], reason: "" };

export type WebhookErrors = Partial<Record<"url" | "events" | "reason", string>>;

/** The browser-side check; the API re-checks (public address at connect time, egress allowlist). */
export function validateWebhook(f: WebhookForm): WebhookErrors {
  const e: WebhookErrors = {};
  const raw = f.url.trim();
  let url: URL | null = null;
  try {
    url = new URL(raw);
  } catch {
    url = null;
  }
  if (!url || raw.length < 8 || raw.length > 2048) e.url = "A full https:// URL.";
  else if (url.protocol !== "https:") e.url = "Webhooks are https only.";
  else if (url.username || url.password) e.url = "Do not put credentials in the URL; verify the Sibyl-Signature header instead.";
  if (f.events.length === 0) e.events = "Pick at least one event.";
  if (f.reason.trim() && f.reason.trim().length < MIN_REASON) e.reason = `At least ${MIN_REASON} characters, or leave it empty.`;
  return e;
}

export function toWebhookCreate(f: WebhookForm): WebhookCreate {
  const reason = f.reason.trim();
  return { url: f.url.trim(), event_types: EVENT_TYPES.filter((t) => f.events.includes(t)), ...(reason ? { reason } : {}) };
}

/** Revoke is terminal; the reason is required (10+ characters, audited). */
export function revokeReasonError(reason: string): string | null {
  return reason.trim().length < MIN_REASON ? `At least ${MIN_REASON} characters; revoking is permanent and audited.` : null;
}

// ── Outcomes in words ───────────────────────────────────────────────────────

const TEST_ERROR: Readonly<Record<string, string>> = {
  timeout: "The receiver did not answer in time.",
  transport: "Sibyl could not connect to the receiver (DNS, network or TLS failure).",
  egress_refused: "Sibyl's egress policy refused the address (private, loopback or not on the allowlist).",
};

export function webhookTestText(r: Pick<WebhookTestResult, "ok" | "http_status" | "error" | "latency_ms">): string {
  if (r.ok) return `Delivered: the receiver answered HTTP ${r.http_status} in ${r.latency_ms} ms.`;
  if (r.error && TEST_ERROR[r.error]) return TEST_ERROR[r.error] ?? "";
  if (r.http_status > 0) return `The receiver answered HTTP ${r.http_status}; Sibyl counts only 2xx as delivered.`;
  return `The test delivery failed${r.error ? ` (${plainText(r.error, 64)})` : ""}.`;
}

/** Problems from the monitor routes, in words; null keeps the API's own detail. */
export function monitorProblemText(status: number, code: string): string | null {
  if (status === 409 && code === "conflict") return "A monitor with this name already exists. Pick another name, or revoke the old one first.";
  if (status === 409 && code === "invalid_transition") return "A revoked monitor cannot change. Register a new one instead.";
  if (status === 409 && code === "not_active") return "This monitor is revoked, so it cannot get new keys or webhooks.";
  if (status === 412) return "The monitor changed since you opened it. Reload, then apply your change again.";
  if (status === 422 && code === "base_url_not_allowlisted") return "That address is not allowed: it must be public https and, where the deployment sets one, on the webhook allowlist.";
  if (status === 503) return "Webhook delivery is not available on this deployment right now.";
  if (status === 403) return "Your role cannot manage monitors (monitors:admin).";
  return null;
}

// ── Ready-to-paste setup (sibyl-mcp and the Python SDK monitor client) ──────

export const KEY_PLACEHOLDER = "<monitor key>";

export interface SnippetInput {
  apiUrl: string;
  secret: string | null;
}

export type SnippetId = "claude-desktop" | "claude-code" | "python" | "webhook-verify";

export interface Snippet {
  id: SnippetId;
  label: string;
  lang: string;
  code: string;
}

const keyOf = (s: SnippetInput): string => s.secret ?? KEY_PLACEHOLDER;

/** The snippets a newly registered monitor needs, by kind (env names from sibyl-mcp's README). */
export function setupSnippets(kind: MonitorKind, input: SnippetInput): Snippet[] {
  const url = input.apiUrl.replace(/\/+$/, "");
  const key = keyOf(input);
  const desktop: Snippet = {
    id: "claude-desktop",
    label: "Claude Desktop (MCP)",
    lang: "json",
    code: JSON.stringify({ mcpServers: { sibyl: { command: "sibyl-mcp", env: { SIBYL_API_URL: url, SIBYL_MONITOR_KEY: key } } } }, null, 2),
  };
  const code: Snippet = {
    id: "claude-code",
    label: "Claude Code (MCP)",
    lang: "shell",
    code: [`# from a checkout of the Sibyl repo (not published to PyPI)`, `pip install ./packages/sibyl-schemas ./packages/sibyl-sdk ./packages/sibyl-mcp`, `export SIBYL_API_URL=${url}`, `export SIBYL_MONITOR_KEY=${key}`, `claude mcp add sibyl --env SIBYL_API_URL="$SIBYL_API_URL" \\`, `    --env SIBYL_MONITOR_KEY="$SIBYL_MONITOR_KEY" -- sibyl-mcp`].join("\n"),
  };
  const python: Snippet = {
    id: "python",
    label: "Python SDK",
    lang: "python",
    code: [
      `# pip install ./packages/sibyl-schemas ./packages/sibyl-sdk   (from a checkout of the Sibyl repo)`,
      `# export SIBYL_API_URL=${url}`,
      `# export SIBYL_MONITOR_KEY=${key}`,
      `from sibyl.monitor import Client`,
      ``,
      `with Client.from_env() as sibyl:`,
      `    for hold in sibyl.list_held_actions(state="pending")["data"]:`,
      `        sibyl.recommend_on_held_action(hold["id"], "needs_more_info", "New payee; confirm the account.")`,
      `    sibyl.submit_finding(kind="anomaly", subject_kind="fleet", severity="info",`,
      `                         summary="Nightly check: no anomalies.")`,
    ].join("\n"),
  };
  const verify: Snippet = {
    id: "webhook-verify",
    label: "Verify deliveries",
    lang: "python",
    code: [
      `from sibyl.monitor import verify_webhook, WebhookSignatureError`,
      ``,
      `# In your receiver: check Sibyl-Signature over the raw body before trusting anything.`,
      `try:`,
      `    event = verify_webhook(WEBHOOK_SECRET, request.headers, request.body)  # whsec_…`,
      `except WebhookSignatureError:`,
      `    return 401`,
    ].join("\n"),
  };
  if (kind === "mcp") return [desktop, code, python];
  if (kind === "webhook") return [verify, python];
  return [python, code];
}
