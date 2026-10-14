/**
 * Sibyl Sentinel (D52) display and form logic, pure and unit-tested. Sentinel is advisory: it
 * explains, reviews and recommends on the tenant's own model key, and never allows, blocks,
 * approves, fails over or changes policy. Copy and helpers here keep that line visible.
 */
import type { Tone } from "@/lib/labels";
import type { SentinelConfig, SentinelConfigPut, SentinelConfigTestResult, SentinelFinding, SentinelProvider, SentinelSeverity, SentinelSubjectKind, SentinelTask } from "@/lib/api/monitor";

export const SENTINEL_CONFIG_PATH = "/sentinel/config";
export const findingsPath = (kind: SentinelTask | null): string => `/sentinel/findings?limit=100${kind ? `&kind=${kind}` : ""}`;

export const ADVISORY_COPY = "Sentinel is advisory only. It explains and recommends; it never allows, blocks, approves, fails over or changes a policy. People and deterministic rules decide.";

export const KIND_LABEL: Readonly<Record<SentinelTask, string>> = {
  incident_explanation: "Incident explanation",
  held_action_review: "Held-action review",
  semantic_drift: "Semantic drift review",
  fleet_summary: "Fleet summary",
};

export const TASK_HELP: Readonly<Record<SentinelTask, string>> = {
  incident_explanation: "Explain what failed, the likely cause and what Sibyl already did.",
  held_action_review: "Give the approver a second opinion on a held tool call.",
  semantic_drift: "Read sampled trajectories for purpose drift or injection-like turns.",
  fleet_summary: "A daily summary of the fleet for the on-call lead.",
};

export const ALL_TASKS: readonly SentinelTask[] = ["incident_explanation", "held_action_review", "semantic_drift", "fleet_summary"];

export const PROVIDER_NAME: Readonly<Record<SentinelProvider, string>> = { anthropic: "Anthropic", openai: "OpenAI", gemini: "Gemini" };

export const DEFAULT_MODEL: Readonly<Record<SentinelProvider, string>> = { anthropic: "claude-haiku-4-5", openai: "gpt-5-mini", gemini: "gemini-2.5-flash" };

export const SEVERITY_TONE: Readonly<Record<SentinelSeverity, Tone>> = { info: "neutral", warning: "degraded", critical: "failed" };

export const SUBJECT_LABEL: Readonly<Record<SentinelSubjectKind, string>> = { incident: "Incident", held_action: "Held action", agent: "Agent", fleet: "Fleet" };

export const FEEDBACK_LABEL = { useful: "Useful", not_useful: "Not useful", wrong: "Wrong" } as const;

/** Where a finding's subject lives in the console. */
export function subjectHref(f: Pick<SentinelFinding, "subject_kind" | "subject_id" | "agent_id">): string | null {
  const id = f.subject_id ?? null;
  switch (f.subject_kind) {
    case "incident":
      return id ? `/incidents/${id}` : null;
    case "held_action":
      return id ? `/held-actions/${id}` : null;
    case "agent": {
      const agent = id ?? f.agent_id ?? null;
      return agent ? `/agents/${agent}` : null;
    }
    default:
      return "/fleet";
  }
}

/** USD decimal strings ("0.0123") for display; tiny amounts keep four places. */
export function formatUsd(v: string | number | null | undefined): string {
  if (v === null || v === undefined || v === "") return "—";
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return "—";
  if (n === 0) return "$0.00";
  return n < 1 ? `$${n.toFixed(4)}` : `$${n.toFixed(2)}`;
}

export interface BudgetUsage {
  spent: number;
  budget: number | null;
  /** 0..1 of the daily budget; null without a budget. */
  share: number | null;
  exhausted: boolean;
  calls: number;
  findings: number;
  skipped: number;
}

export function budgetUsage(cfg: Pick<SentinelConfig, "daily_budget_usd" | "usage_today"> | null | undefined): BudgetUsage {
  const u = cfg?.usage_today ?? null;
  const spent = u ? Number(u.spent_usd) || 0 : 0;
  const budget = cfg?.daily_budget_usd ? Number(cfg.daily_budget_usd) : null;
  const share = budget && budget > 0 ? Math.min(1, spent / budget) : null;
  return {
    spent,
    budget,
    share,
    exhausted: Boolean(u?.exhausted) || (budget !== null && budget > 0 && spent >= budget),
    calls: u?.calls ?? 0,
    findings: u?.findings ?? 0,
    skipped: (u?.skipped_budget ?? 0) + (u?.skipped_sampling ?? 0),
  };
}

// ── Setup form ──────────────────────────────────────────────────────────────

export interface SentinelForm {
  enabled: boolean;
  provider: SentinelProvider;
  model: string;
  /** Write-only: blank keeps the vaulted key. Never prefilled. */
  apiKey: string;
  budget: string;
  /** Percent 0..100 in the form; the API takes a 0..1 share. */
  samplingPct: string;
  tasks: SentinelTask[];
  reason: string;
}

export function formFromConfig(cfg: SentinelConfig | null | undefined): SentinelForm {
  const provider = cfg?.provider ?? "anthropic";
  return {
    enabled: cfg?.enabled ?? false,
    provider,
    model: cfg?.model ?? DEFAULT_MODEL[provider],
    apiKey: "",
    budget: cfg?.daily_budget_usd ? String(Number(cfg.daily_budget_usd)) : "5",
    samplingPct: cfg?.sampling_rate !== null && cfg?.sampling_rate !== undefined ? String(Math.round(cfg.sampling_rate * 1000) / 10) : "10",
    tasks: cfg?.configured ? [...cfg.tasks] : [...ALL_TASKS],
    reason: "",
  };
}

export type FormErrors = Partial<Record<"model" | "apiKey" | "budget" | "samplingPct" | "tasks" | "reason", string>>;

const DECIMAL_RE = /^\d{1,6}(\.\d{1,4})?$/;
const MIN_REASON = 10;

export function validateForm(f: SentinelForm, hasKey: boolean): FormErrors {
  const e: FormErrors = {};
  if (!/^[A-Za-z0-9._:/-]{1,128}$/.test(f.model.trim())) e.model = "Name the model (letters, digits, . _ : / -).";
  const key = f.apiKey.trim();
  if (f.enabled && !key && !hasKey) e.apiKey = "An API key is required to enable Sentinel.";
  else if (key && (key.length < 16 || /\s/.test(key))) e.apiKey = "That does not look like a provider API key.";
  if (!DECIMAL_RE.test(f.budget.trim())) e.budget = "A dollar amount, e.g. 5 or 2.50.";
  const pct = Number(f.samplingPct);
  if (f.samplingPct.trim() === "" || !Number.isFinite(pct) || pct < 0 || pct > 100) e.samplingPct = "Between 0 and 100 percent.";
  if (f.enabled && f.tasks.length === 0) e.tasks = "Pick at least one task, or leave Sentinel off.";
  if (f.reason.trim().length < MIN_REASON) e.reason = `At least ${MIN_REASON} characters; it goes to the audit log.`;
  return e;
}

/** The PUT body; the key is sent only when the person typed a new one. */
export function toPut(f: SentinelForm): SentinelConfigPut {
  const key = f.apiKey.trim();
  const budget = Number(f.budget.trim());
  return {
    enabled: f.enabled,
    provider: f.provider,
    model: f.model.trim(),
    ...(key ? { api_key: key } : {}),
    daily_budget_usd: budget.toFixed(2),
    sampling_rate: Math.round(Number(f.samplingPct) * 10) / 1000,
    tasks: ALL_TASKS.filter((t) => f.tasks.includes(t)),
    reason: f.reason.trim(),
  };
}

/**
 * `If-Match` for the PUT: the ETag the GET returned for the version being edited (the API sends
 * `"0"` before the first save, so the first save is no special case). Without one, the version
 * the form was built from, which is the same strong tag (`"<version>"`).
 */
export function ifMatchFor(cfg: Pick<SentinelConfig, "version"> | null | undefined, etag: string | null): string {
  if (etag) return etag;
  return `"${cfg?.version ?? 0}"`;
}

// ── Connection test outcome (POST /sentinel/config/test) ────────────────────

export type SentinelTestError = "http_error" | "transport" | "timeout" | "egress_refused" | "refused" | "bad_output" | "malformed_response" | "config" | "llm_error";

const TEST_ERROR_TEXT: Readonly<Record<SentinelTestError, string>> = {
  http_error: "The provider answered with an error.",
  transport: "Sibyl could not reach the provider (network or TLS failure).",
  timeout: "The provider did not answer in time.",
  egress_refused: "Sibyl's egress allowlist refused the provider's address. Allow it in the egress policy, or remove the custom base URL.",
  refused: "The model declined to answer the connectivity check (a safety stop).",
  bad_output: "The model answered, but not with the expected reply.",
  malformed_response: "The provider's response could not be read.",
  config: "The saved configuration cannot make a call: check the provider, model and base URL.",
  llm_error: "The call failed for an unexpected reason.",
};

function httpText(status: number): string {
  if (status === 401 || status === 403) return `The provider rejected the key (HTTP ${status}). Check that the key is valid and allowed to call this model.`;
  if (status === 404) return "The provider does not know this model or endpoint (HTTP 404). Check the model name.";
  if (status === 408 || status === 504) return `The provider timed out (HTTP ${status}).`;
  if (status === 429) return "The provider is rate limiting this key or its quota is used up (HTTP 429).";
  if (status >= 500) return `The provider had a server error (HTTP ${status}). Try again later.`;
  return `The provider answered HTTP ${status}.`;
}

/** What a failed connection test means, in words (the API's documented `error` codes). */
export function testFailureText(r: Pick<SentinelConfigTestResult, "ok" | "error" | "http_status">): string | null {
  if (r.ok) return null;
  if (r.error === "http_error" || (!r.error && r.http_status >= 400)) return httpText(r.http_status);
  const known = r.error && r.error in TEST_ERROR_TEXT ? TEST_ERROR_TEXT[r.error as SentinelTestError] : null;
  return known ?? `The test failed${r.error ? ` (${r.error})` : ""}.`;
}

/** Problems from the config routes, in words; null keeps the API's own detail. */
export function sentinelProblemText(status: number, code: string): string | null {
  if (status === 409 && code === "not_active") return "Sentinel is not set up yet: save a provider, a model and an API key, then test the connection.";
  if (status === 503) return "The key vault is not configured on this Sibyl deployment, so a provider key cannot be sealed or used. Ask your platform team to set the key-encryption key.";
  if (status === 412) return "The Sentinel configuration changed since you opened it. Reload, then apply your change again.";
  return null;
}

// ── Finding body (the model's validated output; untrusted text) ─────────────

export interface BodyRow {
  key: string;
  label: string;
  text: string | null;
  items: string[] | null;
  flag: boolean | null;
}

const BODY_LABEL: Readonly<Record<string, string>> = {
  what_failed: "What failed",
  likely_cause: "Likely cause",
  what_sibyl_did: "What Sibyl did",
  what_to_check: "What to check",
  advice: "Advice",
  reasoning: "Reasoning",
  risks: "Risks",
  purpose_drift: "Purpose drift",
  injection_like: "Injection-like turns",
  evidence: "Evidence",
  highlights: "Highlights",
  concerns: "Concerns",
  recommendation: "Recommendation",
  confidence: "Confidence",
};

const SKIP = new Set(["summary", "severity"]);

/** Flatten `body.output` into labelled rows, in a stable reading order. */
export function bodyRows(body: Record<string, unknown> | undefined): BodyRow[] {
  const out = (body?.output ?? null) as Record<string, unknown> | null;
  if (!out || typeof out !== "object") return [];
  const order = Object.keys(BODY_LABEL);
  return Object.entries(out)
    .filter(([k]) => !SKIP.has(k))
    .sort(([a], [b]) => (order.indexOf(a) === -1 ? 99 : order.indexOf(a)) - (order.indexOf(b) === -1 ? 99 : order.indexOf(b)))
    .map(([k, v]) => ({
      key: k,
      label: BODY_LABEL[k] ?? k.replaceAll("_", " "),
      text: typeof v === "string" ? v : typeof v === "number" ? String(v) : null,
      items: Array.isArray(v) ? v.map((x) => String(x)) : null,
      flag: typeof v === "boolean" ? v : null,
    }));
}

/** `held_action_review` advice for the badge on held-action detail. */
export function adviceOf(f: Pick<SentinelFinding, "kind" | "body">): "approve" | "deny" | "needs_more_info" | null {
  if (f.kind !== "held_action_review") return null;
  const a = (f.body?.output as Record<string, unknown> | undefined)?.advice;
  return a === "approve" || a === "deny" || a === "needs_more_info" ? a : null;
}

export const ADVICE_LABEL = { approve: "Leans approve", deny: "Leans deny", needs_more_info: "Needs more information" } as const;
