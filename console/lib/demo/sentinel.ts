/**
 * Sibyl Sentinel (D52) in demo mode: per-tenant configuration (write-only key, If-Match on the
 * version, step-up on save), connection test, findings with feedback, and on-demand explain.
 * Findings are advisory: nothing here changes routing, holds or policies. Meridian runs Sentinel
 * on Gemini; northstar and sandbox start unconfigured.
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type { SentinelConfig, SentinelConfigPut, SentinelConfigTestResult, SentinelExplain, SentinelFeedback, SentinelFinding, SentinelProvider, SentinelTask } from "@/lib/api/monitor";
import type { HeldAction } from "@/lib/api/action-gate";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { MINUTE, hexFor, idFor, iso } from "./core";
import { requireScope, requireStepUp } from "./actions";
import { agentId } from "./fixtures";
import { monitorState, onSeed, type SentinelConfigRec } from "./monitor-state";
import { appendAudit, emit, type IncidentRec, type World } from "./world";

const HOUR = 60 * MINUTE;
const TASKS: readonly SentinelTask[] = ["incident_explanation", "held_action_review", "semantic_drift", "fleet_summary"];
const PROVIDERS: readonly SentinelProvider[] = ["anthropic", "openai", "gemini"];
/** Demo price per million tokens (in, out) for the cost each finding records. */
const PRICE: Readonly<Record<SentinelProvider, [number, number]>> = { anthropic: [1, 5], openai: [0.25, 2], gemini: [0.3, 2.5] };
/** Model names each demo provider answers for (the connection test's 404 otherwise). */
const MODEL_FAMILY: Readonly<Record<SentinelProvider, RegExp>> = { anthropic: /^claude-/, openai: /^(gpt-|o\d)/, gemini: /^gemini-/ };

onSeed((w, s) => {
  if (w.slug !== "meridian") return;
  s.sentinel = {
    configured: true,
    enabled: true,
    provider: "gemini",
    model: "gemini-2.5-flash",
    base_url: null,
    has_key: true,
    key_hint: "…k3Qz",
    key_updated_at: iso(w.anchorAt - 9 * 24 * HOUR),
    daily_budget_usd: "5.0000",
    sampling_rate: 0.25,
    tasks: [...TASKS],
    price_in_usd_per_mtok: null,
    price_out_usd_per_mtok: null,
    version: 3,
    updated_at: iso(w.anchorAt - 2 * 24 * HOUR),
  };
  const fleet = draft(w, s.sentinel, {
    key: "fleet-summary",
    kind: "fleet_summary",
    subject_kind: "fleet",
    subject_id: null,
    agent_id: null,
    severity: "info",
    at: w.anchorAt - 3 * HOUR,
    output: {
      severity: "info",
      summary: "Overnight the fleet stayed inside its error budgets. Two watch items: the KYC verifier's latency trend and the tool-loop handoff on order intake.",
      highlights: ["20 agents scored; 18 healthy at 06:00", "Both overnight handoffs completed by the on-call operator", "Action Gate blocked 0 calls, held 0 overnight"],
      concerns: ["KYC verifier p95 latency trending up for two days", "Order intake repeated an identical slot search 37 times before the loop rule fired"],
      recommendation: "Review the KYC verifier's continuity plan before the morning peak and check the order-intake slot-search tool for a retry loop.",
    },
    tokensIn: 18400,
    tokensOut: 620,
  });
  s.findings.set(fleet.id, fleet);
  const kyc = [...w.incidents.values()].find((i) => i.agent_id === agentId(w.slug, "kyc-verifier"));
  if (kyc) {
    const f = incidentExplanation(w, s.sentinel, kyc, kyc.created_at + 14 * MINUTE, "scheduled", null);
    s.findings.set(f.id, f);
  }
});

interface Draft {
  key: string;
  kind: SentinelTask;
  subject_kind: SentinelFinding["subject_kind"];
  subject_id: string | null;
  agent_id: string | null;
  severity: SentinelFinding["severity"];
  at: number;
  output: Record<string, unknown>;
  tokensIn: number;
  tokensOut: number;
  trigger?: SentinelFinding["trigger"];
  requestedBy?: string | null;
}

function recommendationOf(kind: SentinelTask, out: Record<string, unknown>): string | null {
  if (kind === "incident_explanation") return ((out.what_to_check as string[] | undefined) ?? []).join("; ") || null;
  if (kind === "held_action_review") return `Advisory: ${String(out.advice)}. ${String(out.reasoning ?? "")}`;
  return typeof out.recommendation === "string" ? out.recommendation : null;
}

function draft(w: World, cfg: SentinelConfigRec, d: Draft): SentinelFinding {
  const provider = (cfg.provider ?? "gemini") as SentinelProvider;
  const [pin, pout] = PRICE[provider];
  const cost = (d.tokensIn * pin + d.tokensOut * pout) / 1_000_000;
  return {
    id: idFor(`sentinel-finding:${w.slug}:${d.key}`),
    kind: d.kind,
    subject_kind: d.subject_kind,
    subject_id: d.subject_id,
    agent_id: d.agent_id,
    severity: d.severity,
    summary: String(d.output.summary ?? ""),
    body: { output: d.output, input: { capture_mode: "full", events: Math.round(d.tokensIn / 220), redacted: false } },
    recommendation: recommendationOf(d.kind, d.output),
    provider,
    model: cfg.model ?? "gemini-2.5-flash",
    prompt_sha256: hexFor(`prompt:${w.slug}:${d.key}`, 64),
    tokens_in: d.tokensIn,
    tokens_out: d.tokensOut,
    cost_usd: cost.toFixed(6),
    cost_estimated: false,
    calls: 1,
    trigger: d.trigger ?? "scheduled",
    requested_by_user_id: d.requestedBy ?? null,
    alert_id: null,
    feedback: null,
    feedback_by_user_id: null,
    feedback_at: null,
    created_at: iso(d.at),
    advisory: true,
  };
}

function incidentExplanation(w: World, cfg: SentinelConfigRec, inc: IncidentRec, at: number, trigger: SentinelFinding["trigger"], by: string | null): SentinelFinding {
  const rt = w.agents.get(inc.agent_id);
  const name = rt?.spec.name ?? "The agent";
  const outage = inc.rule_codes.includes("error_rate");
  const output = outage
    ? {
        severity: "warning",
        summary: `${name} failed over to OpenAI after Anthropic returned 503 on every call; the claim backlog kept moving.`,
        what_failed: "Every Anthropic call from this agent failed with HTTP 503 for about 10 seconds; the error-rate rule crossed its threshold with hysteresis.",
        likely_cause: "A provider-side outage, not the agent: all seven Anthropic agents failed at the same second and the status page reported a major outage.",
        what_sibyl_did: "Collapsed the alerts into one provider incident, moved this agent to the alternate provider in its approved chain and handed the in-flight claim to the operator queue.",
        what_to_check: ["Confirm the in-flight claim in the operator queue resumed from its checkpoint", "Watch the OpenAI rate-limit headroom while the fleet runs on it", "Let the failback canary finish before closing the incident"],
        confidence: "high",
      }
    : {
        severity: "warning",
        summary: `${name} was held in degraded mode after its pre-emptive move timed out waiting for approval.`,
        what_failed: "p95 latency rose for 30 minutes; the leading latency rules predicted degradation within 15 minutes.",
        likely_cause: "Longer document-verification prompts since yesterday's release, not the provider (other OpenAI agents are normal).",
        what_sibyl_did: "Asked for approval (tier-1, four-eyes), then held the agent in degraded mode when nobody approved in 10 minutes, as the PII rule requires.",
        what_to_check: ["Compare prompt sizes before and after yesterday's release", "Decide whether to approve a move to the alternate model", "Check the continuity plan's approval timeout for this tier-1 agent"],
        confidence: "medium",
      };
  return draft(w, cfg, { key: `incident:${inc.id}:${trigger}:${at}`, kind: "incident_explanation", subject_kind: "incident", subject_id: inc.id, agent_id: inc.agent_id, severity: "warning", at, output, tokensIn: 9200, tokensOut: 540, trigger, requestedBy: by });
}

function heldReview(w: World, cfg: SentinelConfigRec, held: HeldAction, at: number, trigger: SentinelFinding["trigger"], by: string | null): SentinelFinding {
  const refund = held.tool === "refunds.issue";
  const output = refund
    ? {
        severity: "info",
        summary: "Sixth refund in a minute for unrelated damaged-in-transit orders; consistent with a backlog being cleared, not abuse.",
        advice: "approve",
        reasoning: "Each refund is under ₹5,000, the orders are distinct and all six cite the same carrier incident logged this morning.",
        risks: ["A burst cap exists to catch scripted abuse; confirm the orders share the carrier incident", "Approving does not raise the cap for the next minute"],
        confidence: "medium",
      }
    : {
        severity: "warning",
        summary: "₹75,000 payout to a transporter for claim CLM-204871; amount matches the surveyor's estimate but the payee account is new.",
        advice: "needs_more_info",
        reasoning: "The amount and reference match the claim, but this beneficiary account was first seen today and the agent acted for the person who must not approve it.",
        risks: ["New beneficiary account (first payout to XXXXXXXX0937)", "Four-eyes: the requester cannot approve", "Payout is irreversible once sent"],
        confidence: "medium",
      };
  return draft(w, cfg, { key: `held:${held.id}:${trigger}:${at}`, kind: "held_action_review", subject_kind: "held_action", subject_id: held.id, agent_id: held.agent_id, severity: output.severity as SentinelFinding["severity"], at, output, tokensIn: 3100, tokensOut: 310, trigger, requestedBy: by });
}

function usageToday(w: World, t: number): NonNullable<SentinelConfig["usage_today"]> {
  const day = iso(t).slice(0, 10);
  const today = [...monitorState(w).findings.values()].filter((f) => f.created_at.slice(0, 10) === day);
  const spent = today.reduce((s, f) => s + Number(f.cost_usd), 0);
  return { day, spent_usd: spent.toFixed(4), calls: today.reduce((s, f) => s + (f.calls ?? 1), 0), findings: today.length, failures: 0, skipped_budget: 0, skipped_sampling: Math.floor((t - w.anchorAt) / (2 * MINUTE)) + 14, exhausted: false };
}

export function sentinelConfigView(w: World, t: number): SentinelConfig {
  return { ...monitorState(w).sentinel, usage_today: monitorState(w).sentinel.configured ? usageToday(w, t) : null, advisory: true };
}

const etagOf = (cfg: SentinelConfigRec): string => `"${cfg.version}"`;

const invalid = (pointer: string, message: string): ProblemError => new ProblemError(422, "validation_failed", "Not saved", message, { errors: [{ pointer, code: "invalid", message }] });

export function putSentinelConfig(w: World, p: BffPrincipal, body: SentinelConfigPut, ifMatch: string | null, t: number): { config: SentinelConfig; etag: string } {
  requireScope(p, "sentinel:admin");
  requireStepUp(p, t);
  const s = monitorState(w);
  const cur = s.sentinel;
  if (!ifMatch) throw new ProblemError(428, "precondition_required", "If-Match required", "Send the configuration version you edited (If-Match), or * for the first save.");
  if (cur.configured ? ifMatch !== etagOf(cur) : ifMatch !== "*" && ifMatch !== etagOf(cur)) {
    throw new ProblemError(412, "precondition_failed", "Changed by someone else", "The Sentinel configuration changed since you opened it. Reload, then apply your change again.");
  }
  if (!PROVIDERS.includes(body?.provider)) throw invalid("/provider", "Choose Anthropic, OpenAI or Gemini.");
  if (typeof body.daily_budget_usd !== "string" || !/^\d{1,6}(\.\d{1,4})?$/.test(body.daily_budget_usd)) throw invalid("/daily_budget_usd", "A decimal dollar amount.");
  if (typeof body.sampling_rate !== "number" || body.sampling_rate < 0 || body.sampling_rate > 1) throw invalid("/sampling_rate", "Between 0 and 1.");
  const tasks = (body.tasks ?? [...TASKS]).filter((x) => TASKS.includes(x));
  const key = typeof body.api_key === "string" ? body.api_key.trim() : "";
  if (body.enabled && !key && !cur.has_key) throw invalid("/api_key", "An API key is required to enable Sentinel.");
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";
  s.sentinel = {
    ...cur,
    configured: true,
    enabled: body.enabled,
    provider: body.provider,
    model: body.model?.trim() || cur.model || null,
    base_url: body.base_url ?? null,
    has_key: cur.has_key || Boolean(key),
    key_hint: key ? `…${key.slice(-4)}` : cur.key_hint,
    key_updated_at: key ? iso(t) : cur.key_updated_at,
    daily_budget_usd: Number(body.daily_budget_usd).toFixed(4),
    sampling_rate: body.sampling_rate,
    tasks,
    version: cur.version + 1,
    updated_at: iso(t),
  };
  // The key itself is never written anywhere but the (simulated) vault: not the audit row, not the view.
  appendAudit(w, { action: "sentinel.config_changed", actor_type: "human", actor_id: p.userId, resource_type: "sentinel_config", resource_id: w.tenantId, reason: reason || null, detail: { enabled: body.enabled, provider: body.provider, model: s.sentinel.model, tasks, daily_budget_usd: body.daily_budget_usd, sampling_rate: String(body.sampling_rate), credential_changed: Boolean(key), base_url: body.base_url ?? null } }, t);
  return { config: sentinelConfigView(w, t), etag: etagOf(s.sentinel) };
}

export function testSentinel(w: World, p: BffPrincipal, t: number): SentinelConfigTestResult {
  requireScope(p, "sentinel:admin");
  const cfg = monitorState(w).sentinel;
  if (!cfg.configured || !cfg.has_key || !cfg.provider) throw new ProblemError(409, "not_active", "Sentinel is not configured", "Save a provider and an API key first.");
  const model = cfg.model ?? "";
  // Demo provider: it knows its own model families; any other name answers 404 like the real API.
  const known = MODEL_FAMILY[cfg.provider].test(model);
  const result: SentinelConfigTestResult = known
    ? { ok: true, provider: cfg.provider, model, latency_ms: 640, http_status: 200, error: null, cost_usd: "0.000041" }
    : { ok: false, provider: cfg.provider, model, latency_ms: 210, http_status: 404, error: "http_error", cost_usd: "0.000000" };
  appendAudit(w, { action: "sentinel.config_tested", actor_type: "human", actor_id: p.userId, resource_type: "sentinel_config", resource_id: w.tenantId, detail: { ok: result.ok, provider: cfg.provider, model, http_status: result.http_status, error: result.error, latency_ms: result.latency_ms, cost_usd: result.cost_usd } }, t);
  return result;
}

export function listFindings(w: World, p: BffPrincipal, q: URLSearchParams): SentinelFinding[] {
  requireScope(p, "sentinel:read");
  const eq = (k: string, v: string | null | undefined): boolean => !q.get(k) || q.get(k) === v;
  const since = q.get("since") ? Date.parse(q.get("since") ?? "") : null;
  return [...monitorState(w).findings.values()]
    .filter((f) => eq("kind", f.kind) && eq("subject_kind", f.subject_kind) && eq("subject_id", f.subject_id) && eq("agent_id", f.agent_id) && eq("severity", f.severity) && eq("trigger", f.trigger) && (since === null || Date.parse(f.created_at) >= since))
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
}

export function getFinding(w: World, p: BffPrincipal, id: string): SentinelFinding {
  requireScope(p, "sentinel:read");
  const f = monitorState(w).findings.get(id);
  if (!f) throw notFound("Finding");
  return f;
}

export function rateFinding(w: World, p: BffPrincipal, id: string, feedback: SentinelFeedback, t: number): SentinelFinding {
  const f = getFinding(w, p, id);
  if (feedback !== "useful" && feedback !== "not_useful" && feedback !== "wrong") throw invalid("/feedback", "useful | not_useful | wrong");
  const next: SentinelFinding = { ...f, feedback, feedback_by_user_id: p.userId, feedback_at: iso(t) };
  monitorState(w).findings.set(id, next);
  appendAudit(w, { action: "sentinel.feedback_recorded", actor_type: "human", actor_id: p.userId, resource_type: "sentinel_finding", resource_id: id, detail: { feedback, kind: f.kind } }, t);
  return next;
}

function requireActive(w: World): SentinelConfigRec {
  const cfg = monitorState(w).sentinel;
  if (!cfg.configured || !cfg.has_key) throw new ProblemError(409, "not_active", "Sentinel is not configured", "An administrator sets Sentinel up first (Settings → Sentinel).");
  if (!cfg.enabled) throw new ProblemError(409, "not_active", "Sentinel is off", "Sentinel is not enabled for this tenant.");
  return cfg;
}

function add(w: World, f: SentinelFinding, t: number): SentinelFinding {
  monitorState(w).findings.set(f.id, f);
  appendAudit(w, { action: "sentinel.finding_created", actor_type: f.trigger === "on_demand" ? "human" : "system", actor_id: f.requested_by_user_id ?? null, resource_type: "sentinel_finding", resource_id: f.id, detail: { kind: f.kind, subject_kind: f.subject_kind, subject_id: f.subject_id, provider: f.provider, model: f.model, prompt_sha256: f.prompt_sha256, tokens_in: f.tokens_in, tokens_out: f.tokens_out, cost_usd: f.cost_usd, advisory: true } }, t);
  emit(w, "sentinel.finding", { finding_id: f.id, kind: f.kind, subject_id: f.subject_id, agent_id: f.agent_id }, t);
  return f;
}

export function explain(w: World, p: BffPrincipal, body: SentinelExplain, t: number): SentinelFinding {
  requireScope(p, "sentinel:admin");
  const cfg = requireActive(w);
  if (body?.subject_kind === "incident") {
    const inc = w.incidents.get(body.subject_id);
    if (!inc) throw notFound("Incident");
    return add(w, incidentExplanation(w, cfg, inc, t, "on_demand", p.userId), t);
  }
  if (body?.subject_kind === "held_action") {
    const held = w.heldActions.get(body.subject_id);
    if (!held) throw notFound("Held action");
    return add(w, heldReview(w, cfg, held, t, "on_demand", p.userId), t);
  }
  throw invalid("/subject_kind", "incident | held_action");
}

// ── scheduled findings (scenario beats) ────────────────────────────────────

const enabledFor = (w: World, task: SentinelTask): SentinelConfigRec | null => {
  const cfg = monitorState(w).sentinel;
  return cfg.configured && cfg.enabled && cfg.tasks.includes(task) ? cfg : null;
};

export function scheduledIncidentExplanation(w: World, slug: string, at: number): void {
  const cfg = enabledFor(w, "incident_explanation");
  const inc = [...w.incidents.values()].filter((i) => i.agent_id === agentId(w.slug, slug)).sort((a, b) => b.created_at - a.created_at)[0];
  if (cfg && inc) add(w, incidentExplanation(w, cfg, inc, at, "scheduled", null), at);
}

export function scheduledHeldReview(w: World, callId: string, at: number): void {
  const cfg = enabledFor(w, "held_action_review");
  const held = [...w.heldActions.values()].find((h) => h.call_id === callId);
  if (cfg && held) add(w, heldReview(w, cfg, held, at, "scheduled", null), at);
}

export function scheduledDriftReview(w: World, slug: string, at: number): void {
  const cfg = enabledFor(w, "semantic_drift");
  const rt = w.agents.get(agentId(w.slug, slug));
  if (!cfg || !rt) return;
  add(
    w,
    draft(w, cfg, {
      key: `drift:${slug}:${at}`,
      kind: "semantic_drift",
      subject_kind: "agent",
      subject_id: rt.id,
      agent_id: rt.id,
      severity: "warning",
      at,
      output: {
        severity: "warning",
        summary: "Route optimizer now calls geo.lookup repeatedly before solving; the purpose is unchanged and nothing looks injected.",
        purpose_drift: false,
        injection_like: false,
        evidence: ["12 of 40 sampled runs call geo.lookup 3+ times in a row (baseline: 1 of 40)", "Stops still come from the dispatcher's list; no instruction-like text in tool results", "Run length grew from 6 to 9 steps on average"],
        recommendation: "Likely a geocoder cache miss after last night's depot address import. Check the geocoder cache before resetting the drift baseline.",
        confidence: "medium",
      },
      tokensIn: 22600,
      tokensOut: 480,
    }),
    at,
  );
}
