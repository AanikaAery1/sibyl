/**
 * Seed fixtures for demo-data mode: three tenants (meridian 20 agents across 3 providers,
 * tiers 3/7/10 with 7 on anthropic; northstar 3 agents on providers unaffected by the
 * scripted outage; sandbox empty), personas, providers and models. Shapes follow the
 * OpenAPI contract; anything the contract leaves open is noted inline.
 */
import "server-only";
import type { AgentKind, FailMode, RiskClass } from "@/lib/api/types";
import type { TenantSlug } from "@/lib/auth/personas";
import type { Tier } from "@/lib/health/scoring";
import { idFor } from "./core";

export type ProviderSlug = "openai" | "anthropic" | "ollama";

export interface ProviderSpec {
  slug: ProviderSlug;
  name: string;
  provider_kind: string;
  dialect: "openai_compatible" | "anthropic";
  base_url: string;
  models: { name: string; cls: "small" | "large" | "reasoning" }[];
}

export const PROVIDERS: readonly ProviderSpec[] = [
  {
    slug: "openai",
    name: "OpenAI",
    provider_kind: "openai",
    dialect: "openai_compatible",
    base_url: "https://api.openai.com/v1",
    models: [
      { name: "gpt-5-mini", cls: "small" },
      { name: "gpt-5", cls: "large" },
    ],
  },
  {
    slug: "anthropic",
    name: "Anthropic",
    provider_kind: "anthropic",
    dialect: "anthropic",
    base_url: "https://api.anthropic.com/v1",
    models: [
      { name: "claude-sonnet-4-5", cls: "large" },
      { name: "claude-haiku-4-5", cls: "small" },
    ],
  },
  {
    slug: "ollama",
    name: "Ollama (on-prem)",
    provider_kind: "ollama",
    dialect: "openai_compatible",
    base_url: "https://llm.internal.meridian.example/v1",
    models: [
      { name: "llama-3.3-70b", cls: "large" },
      { name: "qwen3-32b", cls: "large" },
    ],
  },
];

export interface AgentSpec {
  slug: string;
  name: string;
  kind: AgentKind;
  tier: Tier;
  risk_class: RiskClass;
  provider: ProviderSlug;
  model: string;
  modelClass: "small" | "large" | "reasoning";
  framework: string | null;
  process: string;
  owner: string;
  pii: boolean;
  sdk: boolean;
  fail_mode: FailMode;
  rpm: number;
  baseErr: number;
  baseP95: number;
  costPerCall: number;
  description: string;
  /** Baseline rate-limit headroom (share of quota left); busy agents sit closer to the edge. */
  headroom?: number;
  /** Baseline p95 trend ratio vs the 1-hour baseline. */
  trend?: number;
}

const a = (s: Omit<AgentSpec, "fail_mode" | "framework"> & Partial<Pick<AgentSpec, "fail_mode" | "framework">>): AgentSpec => ({
  fail_mode: "open",
  framework: "langgraph",
  ...s,
});

export const MERIDIAN_AGENTS: readonly AgentSpec[] = [
  // anthropic (7) — the scripted outage hits these
  a({ slug: "claims-triage", name: "Claims triage", kind: "autonomous_agent", tier: 1, risk_class: "high", provider: "anthropic", model: "claude-sonnet-4-5", modelClass: "large", process: "Claims handling", owner: "admin", pii: true, sdk: true, fail_mode: "closed", rpm: 42, baseErr: 0.006, baseP95: 6200, costPerCall: 0.0124, description: "Classifies inbound damage claims, pulls the consignment record and drafts the adjuster brief." }),
  a({ slug: "invoice-reconciler", name: "Invoice reconciler", kind: "workflow", tier: 2, risk_class: "limited", provider: "anthropic", model: "claude-sonnet-4-5", modelClass: "large", process: "Finance close", owner: "admin", pii: false, sdk: true, rpm: 18, baseErr: 0.008, baseP95: 7400, costPerCall: 0.0098, description: "Matches carrier invoices to delivery proofs and flags variances above 2%." }),
  a({ slug: "dispatch-planner", trend: 1.6, name: "Dispatch planner", kind: "autonomous_agent", tier: 2, risk_class: "limited", provider: "anthropic", model: "claude-sonnet-4-5", modelClass: "large", process: "Order fulfilment", owner: "admin", pii: false, sdk: true, rpm: 26, baseErr: 0.005, baseP95: 8100, costPerCall: 0.0141, description: "Builds next-day truck allocations across the western depots." }),
  a({ slug: "customer-chat", headroom: 0.085, name: "Customer chat", kind: "chatbot", tier: 2, risk_class: "limited", provider: "anthropic", model: "claude-haiku-4-5", modelClass: "small", process: "Customer support", owner: "admin", pii: true, sdk: false, framework: null, rpm: 64, baseErr: 0.004, baseP95: 2100, costPerCall: 0.0021, description: "Answers shipment-status and delivery-window questions on the web portal." }),
  a({ slug: "contract-reviewer", name: "Contract reviewer", kind: "rag_pipeline", tier: 3, risk_class: "limited", provider: "anthropic", model: "claude-sonnet-4-5", modelClass: "large", process: "Compliance", owner: "admin", pii: false, sdk: true, rpm: 6, baseErr: 0.01, baseP95: 11800, costPerCall: 0.031, description: "Highlights non-standard liability clauses in carrier contracts." }),
  a({ slug: "kb-search", headroom: 0.088, name: "Knowledge search", kind: "rag_pipeline", tier: 3, risk_class: "minimal", provider: "anthropic", model: "claude-haiku-4-5", modelClass: "small", process: "Customer support", owner: "admin", pii: false, sdk: false, framework: null, rpm: 38, baseErr: 0.006, baseP95: 1700, costPerCall: 0.0012, description: "Retrieval over SOPs and depot runbooks for support staff." }),
  a({ slug: "email-summarizer", name: "Email summarizer", kind: "copilot", tier: 3, risk_class: "minimal", provider: "anthropic", model: "claude-haiku-4-5", modelClass: "small", process: "Customer support", owner: "admin", pii: true, sdk: false, framework: null, rpm: 22, baseErr: 0.007, baseP95: 2400, costPerCall: 0.0009, description: "Summarises long customer threads for the support inbox." }),
  // openai (8)
  a({ slug: "quote-assistant", name: "Quote assistant", kind: "autonomous_agent", tier: 1, risk_class: "limited", provider: "openai", model: "gpt-5-mini", modelClass: "small", process: "Quote-to-cash", owner: "admin", pii: false, sdk: true, rpm: 55, baseErr: 0.004, baseP95: 2600, costPerCall: 0.0031, description: "Prices freight quotes from RFQs and drafts the customer email." }),
  a({ slug: "kyc-verifier", name: "KYC verifier", kind: "autonomous_agent", tier: 1, risk_class: "high", provider: "openai", model: "gpt-5", modelClass: "large", process: "Compliance", owner: "admin", pii: true, sdk: true, fail_mode: "closed", rpm: 12, baseErr: 0.005, baseP95: 9800, costPerCall: 0.0187, description: "Verifies new-shipper identity documents against the sanctions list." }),
  a({ slug: "order-intake", name: "Order intake", kind: "autonomous_agent", tier: 2, risk_class: "limited", provider: "openai", model: "gpt-5-mini", modelClass: "small", process: "Order fulfilment", owner: "admin", pii: false, sdk: true, rpm: 31, baseErr: 0.006, baseP95: 2300, costPerCall: 0.0027, description: "Turns emailed purchase orders into bookings in the TMS." }),
  a({ slug: "freight-pricer", headroom: 0.09, name: "Freight pricer", kind: "workflow", tier: 2, risk_class: "minimal", provider: "openai", model: "gpt-5-mini", modelClass: "small", process: "Quote-to-cash", owner: "admin", pii: false, sdk: true, rpm: 47, baseErr: 0.003, baseP95: 1900, costPerCall: 0.0016, description: "Applies lane rates and fuel surcharge to quote drafts." }),
  a({ slug: "returns-agent", name: "Returns agent", kind: "chatbot", tier: 3, risk_class: "minimal", provider: "openai", model: "gpt-5-mini", modelClass: "small", process: "Customer support", owner: "admin", pii: true, sdk: false, framework: null, rpm: 14, baseErr: 0.005, baseP95: 2000, costPerCall: 0.0013, description: "Books reverse pickups for damaged or refused consignments." }),
  a({ slug: "sales-copilot", headroom: 0.096, name: "Sales copilot", kind: "copilot", tier: 3, risk_class: "minimal", provider: "openai", model: "gpt-5", modelClass: "large", process: "Quote-to-cash", owner: "admin", pii: false, sdk: false, framework: null, rpm: 9, baseErr: 0.004, baseP95: 8800, costPerCall: 0.0112, description: "Prepares account briefs for key-account managers." }),
  a({ slug: "ticket-router", headroom: 0.094, name: "Ticket router", kind: "workflow", tier: 3, risk_class: "minimal", provider: "openai", model: "gpt-5-mini", modelClass: "small", process: "Customer support", owner: "admin", pii: false, sdk: true, rpm: 28, baseErr: 0.004, baseP95: 1500, costPerCall: 0.0006, description: "Routes support tickets to the right depot queue." }),
  a({ slug: "report-writer", trend: 1.62, name: "Report writer", kind: "workflow", tier: 3, risk_class: "minimal", provider: "openai", model: "gpt-5", modelClass: "large", process: "Finance close", owner: "admin", pii: false, sdk: true, rpm: 3, baseErr: 0.006, baseP95: 14200, costPerCall: 0.044, description: "Writes the weekly on-time-delivery report for regional heads." }),
  // ollama on-prem (5)
  a({ slug: "doc-extractor", name: "Document extractor", kind: "workflow", tier: 2, risk_class: "limited", provider: "ollama", model: "qwen3-32b", modelClass: "large", process: "Order fulfilment", owner: "admin", pii: true, sdk: true, rpm: 20, baseErr: 0.009, baseP95: 6900, costPerCall: 0.0004, description: "Extracts fields from e-way bills and delivery challans." }),
  a({ slug: "route-optimizer", trend: 1.68, name: "Route optimizer", kind: "autonomous_agent", tier: 2, risk_class: "minimal", provider: "ollama", model: "llama-3.3-70b", modelClass: "large", process: "Order fulfilment", owner: "admin", pii: false, sdk: true, rpm: 11, baseErr: 0.007, baseP95: 9400, costPerCall: 0.0006, description: "Re-sequences multi-drop routes when a stop slips." }),
  a({ slug: "translation-svc", headroom: 0.072, name: "Translation service", kind: "model_endpoint", tier: 3, risk_class: "minimal", provider: "ollama", model: "qwen3-32b", modelClass: "large", process: "Customer support", owner: "admin", pii: false, sdk: false, framework: null, rpm: 33, baseErr: 0.005, baseP95: 3900, costPerCall: 0.0002, description: "Hindi, Marathi and Gujarati translation for driver messages." }),
  a({ slug: "log-analyzer", name: "Log analyzer", kind: "copilot", tier: 3, risk_class: "minimal", provider: "ollama", model: "llama-3.3-70b", modelClass: "large", process: "Compliance", owner: "admin", pii: false, sdk: true, rpm: 4, baseErr: 0.008, baseP95: 10400, costPerCall: 0.0005, description: "Summarises telematics anomalies for the fleet safety team." }),
  a({ slug: "hr-helpdesk", name: "HR helpdesk", kind: "chatbot", tier: 3, risk_class: "limited", provider: "ollama", model: "qwen3-32b", modelClass: "large", process: "People ops", owner: "admin", pii: true, sdk: false, framework: null, rpm: 7, baseErr: 0.006, baseP95: 4300, costPerCall: 0.0003, description: "Answers leave and payroll questions for depot staff." }),
];

export const NORTHSTAR_AGENTS: readonly AgentSpec[] = [
  a({ slug: "triage-assist", name: "Triage assist", kind: "copilot", tier: 1, risk_class: "high", provider: "openai", model: "gpt-5", modelClass: "large", process: "Patient intake", owner: "admin", pii: true, sdk: true, fail_mode: "closed", rpm: 16, baseErr: 0.003, baseP95: 7200, costPerCall: 0.0151, description: "Suggests triage priority from intake notes for the nurse on duty." }),
  a({ slug: "appointment-bot", headroom: 0.093, name: "Appointment bot", kind: "chatbot", tier: 2, risk_class: "limited", provider: "openai", model: "gpt-5-mini", modelClass: "small", process: "Scheduling", owner: "admin", pii: true, sdk: false, framework: null, rpm: 29, baseErr: 0.003, baseP95: 1800, costPerCall: 0.0011, description: "Books and moves outpatient appointments over chat." }),
  a({ slug: "claims-coder", name: "Claims coder", kind: "workflow", tier: 3, risk_class: "limited", provider: "ollama", model: "llama-3.3-70b", modelClass: "large", process: "Revenue cycle", owner: "admin", pii: true, sdk: true, rpm: 8, baseErr: 0.004, baseP95: 8300, costPerCall: 0.0004, description: "Suggests ICD-10 codes for insurance claims." }),
];

export const TENANT_AGENTS: Readonly<Record<TenantSlug, readonly AgentSpec[]>> = {
  meridian: MERIDIAN_AGENTS,
  northstar: NORTHSTAR_AGENTS,
  sandbox: [],
};

export const TENANT_META: Readonly<Record<TenantSlug, { name: string; region: string }>> = {
  meridian: { name: "Meridian Logistics", region: "ap-south-1" },
  northstar: { name: "Northstar Health", region: "eu-west-1" },
  sandbox: { name: "Sandbox", region: "ap-south-1" },
};

export const tenantId = (slug: TenantSlug): string => idFor(`tenant:${slug}`);
export const agentId = (tenant: TenantSlug, slug: string): string => idFor(`agent:${tenant}:${slug}`);
export const providerId = (tenant: TenantSlug, slug: string): string => idFor(`provider:${tenant}:${slug}`);
export const modelId = (tenant: TenantSlug, provider: string, model: string): string =>
  idFor(`model:${tenant}:${provider}:${model}`);

/** Alternate provider per primary (the alt_provider chain step). */
export const ALT_PROVIDER: Readonly<Record<ProviderSlug, { provider: ProviderSlug; model: string }>> = {
  anthropic: { provider: "openai", model: "gpt-5" },
  openai: { provider: "ollama", model: "llama-3.3-70b" },
  ollama: { provider: "openai", model: "gpt-5-mini" },
};

export const ALT_MODEL: Readonly<Record<string, string>> = {
  "claude-sonnet-4-5": "claude-haiku-4-5",
  "claude-haiku-4-5": "claude-sonnet-4-5",
  "gpt-5-mini": "gpt-5",
  "gpt-5": "gpt-5-mini",
  "llama-3.3-70b": "qwen3-32b",
  "qwen3-32b": "llama-3.3-70b",
};

/** Default RTO by tier when the plan is silent (D23): 15 min / 1 h / 4 h. */
export const RTO_BY_TIER: Readonly<Record<Tier, number>> = { 1: 900, 2: 3600, 3: 14400 };
