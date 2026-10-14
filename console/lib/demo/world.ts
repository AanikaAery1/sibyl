/**
 * The in-memory demo world for one tenant: runtime records, the hash-chained audit log and
 * the outbox that feeds the simulated SSE stream. Records are stored in their contract
 * shapes wherever the contract has one; runtime-only fields carry epoch milliseconds.
 */
import "server-only";
import { createHash } from "node:crypto";
import type {
  Alert,
  ApiKey,
  AppUser,
  Approval,
  AuditAnchor,
  AuditEvent,
  AuditExport,
  CapturePolicy,
  ContinuityPlan,
  FailoverKind,
  FailoverState,
  FailoverStep,
  FallbackChain,
  HandoffTask,
  KillSwitch,
  Lifecycle,
  Membership,
  ProviderIncident,
  RoutingStateName,
  RoutingTransition,
  TargetKind,
  TenantKey,
} from "@/lib/api/types";
import type { HandoffPacket, HealthDocument } from "@/lib/api/documents";
import type { ActionPolicyRecord, HeldAction } from "@/lib/api/action-gate";
import type { TenantSlug } from "@/lib/auth/personas";
import type { ProviderStatusLevel } from "@/lib/health/scoring";
import { hexFor, idFor, iso } from "./core";
import type { AgentSpec, ProviderSlug } from "./fixtures";

export interface ServedSegment {
  at: number;
  provider: ProviderSlug | null;
  model: string | null;
}

export type AnomalyKind = "tool_loop" | "latency" | "ratelimit_ramp";

export interface Anomaly {
  kind: AnomalyKind;
  from: number;
  to: number | null;
}

export interface RoutingRt {
  state: RoutingStateName;
  target_kind: TargetKind;
  target_provider: ProviderSlug | null;
  target_model: string | null;
  current_step_id: string | null;
  canary_pct: number;
  operator_hold_until: number | null;
  state_since: number;
  pending_approval_id: string | null;
  last_transition_id: string | null;
}

export interface AgentRt {
  id: string;
  tenant: TenantSlug;
  spec: AgentSpec;
  lifecycle: Lifecycle;
  createdAt: number;
  routing: RoutingRt;
  served: ServedSegment[];
  anomalies: Anomaly[];
  holdSuppressed: number;
  lastBand: string | null;
  discovered: boolean;
}

export type TransitionRec = RoutingTransition & { agent_id: string; health_snapshot?: HealthDocument };

export interface IncidentStepRec {
  step: FailoverStep | "waiting_approval";
  at: number;
  note: string;
}

export interface IncidentRec {
  id: string;
  agent_id: string;
  kind: FailoverKind;
  state: FailoverState;
  step: FailoverStep;
  actor_kind: "human" | "rule" | "policy" | "system" | "api_key";
  requested_by_user_id: string | null;
  trigger_alert_id: string | null;
  rule_codes: string[];
  from_state: RoutingStateName | null;
  to_state: RoutingStateName | null;
  chosen_step: Record<string, unknown> | null;
  approval_id: string | null;
  transition_ids: string[];
  steps: IncidentStepRec[];
  handoff_task_ids: string[];
  created_at: number;
  finished_at: number | null;
  reason: string;
  error: string | null;
  health_snapshot: HealthDocument | null;
}

export interface OutboxEvent {
  id: string;
  event: string;
  data: Record<string, unknown>;
  at: number;
}

export interface World {
  slug: TenantSlug;
  anchorAt: number;
  scriptIndex: number;
  lastStepAt: number;
  tenantId: string;
  name: string;
  region: string;
  routingVersion: number;
  seq: number;
  providerStatus: Record<ProviderSlug, { at: number; status: ProviderStatusLevel }[]>;
  agents: Map<string, AgentRt>;
  plans: Map<string, ContinuityPlan>;
  chains: Map<string, FallbackChain>;
  transitions: TransitionRec[];
  incidents: Map<string, IncidentRec>;
  approvals: Map<string, Approval>;
  alerts: Map<string, Alert & { verdict_wanted?: boolean }>;
  providerIncidents: Map<string, ProviderIncident>;
  tasks: Map<string, HandoffTask>;
  packets: Map<string, HandoffPacket>;
  killSwitches: Map<string, KillSwitch>;
  audit: AuditEvent[];
  anchors: AuditAnchor[];
  exports: Map<string, AuditExport & { requested_at: number; requested_real: number; body: string | null; anchor: AuditAnchor | null }>;
  apiKeys: ApiKey[];
  tenantKeys: TenantKey[];
  capturePolicies: CapturePolicy[];
  users: AppUser[];
  memberships: Membership[];
  outbox: OutboxEvent[];
  idempotency: Map<string, { status: number; body: unknown }>;
  completedDespiteFailure: number;
  counter: number;
  pending: { at: number; kind: "discover"; slug: string }[];
  /** Action Gate: policy versions by row id, held actions by id, cumulative counter hits by `<policy_id>/<rule_id>`. */
  actionPolicies: Map<string, ActionPolicyRecord>;
  heldActions: Map<string, HeldAction>;
  actionCounters: Map<string, { at: number; inc: number }[]>;
}

/** Next deterministic id in this world. */
export function nextId(w: World, kind: string): string {
  w.counter += 1;
  return idFor(`${w.slug}:${kind}:${w.counter}`);
}

// ── Outbox / SSE ──────────────────────────────────────────────────────────

export function emit(w: World, event: string, data: Record<string, unknown>, at: number): void {
  const id = `${iso(at).replace("Z", "000Z")}|${nextId(w, "outbox")}`;
  w.outbox.push({ id, event, data, at });
  if (w.outbox.length > 2000) w.outbox.splice(0, w.outbox.length - 2000);
}

// ── Audit hash chain ──────────────────────────────────────────────────────

/** Canonical JSON with sorted keys (enough for the demo; the product uses RFC 8785). */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
}

export const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");
export const GENESIS_HASH = "0".repeat(64);

export function rowHash(row: Omit<AuditEvent, "hash">): string {
  return sha256(`${row.prev_hash ?? GENESIS_HASH}|${canonical(row)}`);
}

export interface AuditInput {
  action: string;
  actor_type: AuditEvent["actor_type"];
  actor_id?: string | null;
  actor_key_id?: string | null;
  resource_type: string;
  resource_id?: string | null;
  resource_ref?: string | null;
  reason?: string | null;
  detail?: Record<string, unknown>;
  severity?: "info" | "warning" | "critical";
  is_evidence?: boolean;
}

export function appendAudit(w: World, input: AuditInput, at: number): AuditEvent {
  const prev = w.audit[w.audit.length - 1];
  w.seq += 1;
  const base: Omit<AuditEvent, "hash"> = {
    seq: w.seq,
    action: input.action,
    actor_type: input.actor_type,
    actor_id: input.actor_id ?? null,
    actor_key_id: input.actor_key_id ?? null,
    resource_type: input.resource_type,
    resource_id: input.resource_id ?? null,
    resource_ref: input.resource_ref ?? null,
    reason: input.reason ?? null,
    detail: input.detail ?? {},
    occurred_at: iso(at),
    recorded_at: iso(at),
    request_id: idFor(`${w.slug}:req:${w.seq}`),
    is_evidence: input.is_evidence ?? true,
    severity: input.severity ?? "info",
    prev_hash: prev?.hash ?? GENESIS_HASH,
  };
  const row: AuditEvent = { ...base, hash: rowHash(base) };
  w.audit.push(row);
  return row;
}

export function makeAnchor(w: World, kind: AuditAnchor["kind"], at: number): AuditAnchor | null {
  const last = w.anchors[w.anchors.length - 1];
  const from = (last?.seq_to ?? 0) + 1;
  const head = w.audit[w.audit.length - 1];
  if (!head || head.seq < from) return null;
  const id = nextId(w, "anchor");
  const anchor: AuditAnchor = {
    id,
    kind,
    seq_from: from,
    seq_to: head.seq,
    head_hash: head.hash,
    signing_kid: `audit-ed25519-${w.slug}-2026q4`,
    signature: hexFor(`sig:${id}:${head.hash}`, 128),
    anchored_at: iso(at),
    prev_anchor_id: last?.id ?? null,
  };
  w.anchors.push(anchor);
  return anchor;
}

export interface ChainCheck {
  ok: boolean;
  rows: number;
  anchors_checked: number;
  first_break_seq: number | null;
}

/** Recompute every row hash and the prev-hash links, then check anchors cover real heads. */
export function verifyChain(rows: readonly AuditEvent[], anchors: readonly AuditAnchor[]): ChainCheck {
  let prev = GENESIS_HASH;
  for (const row of rows) {
    const { hash, ...rest } = row;
    if (rest.prev_hash !== prev || rowHash(rest) !== hash) {
      return { ok: false, rows: rows.length, anchors_checked: 0, first_break_seq: row.seq };
    }
    prev = hash;
  }
  const bySeq = new Map(rows.map((r) => [r.seq, r.hash]));
  let checked = 0;
  for (const anchor of anchors) {
    const head = bySeq.get(anchor.seq_to);
    if (head === undefined) continue;
    if (head !== anchor.head_hash) return { ok: false, rows: rows.length, anchors_checked: checked, first_break_seq: anchor.seq_to };
    checked += 1;
  }
  return { ok: true, rows: rows.length, anchors_checked: checked, first_break_seq: null };
}

/** Routing state as the contract shows it (RoutingState). */
export function routingVersionBump(w: World): number {
  w.routingVersion += 1;
  return w.routingVersion;
}
