/**
 * TypeScript mirrors of the frozen JSON Schemas the OpenAPI document references as opaque
 * objects: `sibyl-health/1` (GET /agents/{id}/health) and `sibyl-handoff/1`
 * (GET /handoff-tasks/{id}/packet). Source of truth:
 * packages/sibyl-schemas/src/sibyl_schemas/jsonschema/sibyl-{health,handoff}-1.json
 */
import type { Band, CaptureMode, FailureMode, Fidelity, RecommendedAction, RoutingStateName } from "./types";

export type FactorDirection = "above" | "below" | "equals" | "rising" | "falling";
export type RuleKind = "detected" | "leading";

export interface HealthFactor {
  rule: string;
  weight: number;
  penalty?: number;
  value: number | string | boolean;
  threshold: number | string | boolean;
  direction: FactorDirection;
  explanation: string;
  evidence?: string;
  kind?: RuleKind;
  horizon_s?: number;
}

export interface HealthPrediction {
  probability_band: "0.05" | "0.25" | "0.60" | "0.90";
  probability?: number;
  predicted_failure_mode?: FailureMode | null;
  source: string;
  confidence: "low" | "medium" | "high";
  contributing_rules?: string[];
  abstained?: boolean;
}

export interface HealthDocument {
  schema: "sibyl-health/1";
  health_snapshot_id: string;
  tenant_id: string;
  agent_id: string;
  computed_at: string;
  window: { start: string; end: string; grain_s: 60 | 300 | 900 | 3600 };
  score: number;
  status: Band;
  provisional: { flag: boolean; events_seen: number; events_needed: number; observation_coverage?: number };
  factors: HealthFactor[];
  horizons: { "15m": HealthPrediction; "1h": HealthPrediction; "24h": HealthPrediction };
  predicted_failure_mode: FailureMode | null;
  recommended_action?: RecommendedAction | null;
  /** Null when the worker stored no feature snapshot for this evaluation (live). */
  feature_snapshot_ref: string | null;
  policy_version: number;
  routing_state?: RoutingStateName;
}

export interface PayloadRef {
  ref: string;
  sha256: string;
  bytes: number;
  content_type?: string;
  parts?: string[];
}

export interface OutputRef {
  preview?: string;
  ref?: PayloadRef;
  content_type?: string;
}

export interface CompletedStep {
  index: number;
  step: string;
  started_at: string;
  ended_at: string;
  tool_name?: string;
  call_id?: string;
  span_id?: string;
  output?: OutputRef;
  assumed: boolean;
}

export interface PendingStep {
  index: number;
  step: string;
  description?: string;
  inputs_needed?: string[];
  blocked_on?: string;
}

export type SideEffectKind =
  | "external_write"
  | "message_sent"
  | "payment"
  | "file_written"
  | "db_write"
  | "ticket_created"
  | "api_call"
  | "unknown";

export interface SideEffect {
  kind: SideEffectKind;
  target?: string;
  at: string;
  idempotency_key?: string;
  reversible?: boolean;
  assumed: boolean;
  evidence_span_id?: string;
}

export type HandoffTriggerKind = "sdk_explicit" | "rule" | "a2a_state" | "operator" | "approval_timeout";

export interface HandoffPacket {
  schema: "sibyl-handoff/1";
  packet_id: string;
  tenant_id: string;
  agent_id: string;
  agent_name?: string;
  task_id: string;
  created_at: string;
  fidelity: Fidelity;
  goal: string;
  original_input: OutputRef;
  completed_steps: CompletedStep[];
  pending_steps: PendingStep[];
  side_effects?: SideEffect[];
  reason: {
    plain_language: string;
    failure_mode: FailureMode;
    trigger: {
      kind: HandoffTriggerKind;
      rule_id?: string;
      alert_id?: string;
      health_snapshot_id?: string;
      factors?: HealthFactor[];
      span_ids?: string[];
      call_ids?: string[];
    };
  };
  next_action: string;
  deadline: { at: string; derived_from: "task_deadline" | "tier_rto" | "operator"; tier?: number; rto_s?: number };
  accountability: { owner: string; on_call?: string; escalation?: string; business_process?: string; line: string };
  redaction: {
    capture_mode: CaptureMode;
    profile: { id: string; version: number; rules_fired: string[]; secrets_scrubbed: number };
    fields_redacted?: string[];
  };
  provenance: {
    assembled_by: "sdk" | "control_plane";
    sdk_version?: string;
    checkpoint_id?: string;
    checkpoint_seq?: number;
    checkpoint_age_s?: number;
    trace_ids: string[];
    policy_version: number;
    transition_id?: string;
    normaliser_version?: string;
  };
  sidecar?: {
    route_history?: { at: string; to: { provider: string; model: string }; decision?: string }[];
    cost_so_far_usd?: number;
    attempts?: number;
    model_calls?: number;
    tool_calls?: number;
  };
  summary?: string;
}
