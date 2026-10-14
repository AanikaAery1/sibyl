/**
 * Display vocabulary (technical-writer §6 glossary): the console, API and docs use the same
 * words. Tones map each state onto the semantic palette.
 */
import type { AlertSeverity, Band, FailoverKind, FailoverState, Fidelity, HandoffState, RoutingStateName } from "@/lib/api/types";

export type Tone = "healthy" | "watch" | "degraded" | "failed" | "moved" | "human" | "returning" | "killed" | "quiet" | "accent" | "neutral" | "advisory";

export const BAND_LABEL: Record<Band, string> = { healthy: "Healthy", watch: "Watch", degraded: "Degraded", failed: "Failed" };

export const ROUTING_LABEL: Record<RoutingStateName, string> = {
  active: "Active",
  degraded: "Degraded mode",
  awaiting_approval: "Awaiting approval",
  failed_over: "Failed over",
  failing_back: "Failing back",
  quarantined: "Quarantined",
  killed: "Killed",
};

export const ROUTING_TONE: Record<RoutingStateName, Tone> = {
  active: "quiet",
  degraded: "degraded",
  awaiting_approval: "human",
  failed_over: "moved",
  failing_back: "returning",
  quarantined: "neutral",
  killed: "killed",
};

export const SEVERITY_TONE: Record<AlertSeverity, Tone> = { info: "neutral", warning: "degraded", critical: "failed" };

export const FIDELITY_LABEL: Record<Fidelity, string> = { checkpoint: "Checkpoint", request_only: "Request-only" };

export const SAGA_LABEL: Record<FailoverState, string> = {
  pending: "Pending",
  running: "Running",
  waiting_approval: "Waiting for approval",
  done: "Done",
  cancelled: "Cancelled",
  failed: "Failed",
};

export const KIND_LABEL: Record<FailoverKind, string> = {
  failover: "Failover",
  preemptive: "Pre-emptive failover",
  failback: "Failback",
  undo: "Undo",
  quarantine: "Quarantine",
  release: "Release",
  kill: "Kill",
  degrade: "Degrade",
  recover: "Recover",
  drill: "Drill",
};

export const STEP_LABEL: Record<string, string> = {
  validate: "Validate",
  check_viability: "Check viability",
  waiting_approval: "Wait for approval",
  write_routing: "Write routing",
  create_handoff_tasks: "Create handoff tasks",
  mark_alert_actioned: "Mark alert actioned",
  done: "Done",
};

export const HANDOFF_LABEL: Record<HandoffState, string> = { queued: "Queued", claimed: "Claimed", completed: "Completed", returned: "Returned", expired: "Expired" };

export const FAILURE_MODE_LABEL: Record<string, string> = {
  provider_outage: "Provider outage",
  latency_degradation: "Latency degradation",
  quality_collapse: "Quality collapse",
  prompt_injection: "Prompt injection",
  policy_violation: "Policy violation",
  tool_failure: "Tool failure",
  data_source_failure: "Data source failure",
  infinite_loop: "Tool loop",
  cost_runaway: "Cost runaway",
  permission_error: "Permission error",
  model_deprecation: "Model deprecation",
  silent_drift: "Silent drift",
};

export const VERDICT_LABEL: Record<string, string> = { tp: "True positive", fp: "False positive", unsure: "Unsure" };

export const PROVIDER_LABEL: Record<string, string> = { openai: "OpenAI", anthropic: "Anthropic", ollama: "Ollama (on-prem)" };

export const APPROVAL_ACTION_LABEL: Record<string, string> = {
  alt_provider_failover: "Fail over to the alternate provider",
  backup_agent_failover: "Fail over to the backup agent",
  preemptive_failover: "Pre-emptive failover",
  quarantine: "Quarantine",
  inline_fallback_enable: "Enable inline fallback",
};

export const label = (map: Record<string, string>, key: string | null | undefined): string => (key ? (map[key] ?? key.replaceAll("_", " ")) : "—");
