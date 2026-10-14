/**
 * Contract types for the console. Everything here is derived from the generated OpenAPI
 * types (`schema.gen.ts`, regenerate with `npm run gen:api`) or from the frozen JSON Schemas
 * in `packages/sibyl-schemas` that the OpenAPI document leaves opaque (see documents.ts).
 *
 * Pure types only: safe to import from client and server components alike.
 */
import type { components, paths } from "./schema.gen";

type S = components["schemas"];

export type { paths };

export type Uuid = string;
export type Timestamp = string;

export type Agent = S["Agent"];
export type AgentSummary = S["AgentSummary"];
export type AgentKind = S["AgentKind"];
export type Band = S["Band"];
export type Lifecycle = S["Lifecycle"];
export type RiskClass = S["RiskClass"];
export type FailMode = S["FailMode"];
export type RoutingStateName = S["RoutingStateEnum"];
export type RoutingState = S["RoutingState"];
export type RoutingTransition = S["RoutingTransition"];
export type TransitionTrigger = S["TransitionTrigger"];
export type TargetKind = S["TargetKind"];
export type ActorKind = S["ActorKind"];

export type ContinuityPlan = S["ContinuityPlan"];
export type FallbackChain = S["FallbackChain"];
export type FallbackStep = S["FallbackStep"];
export type FallbackKind = S["FallbackKind"];
export type DegradedMode = S["DegradedMode"];
export type PreemptiveMode = S["PreemptiveMode"];

export type Incident = S["Incident"];
export type IncidentActionBody = S["IncidentAction"];
export type IncidentActionName = S["IncidentActionName"];
export type IncidentCreate = S["IncidentCreate"];
export type IncidentCreateAction = S["IncidentCreateAction"];
export type FailoverKind = S["FailoverKind"];
export type FailoverState = S["FailoverState"];
export type FailoverStep = S["FailoverStep"];
export type FailureMode = S["FailureMode"];

export type Approval = S["Approval"];
export type ApprovalAction = S["ApprovalAction"];
export type ApprovalState = S["ApprovalState"];
export type ApprovalTimeoutPolicy = S["ApprovalTimeoutPolicy"];

export type KillSwitch = S["KillSwitch"];
export type KillSwitchCreate = S["KillSwitchCreate"];
export type KillScopeKind = S["KillScopeKind"];

export type HandoffTask = S["HandoffTask"];
export type HandoffTaskSummary = S["HandoffTaskSummary"];
export type HandoffTaskAction = S["HandoffTaskAction"];
export type HandoffState = S["HandoffState"];
export type HandoffOutcome = S["HandoffOutcome"];
export type Fidelity = S["Fidelity"];

export type Alert = S["Alert"];
export type AlertAction = S["AlertAction"];
export type AlertSeverity = S["AlertSeverity"];
export type AlertState = S["AlertState"];
export type Verdict = S["Verdict"];
export type ProviderIncident = S["ProviderIncident"];
export type Provider = S["Provider"];
export type ProviderStatusName = S["ProviderStatusEnum"];

export type FleetHealth = S["FleetHealth"];
export type HealthPoint = S["HealthPoint"];
export type MetricBucket = S["MetricBucket"];
export type RiskDocument = S["RiskDocument"];
export type RecommendedAction = S["RecommendedAction"];
export type ProbabilityBand = S["ProbabilityBand"];
export type Confidence = S["Confidence"];

export type AuditEvent = S["AuditEvent"];
export type AuditAnchor = S["AuditAnchor"];
export type AuditExport = S["AuditExport"];
export type AuditExportCreate = S["AuditExportCreate"];
export type VerificationResult = S["VerificationResult"];

export type ApiKey = S["ApiKey"];
export type ApiKeyCreate = S["ApiKeyCreate"];
export type ApiKeyCreated = S["ApiKeyCreated"];
export type ApiKeyScope = S["ApiKeyScope"];
export type TenantKey = S["TenantKey"];
export type TenantKeyPurpose = S["TenantKeyPurpose"];
export type TenantKeyRotated = S["TenantKeyRotated"];
export type CapturePolicy = S["CapturePolicy"];
export type CapturePolicyCreate = S["CapturePolicyCreate"];
export type CaptureMode = S["CaptureMode"];

export type Tenant = S["Tenant"];
export type AppUser = S["AppUser"];
export type Membership = S["Membership"];
export type RoleName = S["RoleName"];
export type Scope = S["Scope"];
export type Principal = S["Principal"];
export type Problem = S["Problem"];

/** Cursor page envelope (API §2.4). */
export interface Page<T> {
  data: T[];
  next_cursor: string | null;
  has_more: boolean;
}

/** `GET /incidents` and `GET /approvals` etc. all return this envelope. */
export type Paged<T> = Page<T>;
