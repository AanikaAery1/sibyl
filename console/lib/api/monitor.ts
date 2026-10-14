/**
 * Wave 3 contract types (drift D51, Sentinel D52, run tree and discovery D50), all aliased from
 * the generated OpenAPI types (`schema.gen.ts`, `npm run gen:api`). Pure types: safe anywhere.
 */
import type { components } from "./schema.gen";
import type { Page } from "./types";

type S = components["schemas"];

// ── Drift ───────────────────────────────────────────────────────────────────
export type DriftBaseline = S["DriftBaseline"];
export type DriftBaselineState = DriftBaseline["state"];
export type DriftBaselineReset = S["DriftBaselineReset"];
export type DriftBaselineResetResult = S["DriftBaselineResetResult"];
export type DriftFeatureResult = S["DriftFeatureResult"];
export type DriftFeature = DriftFeatureResult["feature"];
export type DriftStatistic = DriftFeatureResult["statistic"];
export type DriftVerdict = DriftFeatureResult["verdict"];
export type DriftContributor = S["DriftContributor"];
export type DriftIdentityFinding = S["DriftIdentityFinding"];
export type DriftIdentityKind = DriftIdentityFinding["kind"];
export type DriftKeySummary = S["DriftKeySummary"];
export type DriftReport = S["DriftReport"];
export type DriftReportSummary = S["DriftReportSummary"];
export type DriftAlertRef = S["DriftAlertRef"];
export type AgentDrift = S["AgentDrift"];
export type FleetDriftSummary = S["FleetDriftSummary"];
/** `GET /drift`: a page of current baselines plus a fleet summary. */
export type DriftPage = Page<DriftKeySummary> & { summary?: FleetDriftSummary };

// ── Sentinel ────────────────────────────────────────────────────────────────
export type SentinelConfig = S["SentinelConfig"];
export type SentinelConfigPut = S["SentinelConfigPut"];
export type SentinelConfigTestResult = S["SentinelConfigTestResult"];
export type SentinelFinding = S["SentinelFinding"];
export type SentinelFeedbackBody = S["SentinelFeedback"];
export type SentinelFeedback = SentinelFeedbackBody["feedback"];
export type SentinelExplain = S["SentinelExplain"];
export type SentinelProvider = SentinelConfigPut["provider"];
export type SentinelTask = SentinelFinding["kind"];
export type SentinelSubjectKind = SentinelFinding["subject_kind"];
export type SentinelSeverity = SentinelFinding["severity"];
export type SentinelUsage = NonNullable<SentinelConfig["usage_today"]>;

// ── Telemetry (run tree) ────────────────────────────────────────────────────
export type TelemetryEvent = S["Event"];
export type TelemetryEventType = S["EventType"];
export type Trace = S["Trace"];

// ── Runs (D50 run tree: GET /runs, GET /runs/{run_id}) ───────────────────────
export type RunStatus = S["RunStatus"];
export type RunSummary = S["RunSummary"];
export type RunDetail = S["RunDetail"];
export type RunNode = S["RunNode"];
export type RunStep = S["RunStep"];
export type RunHandoff = S["RunHandoff"];
export type RunModelCall = S["RunModelCall"];
export type RunToolCall = S["RunToolCall"];
export type ToolActionEffect = S["ToolActionEffect"];
/** How ingest first saw an agent (null for an agent registered through the API). */
export type DiscoveredVia = NonNullable<S["AgentSummary"]["discovered_via"]>;
