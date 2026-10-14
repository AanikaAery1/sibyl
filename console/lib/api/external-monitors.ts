/**
 * Wave 4 contract types (D53 external monitors and the unified findings feed), aliased from the
 * generated OpenAPI types (`schema.gen.ts`, `npm run gen:api`). Pure types: safe anywhere.
 */
import type { components } from "./schema.gen";

type S = components["schemas"];

// ── External monitors ───────────────────────────────────────────────────────
export type Monitor = S["Monitor"];
export type MonitorKind = Monitor["kind"];
export type MonitorState = Monitor["state"];
export type MonitorKey = Monitor["keys"][number];
export type MonitorWebhook = S["MonitorWebhook"];
export type WebhookEventType = MonitorWebhook["event_types"][number];
export type WebhookDeliveryStatus = NonNullable<MonitorWebhook["last_delivery_status"]>;
export type MonitorCreate = S["MonitorCreate"];
export type MonitorCreated = S["MonitorCreated"];
export type MonitorPatch = S["MonitorPatch"];
export type MonitorRevoke = S["MonitorRevoke"];
export type MonitorKeyCreate = S["MonitorKeyCreate"];
export type WebhookCreate = S["WebhookCreate"];
export type MonitorWebhookCreated = S["MonitorWebhookCreated"];
export type WebhookTestResult = S["WebhookTestResult"];
export type AgentGroup = S["AgentGroup"];

// ── Findings (Sentinel and external monitors) ───────────────────────────────
export type Finding = S["Finding"];
export type FindingSource = Finding["source"];
export type FindingKind = Finding["kind"];
export type FindingSubjectKind = Finding["subject_kind"];
export type FindingSeverity = Finding["severity"];
export type FindingFeedback = NonNullable<Finding["feedback"]>;
