/**
 * Handoff packet templates (`sibyl-handoff/1`). `checkpoint` packets come from SDK agents and
 * carry completed and pending steps; `request_only` packets (gateway-only agents) carry the
 * last request and no pending steps, as the schema requires.
 */
import "server-only";
import type { HandoffPacket } from "@/lib/api/documents";
import type { FailureMode } from "@/lib/api/types";
import { hexFor, idFor, iso } from "./core";
import { healthDocAt, spanId, traceId } from "./health";
import type { AgentRt, World } from "./world";

export interface PacketTemplate {
  key: string;
  failure_mode: FailureMode;
  trigger: "rule" | "operator" | "sdk_explicit" | "approval_timeout";
  rule_id?: string;
  goal: string;
  input: string;
  steps: { step: string; tool?: string; output: string; offsetS: number; assumed?: boolean }[];
  pending: { step: string; description: string; inputs?: string[] }[];
  sideEffects?: { kind: "api_call" | "db_write" | "message_sent" | "ticket_created"; target: string; reversible: boolean }[];
  why: string;
  next: string;
  summary: string;
  routeHistory?: { provider: string; model: string; decision: string }[];
}

export const PACKETS: Readonly<Record<string, PacketTemplate>> = {
  "order-intake-loop": {
    key: "order-intake-loop",
    failure_mode: "infinite_loop",
    trigger: "rule",
    rule_id: "tool_loop",
    goal: "Book purchase order PO-55190 from Apex Cements into the TMS and confirm the pickup slot to the shipper",
    input:
      "From: dispatch@apexcements.example\nSubject: PO-55190 — 3 x 32 ft trailers, Chittorgarh → Ahmedabad, pickup 12 Oct 07:00\nPlease book and confirm slot. Consignee contact on the attached PO.",
    steps: [
      { step: "parse_po", output: '{"po":"PO-55190","trailers":3,"lane":"CTG-AMD","pickup":"2026-10-12T07:00+05:30"}', offsetS: -420 },
      { step: "lookup_lane_rate", tool: "tms.lane_rate", output: "Lane CTG-AMD · contract rate INR 41,200 per trailer · fuel 6.5%", offsetS: -400 },
      { step: "check_slot", tool: "tms.slot_search", output: "No 07:00 slot at Chittorgarh yard; nearest 09:30 (2 trailers) and 11:00 (1 trailer)", offsetS: -380 },
      { step: "check_slot", tool: "tms.slot_search", output: "Retried with split pickup; same result", offsetS: -340, assumed: true },
    ],
    pending: [
      { step: "confirm_split_pickup", description: "Agree a split pickup (2 trailers 09:30, 1 at 11:00) with the shipper, or ask the yard for an exception", inputs: ["shipper consent"] },
      { step: "create_booking", description: "Create the TMS booking for the agreed slots", inputs: ["slot choice"] },
      { step: "send_confirmation", description: "Email the booking confirmation to dispatch@apexcements.example" },
    ],
    sideEffects: [{ kind: "api_call", target: "tms.slot_search", reversible: true }],
    why: "The agent called tms.slot_search 37 times in 5 minutes with the same arguments and was stopped by the tool-loop rule before it created a duplicate booking. Nothing was booked.",
    next: "Call Apex dispatch to agree a split pickup (09:30 + 11:00), then create the booking in the TMS and send the confirmation.",
    summary: "PO-55190 for Apex Cements stuck on slot search; no booking made. Agree split pickup and book.",
  },
  "claims-triage-outage": {
    key: "claims-triage-outage",
    failure_mode: "provider_outage",
    trigger: "rule",
    rule_id: "error_rate",
    goal: "Triage damage claim CLM-20931 (wet cement bags, consignment MH-04-7781) and draft the adjuster brief",
    input:
      "Claim CLM-20931 from Shree Infra Projects. 46 of 400 bags arrived wet after monsoon transit Pune → Nashik. Photos (6) and delivery challan attached. Claimed INR 18,860.",
    steps: [
      { step: "classify_claim", output: "Category: transit damage (water ingress). Severity: moderate. Fraud signals: none.", offsetS: -95 },
      { step: "fetch_consignment", tool: "tms.consignment", output: "MH-04-7781 · tarpaulin check passed at origin · 2 h halt at Sinnar due to rain", offsetS: -80 },
      { step: "check_policy", tool: "policy.lookup", output: "Marine-transit cover applies; deductible INR 2,500; carrier liability capped at INR 25,000", offsetS: -60 },
    ],
    pending: [
      { step: "draft_adjuster_brief", description: "Draft the adjuster brief with liability split and the recommended settlement", inputs: ["policy terms", "consignment log"] },
      { step: "notify_customer", description: "Send the acknowledgement and expected timeline to Shree Infra Projects" },
    ],
    why: "Anthropic returned 503 on every call for 3 minutes and the agent's primary model was unavailable. Sibyl moved the agent to OpenAI; this in-flight claim was paused at its last checkpoint and handed to a person so it is not processed twice.",
    next: "Review the consignment log and policy terms in steps 2–3, draft the adjuster brief, and send the acknowledgement to the customer.",
    summary: "Claim CLM-20931 (wet bags, INR 18,860) paused mid-triage during the Anthropic outage. Draft brief and acknowledge.",
    routeHistory: [
      { provider: "anthropic", model: "claude-haiku-4-5", decision: "inline_fallback" },
      { provider: "openai", model: "gpt-5", decision: "failover" },
    ],
  },
  "customer-chat-outage": {
    key: "customer-chat-outage",
    failure_mode: "provider_outage",
    trigger: "rule",
    rule_id: "error_rate",
    goal: "Answer a customer asking where consignment GJ-01-4432 is and when it will arrive",
    input: "Customer (verified by OTP): Where is my order GJ-01-4432? It was supposed to arrive yesterday and the site engineer is waiting.",
    steps: [],
    pending: [],
    why: "The chat request failed against Anthropic during the outage and this agent sends traffic through the gateway only, so Sibyl has the last request but not the agent's state.",
    next: "Look up GJ-01-4432 in the TMS and reply to the customer with the current location and a revised ETA.",
    summary: "Customer waiting on ETA for GJ-01-4432; request failed during outage. Reply with location and ETA.",
  },
};

export function buildPacket(
  w: World,
  rt: AgentRt,
  tpl: PacketTemplate,
  o: { taskId: string; at: number; rtoS: number; transitionId: string | null },
): HandoffPacket {
  const fidelity = rt.spec.sdk ? "checkpoint" : "request_only";
  const hs = healthDocAt(w, rt, o.at);
  const trace = traceId(`${rt.id}:${o.taskId}`);
  const steps = fidelity === "checkpoint" ? tpl.steps : [];
  return {
    schema: "sibyl-handoff/1",
    packet_id: idFor(`packet:${o.taskId}`),
    tenant_id: w.tenantId,
    agent_id: rt.id,
    agent_name: rt.spec.slug,
    task_id: idFor(`agent-task:${o.taskId}`),
    created_at: iso(o.at),
    fidelity,
    goal: tpl.goal,
    original_input: { preview: tpl.input, content_type: "text/plain" },
    completed_steps: steps.map((s, i) => ({
      index: i,
      step: s.step,
      started_at: iso(o.at + s.offsetS * 1000 - 1800),
      ended_at: iso(o.at + s.offsetS * 1000),
      ...(s.tool ? { tool_name: s.tool } : {}),
      span_id: spanId(`${o.taskId}:${i}`),
      output: { preview: s.output },
      assumed: s.assumed ?? false,
    })),
    pending_steps: fidelity === "checkpoint" ? tpl.pending.map((p, i) => ({ index: steps.length + i, step: p.step, description: p.description, ...(p.inputs ? { inputs_needed: p.inputs } : {}) })) : [],
    side_effects: (tpl.sideEffects ?? []).map((s) => ({ kind: s.kind, target: s.target, at: iso(o.at - 60_000), reversible: s.reversible, assumed: false })),
    reason: {
      plain_language: tpl.why,
      failure_mode: tpl.failure_mode,
      trigger: {
        kind: tpl.trigger,
        ...(tpl.rule_id ? { rule_id: tpl.rule_id } : {}),
        health_snapshot_id: hs.health_snapshot_id,
        factors: hs.factors.slice(0, 3),
        span_ids: [spanId(`${o.taskId}:last`)],
      },
    },
    next_action: tpl.next,
    deadline: { at: iso(o.at + o.rtoS * 1000), derived_from: "tier_rto", tier: rt.spec.tier, rto_s: o.rtoS },
    accountability: {
      owner: `${rt.spec.process.toLowerCase().replaceAll(" ", "-")}@${w.slug}`,
      on_call: "operator",
      escalation: "admin",
      business_process: rt.spec.process,
      line: `Owned by ${rt.spec.process} (${w.name}); on call: On-call Operator; escalate to Platform Admin`,
    },
    redaction: {
      capture_mode: "full",
      profile: { id: "secrets_only", version: 1, rules_fired: [], secrets_scrubbed: 0 },
      fields_redacted: [],
    },
    provenance: {
      assembled_by: "control_plane",
      ...(fidelity === "checkpoint" ? { checkpoint_id: idFor(`ckpt:${o.taskId}`), checkpoint_seq: steps.length - 1, checkpoint_age_s: Math.abs(steps.at(-1)?.offsetS ?? 0) } : {}),
      trace_ids: [trace],
      policy_version: w.routingVersion,
      ...(o.transitionId ? { transition_id: o.transitionId } : {}),
      normaliser_version: "normaliser/1.3.0",
      sdk_version: rt.spec.sdk ? "0.1.0" : undefined,
    },
    sidecar: {
      route_history: (tpl.routeHistory ?? []).map((r, i) => ({ at: iso(o.at - (2 - i) * 20_000), to: { provider: r.provider, model: r.model }, decision: r.decision })),
      cost_so_far_usd: Math.round(rt.spec.costPerCall * (steps.length + 2) * 10000) / 10000,
      attempts: steps.length + 2,
      model_calls: steps.length + 1,
      tool_calls: steps.filter((s) => s.tool).length,
    },
    summary: tpl.summary,
  };
}

export const packetHash = (p: HandoffPacket): string => hexFor(`packet-sha:${p.packet_id}`, 64);
