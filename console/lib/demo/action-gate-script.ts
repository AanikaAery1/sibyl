/**
 * Action Gate beats in the meridian scenario (each decided by the seeded policies, not scripted
 * outcomes):
 *   0:20  claims-triage proposes a ₹2,50,000 payout against the ₹1,00,000 limit → blocked
 *   0:26  hr-helpdesk tries to email a candidate's phone and PAN to an outside recruiter → blocked
 *   0:45  claims-triage proposes a ₹75,000 payout acting for the Platform Admin → escalated;
 *         the person it acted for cannot approve it (409 self_approval); the On-call Operator can (step-up)
 *   1:30  returns-agent issues a burst of refunds; the sixth in a minute hits the cap → escalated,
 *         and refund holds need two distinct approvers (four-eyes)
 */
import "server-only";
import type { OnBehalfOf } from "@/lib/api/action-gate";
import { PERSONAS } from "@/lib/auth/personas";
import { agentId } from "./fixtures";
import { gate, type ProposedCall } from "./action-gate";
import type { World } from "./world";

const ADMIN = PERSONAS[0]?.userId ?? null;
const forAdmin = (): OnBehalfOf | null => (ADMIN ? { kind: "user", id: ADMIN } : null);

function call(w: World, slug: string, c: ProposedCall, at: number, onBehalfOf: OnBehalfOf | null = null): void {
  const rt = w.agents.get(agentId(w.slug, slug));
  if (rt) gate(w, rt, c, at, { onBehalfOf });
}

export function overLimitTransfer(w: World, at: number): void {
  call(w, "claims-triage", { tool: "payments.transfer", source: "sdk", call_id: "clm-204655-pay-1", args: { amount: 250000, currency: "INR", payee: "Apex Freight Pvt Ltd", beneficiary_account: "XXXXXXXX4821", ifsc: "HDFC0001234", reference: "CLM-204655", auth_token: "[TOKEN:7c41e0a9]" } }, at);
}

export function exfiltrationAttempt(w: World, at: number): void {
  call(
    w,
    "hr-helpdesk",
    {
      tool: "email.send_external",
      source: "gateway",
      call_id: "hr-77812-mail-1",
      args: { to: "talent@bridgehire.example", subject: "Candidate shortlist", body: "Shortlisted: R. Iyer, mobile +91 98200 12345, PAN ABCDE1234F. Offer band attached." },
    },
    at,
  );
}

export function midSizeTransfer(w: World, at: number): void {
  call(w, "claims-triage", { tool: "payments.transfer", source: "sdk", call_id: "clm-204871-pay-1", args: { amount: 75000, currency: "INR", payee: "Shree Ganesh Transport", beneficiary_account: "XXXXXXXX0937", ifsc: "ICIC0004412", reference: "CLM-204871", auth_token: "[TOKEN:3e9b52d1]" } }, at, forAdmin());
}

export function refundBurst(w: World, at: number): void {
  const customers = ["C-88213", "C-88217", "C-88230", "C-88241", "C-88252", "C-88266"];
  customers.forEach((customer, i) => {
    call(w, "returns-agent", { tool: "refunds.issue", source: "gateway", call_id: `rfd-${customer}`, args: { order_id: `ORD-55${310 + i}`, customer_id: customer, amount: 1200 + i * 350, currency: "INR", reason: "Damaged in transit" } }, at + i * 1500);
  });
}

/** The beats, in scenario order (merged into MERIDIAN_SCRIPT). */
export const ACTION_GATE_BEATS = [
  { at: 20, id: "ag-block", label: "Action Gate blocks a ₹2,50,000 payout (limit ₹1,00,000)", run: overLimitTransfer },
  { at: 26, id: "ag-exfil", label: "Action Gate blocks personal data sent to an outside email", run: exfiltrationAttempt },
  { at: 45, id: "ag-escalate", label: "₹75,000 payout held for a second person (four-eyes)", run: midSizeTransfer },
  { at: 90, id: "ag-refunds", label: "Refund burst hits the 5-a-minute cap; the sixth is held", run: refundBurst },
] as const;
