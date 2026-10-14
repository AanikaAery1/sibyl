/** Starting document for a new policy in the editor (pure). */
import type { PolicyDocumentBody } from "@/lib/api/action-gate";

export const CLAIMS_TEMPLATE: PolicyDocumentBody = {
  schema: "sibyl-action-policy/1",
  default_effect: "allow",
  tool_allowlist_enforced: false,
  tool_allowlist: null,
  sensitive_tools: ["payments.transfer"],
  external_tools: [],
  hold_timeout_s: 900,
  rules: [
    { rule_id: "transfer-limit", tool: "payments.transfer", when: { gt: ["/amount", 100000] }, effect: "block", reason: "Above the ₹1,00,000 single-transfer limit" },
    { rule_id: "transfer-review", tool: "payments.transfer", when: { gt: ["/amount", 50000] }, effect: "escalate", reason: "Transfers above ₹50,000 need a second person" },
  ],
};
