# Action Gate — build spec (chair, 2026-10-11)

Thesis and rationale: `docs/strategy/TECHNICAL-THESIS.md` §5, product: `docs/product/PRODUCT.md` §12. Decision D48.

**Purpose.** Evaluate an agent's proposed action **before it executes**. The outcome is `allow`, `block` or `escalate`. The decision is enforced from signed policy at two independent points and audited.

## 1. Policy model (`sibyl_schemas`, signed into the policy snapshot)
An **action policy** belongs to a tenant and applies to an agent (or an agent group, or tenant-wide). It holds an ordered list of **rules**. Each rule has these fields:
- `tool`: the exact tool name or a glob, e.g. `payments.transfer`, `email.*`.
- `when`: argument predicates in a small, safe expression language. **No eval.** It is a JSON AST.
  - Comparisons: `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `in`, `not_in`, `matches` (anchored regex with a length cap), `exists`.
  - Combinators: `all`, `any`, `not`.
  - JSON-pointer paths into the arguments, e.g. `{"le": ["/amount", 10000]}`, `{"in": ["/currency", ["INR", "USD"]]}`.
- `cumulative` (optional): a cap over a window, e.g. `{"sum": "/amount", "max": 50000, "window_s": 86400}` or `{"count": true, "max": 20, "window_s": 60}`. It is keyed per agent (optionally per argument value, e.g. per `/customer_id`).
- `data_class` (optional): block when an argument scrubs as a secret, or matches PII detectors, and the tool is marked external.
- `effect`: `allow` | `block` | `escalate`.
- `reason`: shown to people and recorded in the audit.

**Evaluation.**
- The first matching rule wins.
- A policy has a `default_effect` used when no rule matches: `allow` or `escalate`. A new policy defaults to `escalate` for tools listed as `sensitive`.
- A tool **absent** from an agent's declared tool allowlist is `block` when `tool_allowlist_enforced` is set.
- Decisions are deterministic, and the evaluator is a pure function shared by every enforcement point: `sibyl_schemas.action_gate.evaluate(policy, tool, args, counters) -> Decision{effect, rule_id, reason, matched_paths}`. It has property tests.
- Exceeding a cumulative cap gives `escalate` by default (configurable to `block`).

## 2. Enforcement points
1. **SDK** (`@sibyl.tool` and `sibyl.instrument()` tool execution).
   - Evaluate before the function runs.
   - `block` raises `SibylActionBlocked(rule, reason)`, and the function never runs.
   - `escalate` calls `POST /api/v1/held-actions`, then either waits for a decision (bounded by the policy `hold_timeout_s`; the default deny on timeout raises `SibylActionDenied`) or, when `mode="async"`, raises `SibylActionHeld(held_action_id)`.
   - It fails **closed** for tools marked sensitive when no fresh snapshot is held.
2. **Gateway** (OpenAI-compatible responses that contain `tool_calls`).
   - Evaluate each proposed call before returning the response to the agent.
   - `block` replaces that tool call with an assistant message explaining the refusal, sets `finish_reason: "stop"` and adds the header `X-Sibyl-Action: blocked`.
   - `escalate` creates a held action and returns the same refusal shape with `X-Sibyl-Action: held` and `X-Sibyl-Held-Action-Id`.
   - Streaming: buffer `tool_calls` deltas only; text deltas still stream. The decision is applied before the final tool-call chunk is released.
3. **Counters** for cumulative caps live in the control plane (`action_counter`). Enforcement points read the counters through the snapshot, and the authoritative check-and-increment is `POST /api/v1/action-decisions`. In Phase 1 the gateway and SDK call it only for rules that have `cumulative`.

## 3. Control plane
- **Tables** (migration 0017):
  - `action_policy` (versioned, with an approval state; tier-1 agents need four-eyes approval of the policy)
  - `action_rule`
  - `held_action`, with state machine `pending → approved | denied | expired | cancelled`, the args digest plus scrubbed args stored as a payload ref, the decision, the deciders and timestamps
  - `action_counter`
  - `action_decision_log` (optional: decisions are also audit rows)
- **Audit actions:**
  - `action.allowed`: sampled; always written for sensitive tools.
  - `action.blocked`, `action.escalated`, `action.approved`, `action.denied`, `action.expired`.
  - `action_policy.created`, `action_policy.approved`, `action_policy.retired`.
- **Outbox topic:** `action`.
- **Routes** (scopes are new: `actions:read`, `actions:decide`, `action_policies:write`):
  - `GET/POST /action-policies`, `GET /action-policies/{id}`, `POST /action-policies/{id}/approve`, `POST /action-policies/{id}/retire`
  - `POST /action-policies/{id}/simulate`: dry-run against sample args. It returns the decision and writes nothing.
  - `POST /held-actions` (key scope `actions:hold`, used by the gateway and SDK), `GET /held-actions`, `GET /held-actions/{id}`
  - `POST /held-actions/{id}/actions` with `approve | deny`. Four-eyes applies when the policy demands it; the requester's own principal cannot approve. Step-up is required for sensitive tools.
  - `POST /action-decisions`: the cumulative check-and-increment, idempotent per `call_id`.
- **Worker:** the `held_actions` loop expires pending holds at `hold_timeout_s`. The default is deny.
- **Snapshot:** the active approved policies for the agents in scope go into the signed snapshot (`action_policies`), within the B4 budget.

## 4. Never auto-resume side-effecting work (A-4)
A handoff task, or saga resume, whose recorded steps include a side effect with `idempotent != true` is never resumed automatically. It goes to the operator queue with the side-effect ledger. This is enforced in the handoff and saga code, with tests.

## 5. Harness (A-5) and console (A-6): follow-on lanes after the core merges
- **Scenarios:**
  - an over-limit transfer is blocked
  - an under-limit transfer is allowed
  - a cumulative daily cap escalates
  - exfiltration of PII to an external tool is blocked
  - an injection-driven tool call is blocked
  - a held action approved by a second human goes ahead
  - a timeout leads to deny
- **Gate:** 0 unauthorised actions executed.
- **Console:** an action policies editor with simulate, a held-actions queue (approve or deny with four-eyes and step-up), decision records, and a fleet badge showing the count of blocked and escalated actions.
