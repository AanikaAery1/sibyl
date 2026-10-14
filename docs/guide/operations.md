# Operations

**Who this is for:** operators and security admins, the On-call Operator persona. Every action on this page is a routing transition or a queue change. Each one is audited with your identity and your reason, and appears in the Compliance Auditor's audit view.

All examples use a console session token (see [API conventions](api.md#authentication)) and assume:

```bash
export SIBYL=https://localhost:8443
H=(-H "Authorization: Bearer $SESSION" -H "Content-Type: application/json")
```

Every `POST` also needs `-H "Idempotency-Key: $(uuidgen)"`. Reasons are 10–2000 characters, except kill-switch reasons, which need at least 20.

## How automation decides

| Trigger | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| **Detected failure** (health band `failed` on an open alert) | Automatic for an alternate model or provider, degraded safe mode or the human queue. A backup agent **always needs approval**. | Automatic | Automatic |
| **Prediction**, 15-minute horizon, band reached, confidence `medium` or higher, two signal families | Always an approval request, from band `0.60` | `degrade_then_auto`: degraded now, failover after 20 s if the prediction persists. Band `0.90` until the D36 criterion opens `0.60`. | `auto`, band `0.90` (same D36 rule) |
| **Operator** | Four-eyes approval for a backup agent | Immediate | Immediate |

**Guard rails:**

- **Lone agent.** A single failing agent whose provider looks healthy waits one extra scoring cycle before failing over.
- **Provider outage.** Agents on a failing provider are opened together, tier 1 first, and that provider is excluded from their targets.
- **Per-agent breaker.** Two automated transitions that were undone, or verdicted `fp`, within 7 days switch that agent's `preemptive_mode` to `approval`. The switch is audited as `config.changed`.
- **Operator hold.** During a hold, rule and policy actors do nothing for that agent. The alert's suppressed count rises instead.

## Incidents

```bash
curl -s "$SIBYL/api/v1/incidents?open=true" "${H[@]}" | jq '.data[] | {id, agent_id, kind, state, step}'
curl -s "$SIBYL/api/v1/incidents/$INCIDENT" "${H[@]}"
curl -s "$SIBYL/api/v1/agents/$AGENT/routing" "${H[@]}"              # state, routing_version, hold
curl -s "$SIBYL/api/v1/agents/$AGENT/routing/transitions" "${H[@]}"  # the audited history
```

An incident's state is `pending`, `running`, `waiting_approval`, `done`, `cancelled` or `failed`. An agent has at most one live incident. A second one is refused with `409 saga_in_flight`, and the response names the live incident.

### Open one by hand: `POST /incidents`

```bash
curl -s -X POST "$SIBYL/api/v1/incidents" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"agent_id": "'"$AGENT"'", "action": "failover", "reason": "Provider latency is hurting customers; moving early."}'
```

| `action` | From routing state | Effect | Second scope (beside `incidents:act`) |
|---|---|---|---|
| `failover` | `active`, `degraded` | Runs the saga to the next viable chain step, or to `target: {step_id}` or `{kind, provider_id, model_id, agent_id}` | `routing:override` |
| `degrade` | `active` | Moves to `degraded`; the plan's degraded mode applies | `routing:override` |
| `recover` | `degraded` | Moves back to `active` | `routing:override` |
| `handoff` | `active`, `degraded`, `failed_over` | Routes to the human queue. The worker builds the tasks. | `routing:override` |
| `quarantine` | `active`, `degraded`, `failed_over` | The gateway refuses the agent's traffic | `quarantine:act` |
| `kill` | anything but `killed` | Shorthand for an agent-scope kill switch | `killswitch:pull` + step-up |

The response is `201` when the work finished in the request. It is `202` when the work continues in the worker, or when the request waits for an approval.

### Act on one: `POST /incidents/{id}/actions`

```bash
curl -s -X POST "$SIBYL/api/v1/incidents/$INCIDENT/actions" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"action": "undo", "reason": "False alarm: the error spike was a load test.", "expected_routing_version": 7}'
```

| `action` | When | Effect | Second scope |
|---|---|---|---|
| `approve` / `deny` | The incident is `waiting_approval` and the approval has not expired | `approve` resumes the saga. `deny` cancels it and moves the agent from `awaiting_approval` to `degraded`. **The requester cannot decide** (`409 self_approval`). | `approvals:decide` |
| `undo` | This incident's newest automated transition is still the agent's latest | Writes the inverse transition, cancels live work, returns queued handoff tasks to the agent, and places a **30-minute operator hold** (D21). It also records a `failover_outcome` label. | `routing:override` |
| `clear_hold` | An operator hold is active | Lifts the hold early. Admins and Security admins only. | `routing:override` |
| `release` | The agent is `quarantined` or `killed` | Returns it to `active`. Releasing from `killed` needs step-up and works only when an agent-scope switch is the only thing killing it. Otherwise release the switch itself. | `quarantine:act` or `killswitch:release` |
| `fail_back` | The agent is `failed_over` and the incident's failover is `done` | Moves to `failing_back` at 10%. The failback loop completes it. | `routing:override` |
| `cancel` | A failover that is pending, waiting, or not yet routed | Stops it. A waiting approval moves the agent from `awaiting_approval` to `degraded`. | `routing:override` |

An action the state does not allow is refused with `409 invalid_transition`, with `from_state` and `action` in the body.

## Approvals

```bash
curl -s "$SIBYL/api/v1/approvals?state=pending" "${H[@]}" | jq '.data[] | {id, agent_id, expires_at}'
```

Approvals are read here and decided through the incident's `approve` and `deny` actions. If nobody decides before the approval expires (10 minutes by default, `approval_timeout_s` on the plan), the plan's `approval_timeout_policy` applies:

- **`hold`**: the approval expires, the saga is cancelled, and the agent moves from `awaiting_approval` to `degraded`.
- **`fail_safe`**: the approval expires and the saga continues to `failed_over`.

A tier-1 agent with PII or residency exposure is always treated as `hold`, whatever the plan says (D22). A human-requested four-eyes approval always ends as `hold`.

## Kill switch

```bash
# Pull, as a person: needs killswitch:pull (Admin or Security admin) and a fresh step-up in this session
curl -s -X POST "$SIBYL/api/v1/kill-switches" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"scope_kind": "agent", "scope_id": "'"$AGENT"'", "reason": "Agent is emailing customers in a loop; stopping it now."}'

# List and release (release is session-only, with step-up; a key can never release)
curl -s "$SIBYL/api/v1/kill-switches?state=pulled" "${H[@]}"
curl -s -X POST "$SIBYL/api/v1/kill-switches/$KS/release" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"reason": "Loop fixed in version 14; verified in staging."}'
```

**Scope.** `scope_kind` is `agent`, `provider` or `tenant`. For a provider, `scope_id` is the provider id. For a tenant, omit `scope_id`.

**What a pull does, in one transaction:**

1. Cancels every live saga on each covered agent.
2. Moves each covered agent to `killed`.
3. Records a kill incident per agent.
4. Writes `killswitch.pulled` to the audit log and the outbox.

The gateway refuses killed agents with `sibyl_agent_killed`. That beats fail-open, and it holds while the snapshot is stale.

Each gateway acknowledges the snapshot it applied (`killswitch.applied`). `GET /kill-switches` shows these acknowledgements.

**A second tenant-wide kill within 10 minutes must come from a different Admin** (D34; `409 second_owner_required`).

**Release** returns to `active` only the agents this switch killed that no other pulled switch still covers.

### Break-glass (D20)

A break-glass key reaches exactly one route, `POST /kill-switches`, when the identity provider is down.

**Minting one.** You need an Admin or Security admin session with a fresh step-up:

```bash
curl -s -X POST "$SIBYL/api/v1/api-keys" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"name": "break-glass-1", "env": "live", "scopes": ["killswitch:pull"]}'
```

**Rules for the key:**

- It holds `killswitch:pull` and nothing else.
- It is tenant-level, never bound to an agent.
- It must be `env=live`.
- A tenant may have at most 2 active.
- Store it offline in two places. Test it in each game-day drill. Rotate it after any use.

**Using it:**

```bash
curl -s -X POST "$SIBYL/api/v1/kill-switches" -H "Authorization: Bearer $BREAK_GLASS_KEY" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" \
  -d '{"scope_kind": "tenant", "reason": "IdP outage and runaway spend; stopping all agents."}'
```

**What a use triggers:**

- It writes `access.break_glass` and requests a `break_glass` anchor.
- It is limited to 3 uses per 10 minutes per key and 6 per hour per tenant (`429 break_glass_rate_limited`, audited).
- Any other route answers `403 break_glass_key_misuse`.

<!-- verify: the compose demo runs SIBYL_ENV=test, and break-glass keys must be env=live, so a break-glass key cannot be minted on the demo stack -->
<!-- verify: the break_glass anchor is written when the anchors loop next runs (hourly, or at worker start); the 10-second target needs the NOTIFY wake-up change request -->

## The operator queue

```bash
curl -s "$SIBYL/api/v1/queue" "${H[@]}" | jq '{summary, tasks: [.data[] | {id, agent_id, priority, deadline_at, state}]}'
curl -s "$SIBYL/api/v1/handoff-tasks/$TASK/packet" "${H[@]}"           # needs packets:read
curl -s -X POST "$SIBYL/api/v1/handoff-tasks/$TASK/actions" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"action": "claim"}'
curl -s -X POST "$SIBYL/api/v1/handoff-tasks/$TASK/actions" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"action": "complete", "outcome": "resolved", "outcome_note": "Refund issued by hand.", "rating": 4}'
```

The queue is ordered by priority, then deadline. The `summary` block counts tasks by state over the last 30 days. It includes `completed_despite_failure`, the tasks people finished after an agent failed.

| Action | Effect |
|---|---|
| `claim` | Takes a 30-minute lock. A lapsed claim returns the task to the queue. |
| `extend_lock` | Extends the lock |
| `release_claim` | Gives the task back to the queue |
| `complete` | `outcome` is required: `resolved`, `escalated` or `abandoned`. `rating` (1–5) scores the packet's usefulness. |
| `return` | Sends a queued task back to the agent |
| `reassign` | Passes it to `accountable_user_id` |

Queued tasks expire at their deadline. When a plan is silent, the deadline is the tier's RTO: 15 min, 1 h or 4 h. An auditor's packet read is always audited (`data.revealed`).

## Alerts and verdicts

```bash
curl -s "$SIBYL/api/v1/alerts?state=open" "${H[@]}"
curl -s "$SIBYL/api/v1/alerts?unverdicted=true" "${H[@]}"        # resolved without a verdict (D33)
curl -s -X POST "$SIBYL/api/v1/alerts/$ALERT/actions" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"action": "silence", "until": "2026-10-11T18:00:00Z", "reason": "Planned provider maintenance."}'
curl -s -X POST "$SIBYL/api/v1/alerts/$ALERT/actions" "${H[@]}" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"action": "close", "verdict": "fp", "verdict_note": "Load test traffic."}'
```

The actions are `ack` (open alerts only), `silence` (needs a timezone-aware `until`) and `close`.

`close` needs a verdict: `tp`, `fp` or `unsure`. Without one the response is `422 verdict_required`. A resolved alert can be given a verdict once; after that the response is `409 already_resolved`. A verdict on a provider-level alert also labels its member alerts. `fp` verdicts on automated transitions count toward the per-agent breaker.

## Failback

The failback loop runs every 30 seconds. It returns an agent to its primary once all of these are true:

- The agent has been `failed_over` for at least 5 minutes.
- Its primary provider has had no non-operational status and no open incident for 5 minutes.
- Its own health has not been `degraded` or `failed` in that window.

In Phase 1 it moves from `failing_back` straight to `active`. With `SIBYL_FAILBACK_RAMP=1` it ramps 10 → 25 → 50 → 100%, holding each step green for 5 minutes. A breach reverts the agent and doubles the wait (5, 10, 20, up to 60 minutes). Two reverts stop automatic failback until someone runs `fail_back` by hand.

## What the gateway tells a client

The gateway answers in OpenAI's error shape, with `X-Sibyl-Error` and `X-Sibyl-Origin: gateway` on errors it produced itself. Successful responses carry `X-Sibyl-Agent-Id`, `X-Sibyl-Policy-Version`, `X-Sibyl-Policy-State`, `X-Sibyl-Route` (`primary`, `failover`, `inline_fallback`, `canary`, `stale_primary`), `X-Sibyl-Provider`, `X-Sibyl-Model`, `X-Sibyl-Routing-State` and `X-Sibyl-Capture-Mode`.

| Status | `X-Sibyl-Error` | Meaning |
|---|---|---|
| 400 | `sibyl_header_not_allowed`, `sibyl_bad_request` | A client may not set its own fail mode, and the body must be a JSON object |
| 401 | `sibyl_key_invalid` | Shown for invalid, revoked and expired keys alike |
| 403 | `sibyl_agent_mismatch`, `sibyl_scope_missing` | Wrong agent for a bound key; the key lacks `gateway:proxy` |
| 403 | `sibyl_agent_killed`, `sibyl_agent_quarantined` | Kill switch, quarantine |
| 403 | `sibyl_model_not_allowed`, `sibyl_policy_blocked` | The agent identity policy, when its enforcement is `block` |
| 404 | `sibyl_agent_unknown` | Unknown agent with no usable default route |
| 429 | `sibyl_rate_limited`, `sibyl_inflight_limit`, `sibyl_budget_exhausted`, `upstream_rate_limited` | Limits from the continuity plan, or the provider's own |
| 502 / 504 | `upstream_error`, `upstream_timeout` | Every target failed before the first byte |
| 503 | `sibyl_policy_expired` | Snapshot expired and the agent fails closed |
| 503 | `sibyl_no_snapshot` | The gateway has never verified a snapshot |
| 503 | `sibyl_agent_handed_off` (`Retry-After: 300`), `sibyl_agent_queued` | Work is with people, or the agent's degraded mode is `queue_only` |
| 503 | `sibyl_breaker_open` | The upstream circuit is open |

Related runbooks: [incident response](../../ops/runbooks/incident-response.md), [provider outage](../../ops/runbooks/provider-outage.md), [snapshot stale or gateway fail-open](../../ops/runbooks/snapshot-stale.md).
