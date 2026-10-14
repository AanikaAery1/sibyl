# Runbook: provider outage

**Symptoms:** many agents on one provider go red together. A provider incident opens, alerts collapse into it, and incidents open for the affected agents. Gateway responses for those agents switch to `X-Sibyl-Route: failover` or `inline_fallback`.

**Sources:** D13, D21, D22, D24, ML §4.5–§4.6, sre §2.3.

## What Sibyl does without you

1. **Detection.**
    - The scoring loop marks the failing agents with a `failed` health band.
    - The status poller (every 60 s) reads the provider's status feed, when one is configured.
    - Alerts on one provider collapse into a single **provider incident**.
2. **Failover, batched and tier 1 first.** The saga opens incidents for the incident's member agents in one transaction. It excludes the failing provider from their targets. On a detected failure, these steps are automatic on every tier:
    - an alternate model,
    - an alternate provider (if a vaulted credential exists),
    - degraded safe mode,
    - the human queue.

   A tier-1 move to a **backup agent** waits for an approval.
3. **Handoff.** Agents whose next step is `human_queue` are refused at the gateway with `sibyl_agent_handed_off` (`Retry-After: 300`). Their work becomes handoff tasks in the operator queue.
4. **Failback.** When the provider has been operational, with no open incident, for 5 minutes, the failback loop returns each agent to its primary.

## What you do

### 1. Confirm the scope

```bash
curl -s --cacert "$CA" "$SIBYL/api/v1/provider-incidents" -H "Authorization: Bearer $SESSION" \
  | jq '.data[] | {id, provider_id, state, affected: (.affected_agent_ids | length)}'
curl -s --cacert "$CA" "$SIBYL/api/v1/providers/$PROVIDER/status" -H "Authorization: Bearer $SESSION" | jq '.data[:5]'
```

### 2. Work the approvals first

Tier-1 agents waiting on a backup-agent move appear in `GET /approvals?state=pending` and on the console's approval cards. Decide them with `approve` or `deny` on the incident.

If nobody decides within the timeout (10 minutes by default), the plan's `approval_timeout_policy` applies. For tier-1 agents with PII exposure, that is always `hold`: the agent stays degraded, and no move happens without a person (D22).

### 3. Watch the queue

```bash
curl -s --cacert "$CA" "$SIBYL/api/v1/queue" -H "Authorization: Bearer $SESSION" | jq '.summary'
```

Claim and complete tasks in the console's **Queue**. Each packet lists the completed and pending steps and the side effects already caused. Check the side effects before redoing any step that writes.

### 4. Stop agents whose fallback is not safe

Some agents should not run on a fallback model, for example because of prompt compatibility or regulatory approval.

- To stop one agent, **quarantine** it, or pull an agent-scope kill switch.
- To stop everything on the provider, pull a provider-scope kill switch:

```bash
curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/kill-switches" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" \
  -d '{"scope_kind": "provider", "scope_id": "'"$PROVIDER"'", "reason": "Provider outage; fallback not approved for these agents."}'
```

A kill switch needs step-up in your console session.

### 5. Legal or contractual exposure

If the outage may lead to a dispute, place an **incident-scope legal hold** so retention does not sweep the evidence:

```bash
curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/legal-holds" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" \
  -d '{"scope_kind": "incident", "provider_incident_id": "'"$PROVIDER_INCIDENT"'", "window_from": "2026-10-11T09:00:00Z", "reason": "Customer SLA dispute expected."}'
```

### 6. Recovery

Do nothing at first: failback is automatic. To return one agent early, run `fail_back` on its incident.

Failback is suspended for an agent after two reverts, which only happens with `SIBYL_FAILBACK_RAMP=1`. That agent stays `failed_over` until you run `fail_back`.

### 7. Close out

- Give the provider-level alert a verdict (usually `tp`). It labels the incident's member alerts too.
- Release any kill switches you pulled.
- Write the incident log entry ([incident-response.md](incident-response.md) step 6).

## In the demo

`sibyl-sim` simulates outages on its own port. Nothing here is reachable from a product port.

```bash
curl -s -X POST http://localhost:8300/_sim/doubles/anthropic-stub/outage -H 'Content-Type: application/json' -d '{"on": true}'
curl -s -X POST http://localhost:8300/_sim/status/anthropic/incidents -H 'Content-Type: application/json' \
  -d '{"name": "Elevated error rates", "status": "major_outage"}'
curl -s -X POST http://localhost:8300/_sim/doubles/anthropic-stub/outage -H 'Content-Type: application/json' -d '{"on": false}'
curl -s -X POST http://localhost:8300/_sim/status/anthropic/reset
```
<!-- verify after INT-2: seeded providers carry no status_url, so the status poller does not read the sim feed unless one is set on the provider -->
