# Runbook: incident response (single operator)

**Owner:** the operator on duty. In Phase 1 that is one person (D18).
**Service window:** business hours.
**Paging:** none. Burn-rate alerts go to an inbox, not a pager.
**Sources:** D18, D21, D24, D34, ARCHITECTURE ADR-1.

This runbook is for when you do not yet know what is wrong. Follow it in order. Stop as soon as a step points you to a specific runbook.

## 0. Two facts to keep in mind

- **Agents keep running when Sibyl is unhealthy.** The gateway serves from its last verified snapshot and never waits for the control plane. When the snapshot expires, each agent's fail mode decides: `open` serves, `closed` refuses. Most control-plane failures therefore stop *governance*, not *traffic*. Do not restart the gateway to fix a control-plane problem.
- **Every human action is audited, with your reason.** Write reasons that will make sense to an auditor in a year.

## 1. Is the stack up?

```bash
dc ps --format '{{.Service}}\t{{.State}}\t{{.Health}}'
```

Every service should be `running` and `healthy`. The one-shot services `bootstrap` and `migrate` should be `exited (0)`.

| Unhealthy service | What it means | Next |
|---|---|---|
| `postgres` | Everything but the gateway is down | `dc logs --tail 200 postgres`. Check disk space. If data is damaged, go to [backup-restore.md](backup-restore.md). |
| `api` | No console, no API, no snapshots. The gateway ages toward `expired`. | `dc logs --tail 200 api`. A missing secret appears as `api cannot start: ...`. Then follow [snapshot-stale.md](snapshot-stale.md). |
| `ingest` | Telemetry backs up in SDK queues and the gateway's queue. Health scoring goes blind. | `dc logs --tail 200 ingest` |
| `worker` | No scoring, prediction, failover, failback, anchors or erasure | See step 2 |
| `gateway` | Agent traffic fails | `dc logs --tail 200 gateway`. Read the readiness check below. |
| `caddy` | Nothing is reachable from the host | `dc logs caddy` |

Gateway readiness shows the snapshot it is serving from:

```bash
dc exec -T gateway python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8080/readyz').read().decode())"
# {"status": "ready", "snapshot": "fresh", "version": 412}
```

## 2. Is the worker doing its job?

The worker's health check lists every loop with its last success and last error:

```bash
dc exec -T worker python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8002/healthz').read().decode())" | jq '.reasons, .stub_loops, (.loops | map_values({runs, consecutive_failures, last_ok, last_error}))'
```

| Loop | Interval | If it is failing |
|---|---|---|
| `rollup`, `scoring` | 10 s | Health is not being computed, so nothing is detected. See [sse-outbox-stalled.md](sse-outbox-stalled.md) if `last_ok` is old but there are no errors. |
| `predict`, `alerts` | 10 s | No predictions; alerts do not resolve |
| `saga` | 1 s | Failovers do not progress. Check `GET /incidents?open=true`. |
| `approvals` | 5 s | Approval timeouts are not applied |
| `failback`, `handoff` | 30 s | Agents stay failed over; handoff tasks are not built or expired |
| `anchors` | hourly | No anchors, exports or async verifications |
| `erasure_exec`, `erasure_ledger` | 10 s / 60 s | Erasures stall. The request carries an `error`. |

A failing loop backs off, up to 5 minutes or its interval, whichever is longer. It never stops the other loops. The worker reports itself unhealthy only when every implemented loop is failing. A loop listed under `stub_loops` is not built yet; `jobs` is one.

## 3. Is an agent or a provider in trouble?

In the console, check **Fleet**, **Incidents** and **Alerts**. Or use the API:

```bash
curl -s --cacert "$CA" "$SIBYL/api/v1/provider-incidents" -H "Authorization: Bearer $SESSION" | jq '.data[] | {id, provider_id, state}'
curl -s --cacert "$CA" "$SIBYL/api/v1/incidents?open=true" -H "Authorization: Bearer $SESSION" | jq '.data[] | {id, agent_id, kind, state, step}'
curl -s --cacert "$CA" "$SIBYL/api/v1/approvals?state=pending" -H "Authorization: Bearer $SESSION" | jq '.data[] | {id, agent_id, expires_at}'
```

- **A provider incident is open:** go to [provider-outage.md](provider-outage.md).
- **One agent is misbehaving:** this means loops, runaway cost, or wrong actions. Choose the smallest action that stops harm:
  1. Degrade it. `POST /incidents` with `action: degrade`.
  2. Quarantine it. The gateway then refuses its traffic.
  3. Kill it with an agent-scope kill switch. Pulling one needs step-up.

  The actions are described in [operations](../../docs/guide/operations.md).
- **Pending approvals.** Decide them before they time out (10 minutes by default). Remember that a person cannot approve their own request.

## 4. When automation made the wrong call

Undo the incident's last automated transition:

```bash
curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/incidents/$INCIDENT/actions" \
  -H "Authorization: Bearer $SESSION" -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" \
  -d '{"action": "undo", "reason": "<what was wrong and how you know>"}'
```

**What undo does.** It reverses the route and returns queued handoff tasks to the agent. It also places a **30-minute operator hold**: rules and predictions take no action on that agent during the hold (D21). Humans and the kill switch still can. An Admin or Security admin can lift the hold early with `clear_hold`.

**Breaker.** Two undone automated transitions on one agent within 7 days switch it to approval-only (`preemptive_mode=approval`).

Later, close the alert that caused the move with verdict `fp`. Verdicts are how rules get tuned.

## 5. When the identity provider is down

People cannot sign in or step up. Two things still work:

- Existing sessions keep working until they expire (8 hours absolute, 30 minutes idle).
- If you must stop agents, use the **break-glass key**. It reaches only `POST /kill-switches`; see [operations](../../docs/guide/operations.md#break-glass-d20).

After any break-glass use, rotate that key. A second tenant-wide kill within 10 minutes must come from a different Admin (D34).

## 6. Close out

1. **Verdict every alert the incident raised** (D24): `tp`, `fp` or `unsure`. Alerts that resolved by themselves wait under **Alerts → Unverdicted**.
2. **Release** kill switches and quarantines once the cause is fixed. Releasing needs step-up and a reason.
3. **Verify the audit chain** for the incident window. Export it if an auditor will ask:
   ```bash
   curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/audit/verifications" -H "Authorization: Bearer $SESSION" \
     -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{}' | jq
   ```
4. **Write the incident log entry:**
   - the timeline;
   - the actions you took, with their audit `seq` numbers (from the `X-Sibyl-Audit-Receipt` headers or **Audit**);
   - the impact: agent-minutes on fallback or refused, and tasks completed by people (`GET /queue`, field `summary.completed_despite_failure`);
   - follow-ups.
