# Sibyl in 10 minutes

**Who this is for:** an engineer who wants to see Sibyl detect a provider outage, move an agent's traffic, and leave an audit trail that someone else can verify offline.

**What you will do:**

1. Start the stack and seed the demo tenants.
2. Connect an agent through the gateway and with the SDK.
3. Take a simulated provider down.
4. Watch detection, the alert and the failover.
5. Close the alert with a verdict.
6. Export the audit log as the auditor and verify it offline.

**You need:**

- The repository checked out.
- Docker with Compose v2.
- Python 3.13 with `uv`.
- `jq`, `curl`, `uuidgen` and a browser.

Run every command from the repository root unless a step says otherwise.

> The compose integration is being finished. Steps marked `<!-- verify after INT-2 -->` are the intended path but have not been run end to end yet.

## 1. Start the stack

```bash
ops/demo/up.sh
```
<!-- verify after INT-2: ops/demo/up.sh (init-env, build, bootstrap, migrate, signing-key registration, every service with the sim profile) -->

The first run builds four images and takes a few minutes. When it finishes, it prints the URLs:

| Surface | URL |
|---|---|
| Console and API | https://localhost:8443 (API under `/api/v1`) |
| Gateway (OpenAI-compatible) | https://localhost:8444/v1 |
| Ingest | https://localhost:8445/v1 |
| Simulator control (dev only) | http://localhost:8300 |

Define a shorthand for compose, then trust Caddy's local certificate authority:

```bash
dc() { docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env --profile sim "$@"; }
dc cp caddy:/data/caddy/pki/authorities/local/root.crt ./sibyl-local-root.crt
export SIBYL=https://localhost:8443
export CA="$PWD/sibyl-local-root.crt"
```

## 2. Seed the demo tenants

```bash
dc run --rm --no-deps api python -m sibyl_control.cli.seed --sim-host sim
```
<!-- verify after INT-2: the seed run inside the api container, and --sim-host sim (the compose alias INT-2 adds) -->

The seed creates three tenants. It writes everything through the real API handlers, so validation, audit rows and outbox events match what a client would produce. Running it again writes nothing.

| Tenant | Contents |
|---|---|
| `meridian` | 20 agents across three simulated providers (`openai-stub`, `anthropic-stub`, `ollama-stub`), each with a continuity plan and an approved fallback chain |
| `northstar` | 3 agents, used to show tenant isolation |
| `sandbox` | Empty |

The seed leaves tier-1 agents in `proposed` until an agent-bound key exists (R35), and lists them in its report.

The demo persona password is in `deploy/compose/env/demo-password.env`. It is the same for all three personas.

## 3. Mint keys

Sibyl keys look like `sbl_test_<prefix>_<secret>`. The compose stack runs with `SIBYL_ENV=test`, so every key here uses `--env test`. The secret is printed once.

**Gateway keys.** The gateway holds one tenant key and one ingest key. Mint them, write them to the gateway's file secrets, and restart the gateway:

```bash
cli() { dc run --rm --no-deps -T api python -m sibyl_control.cli --json "$@"; }
put_secret() { chmod 0644 "$1"; printf '%s' "$2" > "$1"; chmod 0444 "$1"; }

put_secret deploy/compose/env/secrets/gateway_tenant_keys \
  "$(cli keys create meridian --name gateway-meridian --env test --scope gateway:proxy --scope routing:read | jq -r .secret)"
put_secret deploy/compose/env/secrets/gateway_ingest_key \
  "$(cli keys create meridian --name gateway-ingest --env test --scope ingest:write | jq -r .secret)"
dc up -d --force-recreate --wait gateway
```
<!-- verify after INT-2: the gateway_ingest_key secret and the gateway's pinned snapshot key are added by INT-2 -->

**Agent keys.** You will connect `returns-agent`, a tier-2 agent in `meridian` whose primary provider is `anthropic-stub`. It needs two keys bound to it. The SDK refuses any key that carries `gateway:proxy`, so the gateway and the SDK each get their own:

```bash
export SIBYL_GATEWAY_KEY=$(cli keys create meridian --name returns-agent-gateway --env test \
  --agent returns-agent --scope gateway:proxy --scope actions:hold | jq -r .secret)
export SIBYL_API_KEY=$(cli keys create meridian --name returns-agent-sdk --env test \
  --agent returns-agent --scope ingest:write --scope routing:read --scope handoff:write \
  --scope actions:hold | jq -r .secret)
```

Both keys carry `actions:hold` so the Action Gate can hold an escalated action for a person and check cumulative caps. Without it, escalations and capped tools fail closed.

## 4. Log in as the Platform Admin

Open this URL in a browser and sign in as `admin@demo.sibyl.example` with the demo password:

```
https://localhost:8443/api/v1/auth/login?tenant=meridian
```
<!-- verify after INT-2: login entry point from the live console (the console has no sign-in link yet; this API route starts the dex flow and returns to /) -->

You land on **Fleet** in Meridian Logistics. The Platform Admin is an **Admin**, which is the `owner` role.

Some steps use `curl` as a person rather than as an API key. For those you need a session token:

1. In the browser's developer tools, copy the value of the `__Host-sibyl_session` cookie.
2. Export it:

```bash
export ADMIN="sibyl_sess_<paste the cookie value>"
```

## 5. Connect an agent, two ways

### (a) An unchanged OpenAI client, pointed at the gateway

This is the zero-code path. Your provider key goes in the normal place and is passed through to the primary provider. The Sibyl key and the agent name go in two headers (R23). The request body stays plain OpenAI.

Save this as `agent_gateway.py`:

```python
import os
import ssl
import time

import httpx
import openai

client = openai.OpenAI(
    base_url="https://localhost:8444/v1",
    api_key="sim-demo-provider-key",  # your provider key; the simulator accepts any value
    default_headers={
        "X-Sibyl-Key": os.environ["SIBYL_GATEWAY_KEY"],
        "X-Sibyl-Agent": "returns-agent",
    },
    http_client=httpx.Client(verify=ssl.create_default_context(cafile="sibyl-local-root.crt")),
    max_retries=0,
)

while True:
    try:
        raw = client.chat.completions.with_raw_response.create(
            model="claude-sonnet-5",
            messages=[{"role": "user", "content": "Can I return order A-1042?"}],
        )
        h = raw.headers
        print(h["x-sibyl-routing-state"], h["x-sibyl-route"], h["x-sibyl-provider"], h["x-sibyl-model"])
    except openai.APIStatusError as exc:
        print(exc.status_code, exc.response.headers.get("x-sibyl-error"))
    time.sleep(2)
```

Run it and leave it running:

```bash
uv run --with openai python agent_gateway.py
# active primary anthropic-stub claude-sonnet-5
```

Each response carries `X-Sibyl-*` headers. These show the agent's routing state, which route served the call, and the provider and model that answered.

### (b) The Python SDK

The SDK adds task boundaries, checkpoints and handoff packets. Without them, a handoff packet built from gateway traffic has `request_only` fidelity: Sibyl knows the last request, not the agent's progress.

Save this as `agent_sdk.py`:

```python
import os
import ssl

import httpx
import openai
import sibyl

sibyl.init(agent_id="returns-agent")  # reads SIBYL_API_KEY, SIBYL_ENDPOINT, SIBYL_API_URL

client = openai.OpenAI(
    base_url="https://localhost:8444/v1",
    api_key="sim-demo-provider-key",
    default_headers={"X-Sibyl-Key": os.environ["SIBYL_GATEWAY_KEY"]},
    http_client=httpx.Client(verify=ssl.create_default_context(cafile="sibyl-local-root.crt")),
)

with sibyl.agent(goal="Process a return for order A-1042") as run:
    sibyl.checkpoint(
        {"order_id": "A-1042", "eligible": True},
        step="check_eligibility",
        completed=["parse_request", "check_eligibility"],
        pending=["draft_reply", "issue_refund"],
    )
    try:
        reply = client.chat.completions.create(
            model="claude-sonnet-5",
            messages=[{"role": "user", "content": "Draft a return confirmation for A-1042."}],
        )
    except sibyl.SibylKilled:
        run.cancel("kill switch")
        raise
    except openai.APIStatusError as exc:
        run.handoff(
            sibyl.handoff.packet(
                reason=f"The model call failed while drafting the reply ({exc.status_code}).",
                failure_mode="provider_outage",
                next_action="Draft the reply and issue the refund by hand.",
            )
        )
    else:
        run.outcome("success")

print("delivered:", sibyl.flush(5))
sibyl.shutdown()
```

Run it:

```bash
SIBYL_ENDPOINT=https://localhost:8445 SIBYL_API_URL=https://localhost:8443 SSL_CERT_FILE="$CA" \
  uv run --with openai python agent_sdk.py
```
<!-- verify: SSL_CERT_FILE is honoured by the SDK's httpx clients; if not, pass init(transport=httpx.HTTPTransport(verify=ssl_ctx)) -->
<!-- verify after INT-2: the SDK's kill-switch poll (GET /api/v1/policy/snapshot) is answered 404 by Caddy on :8443 today; the SDK then runs fail-open and the gateway still enforces kills -->

`sibyl.init()` auto-instruments the `openai` library. The SDK adds `X-Sibyl-Agent`, `X-Sibyl-Task-Id` and `traceparent` to each call, so the gateway's view and the SDK's view of one call merge in ingest. The SDK never blocks your code and never raises into it, apart from `SibylKilled`, `SibylPolicyUnavailable` (fail-closed agents only) and `SibylConfigError` from `init()`.

Within a few seconds, `returns-agent` shows traffic on its card in the console.

## 6. Take the provider down

The simulator's admin API listens on its own port. It is never on a product port. Switch on a hard outage of the Anthropic double:

```bash
curl -s -X POST http://localhost:8300/_sim/doubles/anthropic-stub/outage \
  -H 'Content-Type: application/json' -d '{"on": true}' | jq '.knobs.outage'
# true
```

Every request to `anthropic-stub` now gets a 503.
<!-- verify after INT-2: the seeded provider base URLs must reach the named double; today the seed builds https://sim:<port>/v1 per provider while the simulator serves all doubles on one port as /<double>/v1 -->

If `SIBYL_SIM_ADMIN_TOKEN` is set for the simulator, add `-H "Authorization: Bearer $SIBYL_SIM_ADMIN_TOKEN"`. The demo stack does not set one.

## 7. Watch detection, the alert and the failover

In the console, watch **Fleet** and then **Incidents**. Or follow the event stream from a second terminal:

```bash
curl -sN --cacert "$CA" "$SIBYL/api/v1/events/stream?topics=health,alert,incident,approval,handoff" \
  -H "Authorization: Bearer $ADMIN"
```

**What happens, in order:**

1. The scoring loop runs every 10 seconds. It sees the errors and turns the agent's health band to `failed`. A `detected` alert fires (`alert.fired`).
2. When several agents on `anthropic-stub` fail together, they collapse into one provider incident (`provider_incident.opened`), not a stream of separate alerts.
3. The saga loop runs every second. It opens a failover for `returns-agent` and moves it to the next viable step in its approved chain (`incident.updated`). Steps on a provider with an open incident are excluded.
    - For tier 2, failover to an alternate model or provider is automatic on a detected failure.
    - Failover to a backup agent on tier 1 always waits for a human approval.
4. The gateway picks up the new routing version on its next snapshot poll. The poll runs every 5 seconds by default.

In the first terminal, the output changes to:

```
failed_over failover openai-stub gpt-5.4
```
<!-- verify after INT-2: with only returns-agent sending traffic there is no provider incident, so the saga may first take the chain's alt_model_same_provider step (claude-haiku-5 on the same failing double) before reaching openai-stub -->

Your client code did not change, and calls keep succeeding.

**Tier-1 agents** (for example `quote-assistant`) behave differently. A move to a backup agent opens an approval and parks the agent in `awaiting_approval`. Sign in as the **On-call Operator** to see the approval card and decide it. The person who requested a move cannot approve it. If nobody decides within 10 minutes, the plan's timeout policy applies. For tier-1 agents with PII exposure, that is always `hold` (D22).

## 8. Recover and close the alert with a verdict

End the outage:

```bash
curl -s -X POST http://localhost:8300/_sim/doubles/anthropic-stub/outage \
  -H 'Content-Type: application/json' -d '{"on": false}' | jq '.knobs.outage'
```

The alert resolves once the agent is healthy. The failback loop checks every 30 seconds. After the primary has been healthy for 5 minutes, it moves the agent to `failing_back` and then back to `active`.

The canary ramp (10 → 25 → 50 → 100%) is off in Phase 1. Enable it with `SIBYL_FAILBACK_RAMP=1`.

**Every alert needs a verdict** (D24). An alert that resolved without one is listed under **Alerts → Unverdicted** in the console. To close it from the command line, sign in as the On-call Operator (`operator`) in a private window, copy that session cookie the same way, and run:

```bash
export OPERATOR="sibyl_sess_<the operator's cookie value>"
AGENT=$(curl -s --cacert "$CA" "$SIBYL/api/v1/agents?q=returns-agent" -H "Authorization: Bearer $OPERATOR" | jq -r '.data[0].id')
ALERT=$(curl -s --cacert "$CA" "$SIBYL/api/v1/alerts?agent_id=$AGENT&unverdicted=true" \
  -H "Authorization: Bearer $OPERATOR" | jq -r '.data[0].id')

curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/alerts/$ALERT/actions" \
  -H "Authorization: Bearer $OPERATOR" -H "Idempotency-Key: $(uuidgen)" -H 'Content-Type: application/json' \
  -d '{"action": "close", "verdict": "tp", "verdict_note": "Simulated anthropic-stub outage; failover worked."}' \
  | jq '{id, state, verdict}'
```

The verdict is `tp`, `fp` or `unsure`. A `close` without one returns `422 verdict_required`. Verdicts become labels for rule tuning. A verdict on a provider-level alert also labels the incident's member alerts.

## 9. The Compliance Auditor exports the audit log and verifies it offline

Sign in as the **Compliance Auditor** (`auditor`) and copy that session cookie:

```bash
export AUDITOR="sibyl_sess_<the auditor's cookie value>"
```

**Find the head of the chain.** Verify the whole chain on the server. Up to 100,000 rows are verified inline. The response tells you how many rows exist:

```bash
ROWS=$(curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/audit/verifications" \
  -H "Authorization: Bearer $AUDITOR" -H "Idempotency-Key: $(uuidgen)" -H 'Content-Type: application/json' \
  -d '{}' | jq .rows)
echo "chain has $ROWS rows"
```

**Request an export up to the head.** The worker writes a signed `export` anchor at `to_seq` first, then the export object:

```bash
EXPORT=$(curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/audit/exports" \
  -H "Authorization: Bearer $AUDITOR" -H "Idempotency-Key: $(uuidgen)" -H 'Content-Type: application/json' \
  -d "{\"from_seq\": 0, \"to_seq\": $((ROWS - 1)), \"format\": \"jsonl\"}" | jq -r .id)
```

**Wait for it to finish.** The anchors loop serves export requests. In Phase 1 that loop wakes hourly and at worker start, so restart the worker to serve the request now:

```bash
dc restart worker
curl -s --cacert "$CA" "$SIBYL/api/v1/audit/exports/$EXPORT" -H "Authorization: Bearer $AUDITOR" | jq '{state, anchor_id, export_sha256}'
# "state": "done"
```
<!-- verify: the anchors loop does not yet wake on the sibyl_outbox NOTIFY (change request to INT-1); until it does, a restart is the fastest way to serve an export -->

**Download it.** An auditor's payload reads are always audited and need a stated reason:

```bash
URL=$(curl -s --cacert "$CA" "$SIBYL/api/v1/audit/exports/$EXPORT" -H "Authorization: Bearer $AUDITOR" | jq -r .download_url)
curl -s --cacert "$CA" "$URL" -H "Authorization: Bearer $AUDITOR" \
  -H "X-Sibyl-Reveal-Reason: Quickstart audit evidence export" -o audit-export.jsonl
```
<!-- verify: download of an anchor_export object by an auditor (reveal reason path in GET /payloads/{ref_id}) -->

**Verify it offline.** This needs no server access, only the file and the anchor public key:

```bash
uv run sibyl audit verify audit-export.jsonl --public-key deploy/compose/env/public/anchor_signing.pem
# stdout: {"ok": true, "rows": ..., "anchors_checked": 1, ...}
# stderr: OK: <n> rows (seq 0..<n-1>), 1 anchor(s) verified
```

`sibyl audit verify` checks four things:

- It re-hashes every row: `sha256(prev_hash ‖ sha256(JCS(envelope)) ‖ sha256(JCS(detail)))`.
- It checks that the rows are contiguous.
- It checks every anchor's Ed25519 signature.
- It checks that the export ends at an anchor.

It exits 0 when the chain verifies, 1 on a break (reported with the `seq` and kind), and 2 when the input cannot be read.

The public key can also come from the API:

```bash
curl -s --cacert "$CA" "$SIBYL/api/v1/audit/signing-keys" -H "Authorization: Bearer $AUDITOR" > anchor-keys.json
uv run sibyl audit verify audit-export.jsonl --public-key anchor-keys.json
```

To see a failure, change one character in any row's `reason` and run the command again. It reports `content_mismatch` at that `seq`.

## Next

- [Concepts](guide/concepts.md): the vocabulary used throughout.
- [Operations](guide/operations.md): approvals, undo and hold, quarantine, the kill switch, break-glass.
- [Governance](guide/governance.md): anchors, exports, erasure, legal holds.
- [Python SDK](guide/sdk.md).
- [Runbooks](../ops/runbooks/README.md).

**Clean up:**

```bash
ops/demo/down.sh            # keeps volumes
ops/demo/down.sh --purge    # deletes the database, blobs, ledger and gateway snapshot too
```
<!-- verify after INT-2 -->
