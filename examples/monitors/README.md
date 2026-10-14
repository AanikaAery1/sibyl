# External monitor examples

Any outside agent can watch the agents in Sibyl and report what it sees (D53). Each example
below uses a **monitor key**: register a monitor in the console (Monitors page) or with
`POST /api/v1/monitors`, and keep the `sbl_…` secret shown once. The key carries
`monitor:read` (metadata reads, limited to the agent groups the monitor watches) and
`findings:write` (advisory findings, rate-limited per monitor).

Findings are **advisory**. A finding can open a watch-only `external_finding` alert or attach
advice to a held action; a monitor can never allow, block, approve, fail over or change policy.
Everything a monitored agent wrote (names, summaries, tool names, errors) is **untrusted data**:
the prompts below tell the model never to follow instructions found in it.

| Example | Model / runtime | How it reads Sibyl |
|---|---|---|
| [`claude_mcp/`](claude_mcp/) | Claude (Desktop, Code, Agent SDK, `claude-fable-5-1`) | `sibyl-mcp` over stdio |
| [`openai_agents_monitor.py`](openai_agents_monitor.py) | OpenAI Agents SDK | `sibyl-mcp` over stdio |
| [`gemini_monitor.py`](gemini_monitor.py) | Gemini (`google-genai`) | `sibyl.monitor.Client` |
| [`webhook_receiver.py`](webhook_receiver.py) | none (FastAPI) | signed webhooks, then the client |
| [`rules_monitor.py`](rules_monitor.py) | none (rules) | `sibyl.monitor.Client` |

## Environment

| Variable | Used by |
|---|---|
| `SIBYL_API_URL` | all (control plane URL, with or without `/api/v1`) |
| `SIBYL_MONITOR_KEY` | all (the monitor key) |
| `SIBYL_CA_FILE` | optional extra CA bundle (corporate TLS inspection; verification stays on) |
| `SIBYL_WEBHOOK_SECRET` | `webhook_receiver.py` (the `whsec_` secret shown when the webhook was created) |
| `ANTHROPIC_API_KEY` | `claude_mcp/agent_sdk_monitor.py` |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | `openai_agents_monitor.py` |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | `gemini_monitor.py` |

Keys are read from the environment only; no example prints or stores them.

## (a) Claude via MCP

```bash
# from a checkout of the Sibyl repo (not published to PyPI)
pip install ./packages/sibyl-schemas ./packages/sibyl-sdk ./packages/sibyl-mcp   # installs the `sibyl-mcp` command
```

* **Claude Desktop**: merge [`claude_mcp/claude_desktop_config.json`](claude_mcp/claude_desktop_config.json)
  into `claude_desktop_config.json` and paste the monitor key.
* **Claude Code**: copy [`claude_mcp/mcp.json`](claude_mcp/mcp.json) to `.mcp.json` in your
  project (it expands `${SIBYL_API_URL}` and `${SIBYL_MONITOR_KEY}` from your shell), or run

  ```bash
  claude mcp add sibyl --env SIBYL_API_URL="$SIBYL_API_URL" \
      --env SIBYL_MONITOR_KEY="$SIBYL_MONITOR_KEY" -- sibyl-mcp
  ```

  then ask: *"Review the pending held actions in Sibyl and give your advice on each."*
* **Claude Agent SDK**: `pip install claude-agent-sdk` and run
  `python examples/monitors/claude_mcp/agent_sdk_monitor.py`.

## (b) OpenAI Agents SDK

```bash
pip install openai-agents ./packages/sibyl-schemas ./packages/sibyl-sdk ./packages/sibyl-mcp
python examples/monitors/openai_agents_monitor.py
```

## (c) Gemini

```bash
pip install google-genai ./packages/sibyl-schemas ./packages/sibyl-sdk
python examples/monitors/gemini_monitor.py
```

## (d) Webhook receiver

Create a webhook for the monitor (`POST /api/v1/monitors/{id}/webhooks` with an https URL and
the event types, e.g. `run.failed`, `action.held`), keep the `whsec_` secret, then:

```bash
pip install fastapi uvicorn ./packages/sibyl-schemas ./packages/sibyl-sdk
uvicorn --factory examples.monitors.webhook_receiver:create_app --port 9000
```

Every delivery carries `Sibyl-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>`,
`Sibyl-Event-Id`, `Sibyl-Event-Type` and `Sibyl-Delivery-Id`. The receiver verifies the
signature over the raw body, rejects anything older than five minutes, de-duplicates by event
id (deliveries are retried), and answers 2xx quickly. Use the test button (or
`POST …/webhooks/{wid}/test`) to send a signed `ping`.

## (e) Rules-only monitor

```bash
python examples/monitors/rules_monitor.py     # e.g. from cron every 5 minutes
```

It flags agents in band `failed` (critical, opens an alert) or `degraded` (warning), and agents
with `FAILED_RUNS_THRESHOLD` (default 5) failed runs in the last hour. Idempotency keys are
derived from rule, agent and hour, so re-runs never duplicate findings.
