# Sibyl — Product Document

As of 2026-10-14, release 1.0.0. Use this document as the source for marketing, go-to-market and business material. Every claim here is either built and tested, or explicitly marked as planned or as a research goal.

## 1. Product overview

Sibyl lets companies give AI agents more autonomy safely. It controls what agents are allowed to do, keeps them working when models and providers fail, and records every decision as evidence an auditor can verify.

Positioning line: **the control layer for the AI workforce: autonomy with guardrails, continuity and proof.**

- **What it is.** One self-hosted control plane:
  - an inventory of every agent, model and owner
  - enforcement points in the request path (a gateway that speaks the OpenAI, Anthropic and Gemini APIs, and a Python SDK that instruments an agent in one line)
  - signed policy, approvals, automatic failover and human handoff
  - a tamper-evident audit log
- **Who it is for.** Companies moving agents into workflows with real consequences (payments, claims, orders, customer communication), usually regulated or quasi-regulated firms with 10 to 60 production agent workflows on two or more model providers.
- **What makes it different.** Observability tools show what happened. Sibyl decides what is allowed to happen, acts when something fails, and proves it.
- **Form factor.** Self-hosted, multi-tenant, open-source dependencies only. The Python SDK is Apache-2.0; the core is proprietary.

## 2. The problem

Agents now do real work. Two things go wrong, and today nobody owns either.

**The agent fails.**

| Failure | What happens today |
|---|---|
| Provider outage or rate limit | Someone notices, edits config, redeploys |
| Silent quality loss (refusals, truncation, malformed tool calls) | Found days later through complaints |
| The provider serves a new model snapshot, or behaviour shifts with no error | Nobody notices until outputs look wrong |
| Runaway cost or tool loops | Found on the invoice |
| Work abandoned mid-task | Lost or duplicated |

**The agent works perfectly and does something it should not.**

| Example | Why monitoring misses it |
|---|---|
| Transfers $100,000 when authorised for $10,000 | Every call succeeded; nothing looks unhealthy |
| Sends customer data to an external tool after a prompt injection | Normal latency, normal tokens |
| Issues 40 refunds in a minute, each individually valid | No single call breaks a rule |

The second class is the larger risk, and it is what stops companies from giving agents more autonomy.

## 3. Personas and buyers

| Persona | Role in Sibyl | The job Sibyl does for them |
|---|---|---|
| Platform Admin | Admin | Registers agents, connects them through the gateway or SDK, sets action policies, continuity plans and fallback chains, mints keys |
| On-call Operator | Operator + Security admin | Approves or denies held actions and risky failovers, works the handoff queue, undoes automation, pulls the kill switch |
| Compliance Auditor | Auditor (read-only) | Reads every decision record, verifies the audit chain offline, exports evidence, confirms erasures |
| Head of AI | Economic buyer | Ships more autonomous workflows without more incidents |
| CISO | Approver / veto | Independent enforcement, isolation, no stored provider secrets, kill switch |
| Risk / compliance officer | Approver | Human oversight with approvals, evidence, legal holds, erasure certificates |

## 4. Core capabilities

1. **Registry.** Every agent, model, provider and owner, with risk tier, risk class and dependencies.
2. **Enforcement in the path.** All model traffic goes through the gateway; the SDK wraps tool calls. Policy is signed, so it can't be altered at the enforcement point.
3. **Action control: the Action Gate.** Allow, block or escalate a proposed action before it executes. The policy evaluator, enforcement in the gateway and SDK, and the approval workflow (held actions, four-eyes, deny on timeout, spending caps) and the console screens are built (section 12).
4. **Explainable health.** A 0–100 score per agent where every lost point names its cause.
5. **Leading indicators.** Trend and change-point statistics raise warnings before a failure. This is statistics today, not learned prediction (section 11).
6. **Automatic failover by risk tier.** Automatic where safe, approval-gated where not, with undo and a hold.
7. **Human handoff.** Unfinished work moves to a person as a structured packet, so nothing is lost or done twice.
8. **Kill switch.** Stop an agent, a provider or a tenant in seconds, including through an emergency key.
9. **Evidence.** A hash-chained, signed audit log, verifiable offline.
10. **Governance.** Legal holds, right-to-erasure with certificates, retention, per-tenant isolation.
11. **Plug-and-play monitoring.** One line of code, or none, instruments the model clients and agent frameworks an app already uses. Multi-agent systems report a run tree.
12. **Model drift detection.** Sibyl notices when a provider serves a different model than before, or when an agent's behaviour shifts against its own baseline. Plain statistics, watch-only.
13. **Sibyl Sentinel.** An optional advisory agent on the tenant's own model key. It explains and recommends. It never enforces (section 7a).
14. **External monitor agents.** Bring your own monitor: a customer's Claude, OpenAI or Gemini agent, an MCP assistant or a plain script reads the fleet and reports advisory findings next to Sentinel's. Monitors never enforce either (section 7b).

## 5. Functionality catalogue (built in Phase 1 unless marked)

### Registry
- Agents with owner, group, tier (1 critical, 2 important, 3 routine), declared risk class, tags and lifecycle.
- Versions, models and providers catalogue, dependency graph.
- Auto-discovery of unknown agents seen in traffic: a gateway header, a span attribute, or a handoff target inside a run tree. A discovered agent is recorded and watched, but it is never routed or failed over until an admin confirms it. The kill switch and quarantine still apply to it.
- Tier-1 agents must use agent-bound keys.

### Capture and privacy
- Capture mode per tenant: full, redacted or metadata only.
- Secrets scrubbed at three points (SDK, gateway, ingest), with 23 detectors that also catch JSON-escaped, URL-encoded and base64-wrapped secrets.
- Content encrypted per tenant (AES-256-GCM envelope encryption). Payloads expire after the tenant's retention period.

### Health and detection
- A score every 10 seconds per agent: 100 minus the penalty of each failing signal, with the arithmetic shown.
- Detected rules:
  - consecutive failures, error rate, latency, provider status, budget
  - refusals, truncation, malformed tool calls
  - missing heartbeat, tool loops
- Hysteresis, cooldowns and flap protection.
- Correlated failures on one provider collapse into one provider incident.

### Leading indicators (statistical)
- Error and latency trends (EWMA, CUSUM), rate-limit headroom running out, budget burn, provider status.
- Probability bands for 15 minutes, 1 hour and 24 hours, with contributing factors.
- In simulated ramp scenarios, warnings fired 5 to 39 minutes before the failure. A single weak signal never triggers automation.

### Continuity and failover
- Continuity plan per agent: recovery-time target (15 min / 1 h / 4 h by tier), recovery-point target, degraded mode, approval timeout.
- Fallback chain per agent: alternate model, alternate provider, backup agent, human queue. Chains are approved; four-eyes for tier 1.
- Failover rules:
  - **Detected failure:** automatic failover.
  - **Predicted failure:** automatic for tier 3, degrade-then-switch for tier 2, approval-only for tier 1.
- Undo restores the route and pauses automation for 30 minutes.
- The viability check refuses failover targets that share the failed provider.
- Per-agent breaker: two undone automated moves in 7 days switch the agent to approval-only.

### Human handoff
- A handoff packet holds the reason, the next action, the original input (marked untrusted), the steps done and pending, the side effects, and the cost so far.
- Operator queue actions: claim, extend, release, complete, return to agent.

### Kill switch and emergency access
- Agent, provider or tenant scope, enforced through signed policy at the gateway and SDK.
- A break-glass key can only stop agents, and works when single sign-on is down.

### Alerts and verdicts
- Closing an alert requires a verdict (true positive, false positive, unsure). Verdicts are the training labels for any future learned model.

### Audit and evidence
- Per-tenant hash chain with hourly signed anchors.
- Decision records show the rule, the score arithmetic and who approved.
- `sibyl audit verify` checks an exported chain offline.

### Governance
- Legal holds; crypto-shred erasure approved by a second owner, with a certificate.
- Personal data in user records is pseudonymised on erasure.
- A signed erasure ledger is re-applied after any backup restore.

### Identity and access
- OIDC single sign-on with step-up re-authentication.
- Seven roles, agent groups, and scoped API keys with expiry and rotation.

### Action Gate (built)
- Signed action policies per agent, group or tenant:
  - tool allowlists
  - argument limits (for example `amount <= 10000`, or a destination on an allowlist)
  - cumulative caps (for example 50,000 per day, or 20 refunds per minute)
  - dual control above a threshold
  - blocking personal data sent to external tools
- Enforced in two independent places: the gateway inspects tool calls the model proposes, and the SDK checks each tool just before it runs. Overhead is about 0.2 ms at p99.
- Outcomes:
  - **Allow:** the action runs.
  - **Block:** the action never runs, and the agent receives a clear refusal.
  - **Escalate:** the action is held until a person approves it. If nobody decides in time, it is denied.
- Fail-closed by design:
  - An unreadable or ambiguous argument never allows.
  - A missing policy for a sensitive tool blocks.
  - An evaluator error blocks.
- Every decision is recorded in the audit chain.
- Built for live use:
  - **On behalf of.** A held action records who the agent acts for (a Sibyl user or an external reference). The approver sees it.
  - **No self-approval.** The person who requested an action, or the person it acts for, cannot approve it.
  - **Decision history.** Each held action keeps its trail: requested, refused attempts, first approval under four-eyes, decision, expiry.
  - **Draft simulate.** Test a policy draft against a sample action before it is approved.
  - **Policy versions.** Every version of a policy keeps a stable identity, a change note and its approval trail. A new version cannot reset a cumulative cap.
  - **Approved holds count toward caps.** An approved escalation still adds to the running total.
  - **Framework tools.** Tools run by LangChain, the OpenAI Agents SDK or CrewAI go through the same check as `@sibyl.tool`.
  - **Audit filters** by time and agent, and a per-agent action summary (blocked, escalated, approved, denied, expired) for the fleet view.

### Plug-and-play monitoring (built)
- **One line:** `sibyl.instrument()` at the top of the entry point.
- **Zero code:** `sibyl-run app.py` starts the app unchanged, configured from environment variables. A configuration problem never stops the app from starting; it runs without monitoring and says why.
- **Model clients instrumented:** OpenAI (Chat Completions and Responses), Anthropic, Google Gen AI (Gemini). Sync, async and streaming.
- **Agent frameworks instrumented:** LangChain and LangGraph, OpenAI Agents SDK, CrewAI. Libraries that are not installed are skipped.
- **What every model call records:** provider, requested model, served model, provider fingerprint, tokens, latency, time to first token, finish reasons, refusals and proposed tool calls. Prompts and outputs leave the process only in full or redacted capture, after the secrets scrub.
- **Run trees:** multi-agent systems report the parent run, each step's index and agent-to-agent handoffs. The console draws the tree.
- **Discovery:** an agent first seen as a handoff target is registered as `discovered` (see Registry).

### Model drift detection (built)
- **Model identity drift.** The provider serves a different model, a new snapshot, or a new fingerprint compared with what the agent was served in its baseline. Raises `model_change`.
- **Behavioural drift.** Per agent and model, Sibyl compares the last hour with a frozen baseline: output tokens, input tokens, latency, refusal share, truncation share, tool-call rate, schema failures, error mix and tool sequences. Raises `silent_drift` after two drift verdicts in a row.
- **Plain statistics, no LLM.** Population Stability Index for numbers, Jensen–Shannon divergence for shares and mixes. A sampling noise floor is subtracted first, so small samples do not raise alarms. Every report shows each feature's value, floor, thresholds and sample counts.
- **Watch-only.** Drift alerts ask a person to look. Drift alone never fails over, holds an action or changes a policy, and it does not move the health score.
- **Reset baseline** after an intended change, with a reason; the reset is audited.
- **Limits:** thresholds are tunable per tenant through the API (no console screen yet). Reports are kept 30 days. Drift detects a change; it does not predict one.

### External monitor agents (built)
- Register a monitor, give it a key bound to the agent groups it may watch, and connect it through the Sibyl MCP server, signed webhooks or the REST API. Section 7b has the details.
- Findings appear beside Sentinel's and beside the held action, incident or agent they concern. People rate them.
- Advisory only: a monitor cannot allow, block, approve, fail over or change a policy.

## 6. Console experience

A calm, Apple-style interface: light and dark modes, glass only where layers overlap, colour only for meaning.

![Fleet overview during a provider outage](../../console/docs/screenshots/fleet-outage-light.png){width=full}

![Agent detail with the health score arithmetic](../../console/docs/screenshots/agent-light.png){width=full}

![Incident: failover timeline and recovery-time clock](../../console/docs/screenshots/incident-failover-light.png){width=full}

![Operator queue with a handoff packet](../../console/docs/screenshots/queue-light.png){width=full}

![Audit chain and decision record](../../console/docs/screenshots/audit-decision-light.png){width=full}

![Held actions: the queue with auto-deny countdowns, the tool, the agent and the rule that held each action](../../console/docs/screenshots/held-actions.png){width=full}

![Held action detail: the requester's own approval is refused (four-eyes), with scrubbed arguments, the reason it was held and the decision history](../../console/docs/screenshots/held-action-detail.png){width=full}

![Action policies grouped by tenant, group and agent, with version, approval state and four-eyes markers](../../console/docs/screenshots/action-policies.png){width=full}

![Policy editor: conditions, cumulative cap, data class, effect and reason, beside the read-only JSON](../../console/docs/screenshots/action-policy-editor.png){width=full}

![Simulate: an over-limit transfer is blocked by the transfer-limit rule on /amount](../../console/docs/screenshots/action-policy-simulate.png){width=full}

![Audit log filtered to Action Gate decisions](../../console/docs/screenshots/audit-actions.png){width=full}

![Onboarding: one line or zero code, per model client and framework](../../console/docs/screenshots/onboarding-instrument.png){width=full}

![Run tree of a claims run (demo data): steps, model calls with the served model, a handoff to an unconfirmed payout agent, and a transfer held for a person](../../console/docs/screenshots/run-tree.png){width=full}

![Discovered agents: found in telemetry, watched, not routed until an admin confirms them](../../console/docs/screenshots/discovered-agents.png){width=full}

![Model drift across the fleet: drift, watch, model changed and collecting baselines, with the watch-only notice](../../console/docs/screenshots/drift-fleet.png){width=full}

![Drift for one agent: each feature's value, noise floor, excess and verdict against the frozen baseline, and the served model](../../console/docs/screenshots/drift-agent.png){width=full}

![Sentinel findings: advisory explanations, reviews and drift flags, with severity and cost](../../console/docs/screenshots/sentinel-findings.png){width=full}

![A Sentinel review of a held payout: advice, reasoning, risks and provenance (provider, model, tokens, cost, prompt hash)](../../console/docs/screenshots/sentinel-finding.png){width=full}

![Sentinel setup: provider, model, write-only key, daily budget, sampling rate and tasks](../../console/docs/screenshots/sentinel-settings.png){width=full}

![Monitors: the registered external monitors with kind, state, watched groups, keys, rate limit and findings in the last 24 hours, under the advisory-only notice](../../console/docs/screenshots/monitors.png){width=full}

![Registering a monitor: the monitor key is shown once, with its scopes, rate limit and a ready-to-copy Python SDK or Claude Code (MCP) snippet](../../console/docs/screenshots/monitor-register.png){width=full}

![One monitor: watched groups, key scopes, rate limit, keys, signed webhooks with delivery health and a test button, and its recent findings](../../console/docs/screenshots/monitor-detail.png){width=full}

![Findings filtered to external monitors: each names the monitor, kind, severity, subject, model and confidence](../../console/docs/screenshots/findings-external.png){width=full}

![One external finding with its subject, advice and provenance](../../console/docs/screenshots/finding-external.png){width=full}

![A held payout with two advisory reviews side by side, Sentinel's and an external Claude monitor's; the approver still decides](../../console/docs/screenshots/held-action-monitors.png){width=full}

| Screen | What it shows | Who acts |
|---|---|---|
| Fleet | Every agent's health, tier and routing state; incident card with blast radius | Admin, Operator |
| Agent detail | Score arithmetic, risk bands, routing chain, continuity plan, sparklines, events | Admin, Operator |
| Incidents | Decisions needed first, failover timeline, recovery-time clock, handoff tasks | Operator (four-eyes) |
| Operator queue | Handoff packets with full context | Operator |
| Alerts | Open, unverdicted, resolved; provider incidents grouped | Operator |
| Audit | Hash chain, verify, decision records, export | Auditor |
| Onboarding | Capture policy, first key, gateway snippet, and one-line or zero-code instrumentation per client and framework | Admin |
| Runs | Every agent run, newest first, with status filters; each opens its run tree | Admin, Operator |
| Run tree | One run's agents, steps, model calls, tool calls and handoffs, metadata only | Admin, Operator |
| Discovered agents | Agents found in telemetry, waiting for confirmation | Admin |
| Model drift | Fleet drift summary; per agent, every feature's statistics, served model and fingerprint, reset baseline | Admin, Operator (read); Admin, Security admin (reset) |
| Sentinel | Advisory findings with provenance and feedback, from Sentinel and from external monitors; on-demand explain; setup | Operator, Auditor and admins read; Admin, Security admin set up and explain on demand |
| Monitors | External monitors: register, issue keys, add and test webhooks, pause, resume, revoke; each monitor's findings | Admin, Security admin (Operator and Auditor read) |
| Settings | API keys, tenant keys, members | Admin, Security admin |
| Kill switch | Scope, reason, typed confirmation, step-up | Admin, Security admin |
| Held actions | Actions waiting for a person, with countdown and the rule that held them; the detail view shows scrubbed arguments, who the agent acts for and the decision history | Operator, Admin (four-eyes, step-up for sensitive tools) |
| Action policies | Versioned policies, structured editor, simulate, approve and retire | Admin, Security admin |

## 7. Integration paths

| Path | Effort | What it gives |
|---|---|---|
| Gateway (OpenAI, Anthropic and Gemini protocols) | Change the base URL and the API key; add the agent header | Traffic visibility, inline fallback, failover, kill switch, limits, and action control on proposed tool calls (Action Gate). Adds about 0.2 ms at p99 |
| Python SDK (Apache-2.0) | `pip install sibyl-sdk`, then `sibyl.instrument()` or `sibyl-run app.py` | Model calls, agent runs and run trees, tool calls, handoffs, checkpoints, handoff packets, in-process kill switch, and pre-execution Action Gate checks on tools |
| OTLP ingest | Point an OpenTelemetry exporter at Sibyl | Reuse existing instrumentation |
| REST API | OpenAPI 3.1 contract, 186 operations | Automate everything; live event stream for people signed in to the console |
| External monitor | Register a monitor, then `sibyl-mcp`, a signed webhook, the SDK's `sibyl.monitor` client or plain REST | A customer's own Claude, OpenAI, Gemini or script-based monitor reads fleet metadata and posts advisory findings (section 7b) |

**Model providers.**
- **Gateway, built:** the OpenAI-compatible API (OpenAI, Azure OpenAI, Ollama, vLLM and any OpenAI-compatible endpoint), the native Anthropic Messages API and the native Gemini `generateContent` API, all with streaming. All three get the same kill switch, limits, routing and Action Gate.
- **Fallback stays inside one protocol.** An Anthropic-protocol call falls back only to Anthropic-protocol targets, and so on. Sibyl does not translate between protocols. A route with no same-protocol target is refused when it is configured.
- **SDK, built:** instrumentation for the OpenAI, Anthropic and Google Gen AI client libraries.

**Agent frameworks.**
- **Built connectors:** LangChain and LangGraph, OpenAI Agents SDK, CrewAI. Each reports runs, steps, tools and handoffs, and sends framework tools through the Action Gate.
- **Planned connectors:** Google Agent Development Kit, Microsoft AutoGen, and others on demand.
- **Any framework today:** frameworks that emit OpenTelemetry GenAI spans can report through OTLP ingest, and any framework can route its model calls through the gateway.

## 7a. Sibyl Sentinel: an advisory monitoring agent (built)

An optional internal agent that customers switch on to watch their other agents and frameworks. It runs on the customer's own Anthropic (Claude), OpenAI or Google Gemini API key through one provider-neutral adapter. Sentinel is advisory: it never enforces.

**What it does:**
- **Explains incidents in plain language:** what failed, why, what Sibyl did, what to check.
- **Reviews held actions:** attaches a recommendation and its reasoning for the human approver.
- **Flags semantic anomalies that rules cannot see:** an agent drifting from its declared purpose, a tool sequence that looks like prompt injection, an answer that contradicts policy.
- **Summarises fleet health** for operators and managers.

- **Explains on demand:** an Admin or Security admin can ask for an explanation of an incident or a held action.

Findings appear in the console. A finding can open a watch-only `sentinel_finding` alert. People rate each finding as useful, not useful or wrong.

**What it never does.** Sentinel is advisory. It cannot allow, block, approve, fail over or change a policy. It never calls an enforcement route. Tests check that a reviewed hold stays pending and that a Sentinel alert never starts a failover, even when the agent is failing. Enforcement stays deterministic, signed and auditable. This keeps "an agent watching agents" out of the safety-critical path, while still using language models where they add value: judgement and explanation.

**Controls:**
- **Opt-in:** per tenant, set up by an Admin or Security admin.
- **Key:** write-only. It is sealed in the tenant vault and never shown again, logged or audited.
- **Network:** calls go only to the provider's API host (or a vetted custom endpoint), over verified TLS.
- **Data:** respects the tenant's capture mode. Metadata-only tenants send no prompts or outputs.
- **Untrusted input:** agent data is passed as quoted evidence, never as instructions. Answers are structured and validated before they are stored.
- **Cost:** a daily budget, reserved before each call so it is never overshot, and a sampling rate for drift reviews.
- **Audit:** every finding records the provider, the model, a hash of the prompt, the tokens and the cost.
- **Quality:** its behaviour is checked on the harness (scenario S-33: never enforces, keeps to budget and capture mode); its judgement is not yet measured. Treat findings as a second opinion, not a verdict.

## 7b. External monitor agents: bring your own monitor (built)

Many customers already have an agent they trust to review other agents: a Claude assistant their operations team uses every day, an OpenAI Agents SDK app, a Gemini pipeline, or a script that pages the on-call. Sibyl lets any of them watch the fleet and report what it sees. Sentinel is the built-in monitor; external monitors are first-class peers beside it.

**Who it is for.**
- **Platform Admins** who want their own reviewer, prompt and model rather than Sentinel's.
- **Security and risk teams** that already run a review agent and want it to see held actions and incidents.
- **Operations teams** that want alerts, incidents and held actions pushed into their own tooling (paging, chat, ticketing) as signed webhooks.

**How a customer plugs one in.**

1. **Register** the monitor in the console (**Monitors → Register monitor**) or with `POST /monitors`: a name, a kind (`mcp`, `webhook` or `api`), an owner, the agent groups it may watch (or all of them) and a findings rate limit (60 a minute by default). Registration issues a **monitor key**, shown once.
2. **Connect** it, whichever way suits the agent:

| Monitor | How it connects |
|---|---|
| Claude (Desktop, Claude Code, the Claude Agent SDK) | The Sibyl MCP server, `sibyl-mcp`, over stdio; one entry in the MCP configuration |
| OpenAI Agents SDK | `sibyl-mcp` over stdio, as an MCP tool server |
| Gemini, or any Python agent | The SDK's monitor client, `sibyl.monitor.Client` |
| Any MCP-capable assistant | `sibyl-mcp` over stdio, or streamable HTTP on the local machine |
| Paging, chat or ticketing tools | Signed webhooks for alert, incident, held-action, drift and failed-run events |
| A plain script or rules job | The REST API, or the same SDK client |

3. **Observe.** The monitor reads agents, fleet and agent health, runs and run trees, drift, alerts, incidents, held actions and findings. `sibyl-mcp` exposes this as 13 tools, including `list_held_actions`, `get_drift` and `list_runs`.
4. **Report.** The monitor posts **findings** in the same shape as Sentinel's (an explanation, a review of a held action, an anomaly, a safety, quality or cost observation, a fleet summary), with its own provider, model and confidence. A finding about a held action attaches advice (`approve`, `deny` or `needs_more_info`) for the approver. A critical finding about an agent can open a watch-only `external_finding` alert.

Ready-made examples ship in the repository for Claude over MCP, the OpenAI Agents SDK, Gemini, a webhook receiver and a rules-only monitor.

**The advisory guarantee.** A monitor is advisory, exactly like Sentinel:
- It cannot allow, block, approve, deny, fail over, quarantine, kill or change a policy. Its key holds two scopes, `monitor:read` and `findings:write`, and nothing else, and an API key can use only the scopes a route lists for keys. No enforcement route lists either scope.
- Its alerts are watch-only: they ask a person to look and never start a failover.
- Its advice on a held action is shown to the approver; the hold stays pending until a person or the timeout decides.
- Enforcement stays deterministic, signed and auditable. A wrong or manipulated monitor costs a bad recommendation, never an action.

**Watched groups.** A monitor sees only the agents in the groups it watches (child groups included). Anything outside them, including the fact that it exists, answers "not found". Fleet-wide findings and events with no agent need a monitor that watches all groups.

**Metadata only.** Monitor reads return metadata: names, states, scores, timings, counts, tool names, rules. They never return payload content or held-action arguments, whatever the tenant's capture mode. Everything an agent wrote (names, summaries, tool names, errors) is marked as untrusted data, and the MCP server tells the model never to follow instructions found in it.

**Controls.**
- **Keys:** stored as hashes, shown once, rotated and revoked like any other API key. Revoking a monitor revokes its keys and disables its webhooks.
- **Pause:** a paused monitor cannot submit findings; its webhook deliveries wait until it is resumed.
- **Rate limit:** per monitor, 1 to 600 findings a minute.
- **Webhooks:** https only, to public addresses checked at connect time, signed with HMAC-SHA256 and a timestamp, retried with backoff, then dead-lettered. A deployment can restrict webhook hosts to an allowlist.
- **Audit:** registration, updates, revocation, every finding, every rating, webhook tests and dead deliveries are in the audit chain.

**Quality.** Sibyl does not measure an external monitor's quality. People rate each finding as useful, not useful or wrong, so a team can judge a monitor over time.

## 7c. Two ways to run: demo and real (built)

| | Demo | Real deployment |
|---|---|---|
| What you get | The console with dummy data and a scripted provider-outage scenario; every screen clickable, monitors included | The full stack for your own agents: Postgres 17, API, ingest, worker, gateway, console, Caddy TLS and OIDC sign-in; no simulator |
| Needs | Node.js only | Docker with Compose 2.24.4 or later |
| In the browser | [Open in Codespaces (demo)](https://codespaces.new/MK-JKC/sibyl?devcontainer_path=.devcontainer/demo/devcontainer.json) | [Open in Codespaces (real)](https://codespaces.new/MK-JKC/sibyl?devcontainer_path=.devcontainer/real/devcontainer.json) |
| On your machine | `make demo` | `make up` |
| First run | A minute or two | About 10 minutes; it bootstraps the first workspace and its Platform Admin |

- **Demo.** For a first look and for sales demos. Nothing to configure, no external services. A purple **Demo data** chip marks every screen.
- **Real.** For real agents. `make up` generates every secret, builds or pulls the images, applies migrations, creates the first workspace and admin, and prints the URLs. Then connect an agent through the gateway, `sibyl.instrument()` or `sibyl-run`, approve a first Action Gate policy, switch on Sentinel and register an external monitor. `docs/setup/SETUP.md` covers prerequisites per operating system, corporate TLS-inspection proxies and production hardening (your own OIDC provider, certificates, backups, upgrades).
- **Release images.** Version 1.0.0 is published as multi-arch images on GitHub Container Registry; `SIBYL_IMAGE_TAG=1.0.0 make up` runs them instead of local builds.
- **Access.** A public demo runs at https://sibyl-demo.onrender.com (dummy data, shared by every visitor). The repository is public, so both Codespaces links work for anyone with a GitHub account.

## 8. Security, privacy and compliance

- **Tenant isolation:** row-level security on every tenant table, tested for every table and role.
- **Secrets:** provider keys pass through and are not stored for the primary call. Fallback keys are vaulted. API keys are stored as salted hashes. Each service receives only its own secrets.
- **Signed policy:** enforcement points act only on Ed25519-signed snapshots, with key rotation as a signed chain.
- **Network safety:** outbound URLs are allowlisted and checked at connect time, including monitor webhooks.
- **Outside monitors:** monitor keys are bound to one monitor and its watched groups, read metadata only and can reach no enforcement route.
- **Evidence:** hash chain, signed anchors, offline verification.
- **Licences:** permissive dependencies only; licence gate in CI.
- **Compliance mapping:** supports human-oversight, inventory and record-keeping duties (EU AI Act, NIST AI RMF, ISO/IEC 42001). No formal attestation yet; an external security assessment comes before the first paid tenant.

## 9. Architecture and deployment

Stateless services (gateway, ingest, API, worker, console) around one Postgres database and a blob store. The real deployment runs with Docker Compose in one command (`make up`), behind Caddy for TLS, with the bundled sign-in for a first install or the customer's own OIDC provider for production. Release 1.0.0 ships as multi-arch images on GitHub Container Registry, built by a GitHub Actions release workflow; GitHub Actions CI runs lint, types, tests against Postgres and the console checks on every change. External monitors need no extra service: the MCP server runs next to the customer's assistant, and webhooks are sent by the existing worker. Phase 2 adds a Helm chart, managed Postgres and S3-compatible storage. Design partner #1 self-hosts in their own cloud.

## 10. Recovery: what Sibyl owns and what it doesn't

| Sibyl owns | The customer's infrastructure owns |
|---|---|
| Which model, provider or agent a call goes to | Business transaction integrity |
| Stopping traffic (kill switch, quarantine) | Idempotency of their tools and APIs |
| Handing unfinished work to a person, with context | Re-running or compensating side effects |
| Evidence of every decision | Their own data stores and backups |

- **Shared dependencies.** If every alternative depends on the same failed API, switching achieves nothing. Sibyl models dependencies and refuses targets that share the failure, and sends the work to a person or a degraded mode instead.
- **Duplicate actions.** A task with recorded external side effects is never automatically resumed. A person decides, with the side-effect ledger in front of them. *(Rule recorded; enforcement is backlog item A-4.)*

## 11. Honest assessment: questions we must answer

These are the hardest questions about the product, with our current answers.

1. **Is this observability or prediction?**
   - Today it is governed reliability plus statistical early warning, not learned prediction.
   - What observability tools lack, and Sibyl has: acting under governance (failover, approvals, undo, handoff, kill switch) and verifiable evidence.
   - The learned model ships only if it measurably beats the rules on our scenario harness and on each customer's own labelled alerts.
2. **What is the technical differentiation?**
   - No LLM sits in the decision path.
   - **Data:** comes from in-path enforcement points, the gateway and the SDK.
   - **Detection:** deterministic rules plus change detection, every score explained.
   - **Intervention:** made safe by signed policy, risk tiers, approvals, undo and a kill switch.
   - **Learning:** improves per-tenant calibration from operator verdicts, measured by precision, recall, lead time and false-failover rate.
3. **How much recovery do we own?** The boundary in section 10.
4. **Is there a data moat?**
   - Not yet. Execution histories alone are not intelligence.
   - Candidates: per-tenant verdict-labelled incident data (value shown as measured lift over time), the scenario library, and policy templates.
   - Cross-customer learning needs opt-in aggregate priors or federated training, plus contract terms. Neither is built, so we do not claim a moat.
5. **Failure versus forbidden action.**
   - Detecting that an agent is about to fail is useful.
   - Detecting that a healthy agent is about to do something it is not authorised to do is the bigger problem, and the one that blocks autonomy.
   - That is the Action Gate (section 12).
6. **Where is our advantage?**
   - **Enforcement in the request path:** a one-URL change, no code change.
   - **Governance that holds up in an audit.**
   - **Execution:** easy deployment and safe defaults.
   - We claim prediction only where we measure it.

7. **Isn't an external monitor just another "agent watching agents"?**
   - Yes, and that is why it is advisory. Monitors bring judgement the customer already trusts; they never decide.
   - Every allow, block, escalate and failover stays with deterministic, signed policy. A monitor's key cannot reach an enforcement route.

**The deciding question:** are we telling companies when agents might fail, or building infrastructure that lets them safely give agents more autonomy? **The latter.** Reliability is part of it, but safe autonomy is the thesis.

### Known limits (release 1.0.0)

State these whenever the matching capability is described.

| Area | Limit |
|---|---|
| Prediction | Early warning is statistics, measured in simulation only; no learned model yet |
| Drift | Detects a change after it happens; thresholds tunable per tenant by API only; no console screen yet |
| Harness | 20 scenarios pass; 12 wait on design rulings, unbuilt features or one known coverage gap (B-10) |
| Sentinel | Behaviour checked on the harness (S-33); judgement not yet measured |
| External monitors | Reads are metadata only: there is no path yet for a monitor to read prompts, outputs or held-action arguments, even where the capture mode keeps them |
| External monitors | No live event stream for monitor keys; a monitor polls the API or receives webhooks |
| External monitors | `run.failed` is the only run event a webhook can carry |
| External monitors | A monitor sees other monitors' findings about agents in its watched groups |
| External monitors | The SDK monitor client accepts `http://` URLs, so a misconfigured client could send its key unencrypted; use `https://` |
| External monitors | A paused monitor's webhook deliveries wait until it is resumed; they are not dropped |
| External monitors | Sibyl does not measure a monitor's quality; people rate findings |
| Packages | `sibyl-sdk` and `sibyl-mcp` are not on PyPI yet; install them from the repository |
| Public demo | One shared instance with dummy data; it restarts after 15 idle minutes on the free plan |
| Security | No external security assessment yet; treat a deployment as pre-production |
| Deployment | One host; logical backups; no Helm chart or point-in-time recovery yet |

## 12. Roadmap

| Phase | Theme | Contents | Gate to the next phase |
|---|---|---|---|
| 1 (built) | Governed reliability | Registry, gateway, SDK, ingest, health, leading indicators, failover with approvals, handoff, kill switch, audit, erasure, console, harness | Demo end to end; critical harness gates green |
| 1.5 | Action Gate + close the cuts | **Action Gate:** evaluator, gateway/SDK enforcement, approval routes, held-action queue, console screens, the never-auto-resume guard and the harness scenarios built; AI bill of materials; console editors; canary failback | Zero unauthorised actions executed in the harness; restore drill; external security assessment |
| 1.5 (wave 3, built) | Plug-and-play monitoring, drift and Sentinel | `sibyl.instrument()` and `sibyl-run`; OpenAI, Anthropic and Google Gen AI clients; LangChain/LangGraph, OpenAI Agents SDK and CrewAI connectors; run trees and auto-discovery; native Anthropic and Gemini at the gateway; model drift detection (watch-only); **Sibyl Sentinel** (advisory); Action Gate live in the console | Harness lane: A-5 scenarios, silent model swap scenario, outage detection-gap fix (in progress); Sentinel quality measured on the harness |
| 1.0 (wave 4, built) | Open monitoring ecosystem and release | **External monitor agents** (registration, monitor-bound keys, `sibyl-mcp`, signed webhooks, external findings beside Sentinel's, the SDK monitor client, examples for Claude, OpenAI, Gemini, webhooks and rules); a runs list; demo and real deployments with Codespaces links; GitHub Actions CI and release images on GHCR; tag `v1.0.0`; tenant-tunable drift thresholds (API); harness gate suite running with 20 scenarios passing; Sentinel behaviour scenario S-33; CI under 10 minutes | Design-partner pilot; external security assessment before the first paid tenant |
| 2 | First design partner | Cloud deployment, notifications, TypeScript SDK, Google ADK and AutoGen connectors, tenant-tunable drift thresholds, a content path for monitors under the capture mode, a live event stream for monitor keys, learned model in shadow, trajectory-risk research | Pilot success criteria; measured lift (or not) of learned models over rules |
| 3 | Sellable product | Residency, SOC 2 readiness, billing, compliance packs, ITSM integrations | — |

**Action Gate backlog (smallest differentiated product):**

| # | Item | Status |
|---|---|---|
| A-1 | Action policy in signed snapshots: tool allowlists, argument predicates (e.g. `amount <= 10000`, `destination in allowlist`), cumulative caps, dual control above a threshold, data-classification rules | Built |
| A-2 | Enforcement at the gateway (tool calls proposed in model responses) and in the SDK (`@sibyl.tool` before execution) | Built |
| A-3 | Escalation: the action is held, a person approves or denies it in the queue, a timeout defaults to deny, and every decision is audited | Built |
| A-4 | Never auto-resume a task with recorded external side effects | Built |
| A-5 | Harness scenarios: over-limit transfer, data exfiltration via a tool, injection-driven action, cumulative cap breach | Built (merged; full gate suite not yet green, see section 11) |
| A-6 | Console: action policies, held actions, decision records, on the live API with end-to-end and accessibility tests | Built |

## 13. Packaging, metrics and messaging

Pricing is a Phase 3 hypothesis, not validated with customers.

| Package | For | Includes |
|---|---|---|
| Developer (free) | Evaluation | SDK, gateway, registry, health, single tenant |
| Team | First production agents | Action Gate, failover, handoff queue, audit export |
| Business | Several teams and providers | Approvals and four-eyes, leading indicators, legal holds, erasure certificates, SSO |
| Enterprise | Regulated firms | Compliance packs, long audit retention, residency, support SLA |

Pricing shape: a platform fee plus a per-governed-agent charge weighted by tier. The SDK and the kill switch are never paywalled.

**North-star metric.** Governed autonomy: the share of production agent actions that pass through Sibyl's enforcement points under a declared, approved policy.

**Supporting metrics.**
- unauthorised actions blocked or escalated
- time to detect
- failovers within recovery target
- false-failover rate
- tasks completed despite agent failure
- verdict coverage

**Messaging.**
- **One-liner:** Give your AI agents more autonomy, with guardrails, continuity and proof.
- **Head of AI:** ship autonomous workflows without more incidents.
- **CISO:** an independent control layer the agent cannot talk its way past.
- **Risk and compliance:** human oversight where it matters, evidence for every decision.
- **Engineers:** change one URL, or add one line, to start; tools are gated where they run.
- **Teams with their own review agent:** bring your Claude, OpenAI or Gemini monitor; it advises, Sibyl enforces.

**Claims to avoid** until measured: "predictive intelligence", "learns from your data", "data moat", "predicts model drift" (drift detection detects a change after it happens), "Sentinel catches attacks" (its quality is not yet measured), "your monitor agent can stop your other agents" (monitors are advisory), "monitors see everything" (metadata only, within their watched groups), "try it on your own data online" (the public demo is shared dummy data).

**Glossary.**

| Term | Meaning |
|---|---|
| Agent | An AI workflow Sibyl governs |
| Tier | Business criticality, 1 to 3 |
| Action policy | What an agent may do, enforced before it acts |
| Continuity plan | Recovery targets and what to do on failure |
| Fallback chain | Ordered alternatives |
| Handoff packet | Structured hand-over of unfinished work |
| Hold | A pause on automation after an undo |
| Verdict | An operator's judgement on an alert |
| Anchor | A signed checkpoint of the audit chain |
| Break-glass key | An emergency key that can only stop agents |
| Run tree | One multi-agent run: parent run, steps, handoffs |
| Discovered agent | An agent seen in telemetry but not yet confirmed by an admin; never routed |
| Baseline | An agent's frozen reference behaviour for one model, used by drift detection |
| Sentinel finding | An advisory explanation, review or flag written by Sibyl Sentinel |
| External monitor | An outside agent or script registered to watch some or all agent groups and report advisory findings |
| Monitor key | An API key bound to one monitor, holding only `monitor:read` and `findings:write` |
| External finding | An advisory finding submitted by an external monitor, shown beside Sentinel's |
| Webhook | A signed HTTPS delivery of an alert, incident, held-action, drift or failed-run event to a monitor's endpoint |

See `docs/strategy/TECHNICAL-THESIS.md` for the technical reasoning behind sections 10 to 12.
