# Executive summary

Sibyl is infrastructure that lets companies give AI agents more autonomy safely. It decides what an agent is allowed to do before the agent acts, keeps agents working when models and providers fail, and records every decision as evidence an auditor can verify offline.

Status as of 2026-10-14, release 1.0.0. This document separates three kinds of statement, and sales must keep them separate too:

- **Built.** Registry, a gateway that speaks the OpenAI, Anthropic and Gemini APIs, a Python SDK that instruments an agent in one line or none, OTLP ingest, explainable health, statistical leading indicators, tier-gated failover with approvals and undo, human handoff, kill switch, hash-chained audit, erasure, the console and the `sibyl-sim` provider doubles. Also built: the **Action Gate** (pre-execution allow, block or escalate on tool calls, from signed policy, at the gateway and in the SDK, with live console screens), **model drift detection** (watch-only statistics), **Sibyl Sentinel** (an advisory agent on the customer's own model key), **external monitor agents** (the customer's own Claude, OpenAI, Gemini, MCP or script-based monitors, advisory only), and two ways to run: a **demo** with dummy data and a **real deployment** for real agents, each with a Codespaces link.
- **Harness.** The Action Gate scenarios pass with no unauthorised action executed; 20 scenarios pass, including the Action Gate scenarios S-29 (approval and timeout re-run) and S-30, the silent model swap S-31, the outage reproduction S-32 and the new Sentinel scenario S-33; 12 do not yet pass, 11 of them waiting on a design ruling or an unbuilt feature and one a known coverage gap (B-10). Sentinel's judgement is not yet measured.
- **Research or hypothesis.** Learned prediction, cross-customer learning, pricing. None of these is claimed as fact.

**The pitch in one paragraph.** Monitoring catches an agent that breaks. It does not catch a healthy agent about to transfer $100,000 when it is authorised for $10,000, because every call in that sequence succeeds. That second failure class is what stops companies from giving agents real authority. Sibyl sits in the request path, evaluates each proposed action against signed policy, holds risky actions for a human, and proves what happened. When the agent itself fails, Sibyl moves the work to an approved alternative or to a person, with undo and a kill switch.

**Bring your own monitor.** Prospects increasingly already have an agent they trust to review other agents. Sibyl lets them plug it in: their Claude, OpenAI or Gemini agent, an MCP assistant or a plain script reads the fleet and posts findings next to Sibyl's own Sentinel. It advises; Sibyl's signed, deterministic policy still decides. That turns "we already have an AI reviewer" from an objection into an integration.

**Who we sell to first.** Regulated or quasi-regulated companies of 500 to 5,000 people running 10 to 60 production agent workflows on two or more model providers, with a human exceptions team already in place. The Head of AI buys, the Platform Admin adopts, the CISO approves or vetoes, and risk and compliance co-sign.

**What we are honest about.** Sibyl is not a prediction engine today; its early warnings are statistics, measured in simulation only. Drift detection detects a silent model swap or a behaviour shift after it happens; it does not predict one. It has no data moat. It does not own the integrity of the customer's business transactions. Its advantage is integration in the request path, governance that survives an audit, and execution.

**The commercial goal for the next two quarters** is one design partner in a 90-day pilot with written success criteria, followed by a signed intent to convert. The budget for finding that partner is zero.

# Market problem: agents failing, and healthy agents doing forbidden things

## Agents now do work with consequences

Companies are moving agents from drafting text to taking actions: issuing refunds, moving money, approving claims, changing orders, emailing customers. Two different things go wrong, and in most organisations nobody owns either.

## Problem one: the agent fails

| Failure | What usually happens today |
|---|---|
| Provider outage or rate limit | Someone notices, edits configuration, redeploys |
| Silent quality loss (refusals, truncation, malformed tool calls) | Found days later through complaints |
| The provider serves a new model snapshot, or the agent's behaviour shifts with no error | Nobody notices until outputs look wrong |
| Runaway cost or tool loops | Found on the invoice |
| Work abandoned mid-task | Lost, or done twice when someone retries |

Observability tools help here, but they stop at the alert. Someone still has to decide what to do, at whatever hour it happens.

## Problem two: the agent works and does something it should not

| Example | Why monitoring misses it |
|---|---|
| Transfers $100,000 when authorised for $10,000 | Every call succeeded; nothing looks unhealthy |
| Sends customer data to an external tool after a prompt injection | Normal latency, normal token counts |
| Issues 40 refunds in a minute, each individually valid | No single call breaks a rule |

This is the larger risk. It is also the one that blocks adoption: a risk committee will not approve an autonomous refund agent because a dashboard shows it is fast. It approves when there is an independent limit the agent cannot exceed, a person on the high-value cases, and a record of every decision.

## Why existing controls do not close the gap

- **Prompt instructions** ("never transfer more than $10,000") are advice to the model, not enforcement. A prompt injection or a model change can override them.
- **Limits in the agent's own code** are owned by the same team that ships the agent, change with every release, and are invisible to audit.
- **Limits in the downstream system** are the strongest control where they exist, but most internal APIs were built for trusted human operators, not for an automated caller that can make forty requests a minute.

Sibyl adds a control point that is independent of the model and of the agent's code, sits before execution, and produces evidence.

# Ideal customer profile and buyer map

## Ideal customer profile

| Attribute | Target | Why it matters |
|---|---|---|
| Industry | Financial services (lending, insurance, payments, broking), healthtech operations, BPO and customer-experience outsourcing, logistics with customer-facing agents | Real cost of a wrong or stuck action; existing exceptions teams; audits that ask about AI |
| Size | 500 to 5,000 employees; AI platform team of 2 to 10 | Large enough to have production agents and an audit function; small enough for the Head of AI to sign a pilot |
| Estate | 10 to 60 production agent workflows; at least 3 tier-1 (money- or customer-facing); at least 2 model providers | Enough traffic for scores to mean something; tier 1 makes approvals relevant; two providers make failover real |
| Stack fit | OpenAI, Anthropic or Gemini clients that can point at a new base URL; Python for the tier-1 agents, ideally on LangChain/LangGraph, the OpenAI Agents SDK or CrewAI | Matches the built integration paths |
| Pain | A provider outage, rate-limit storm, model deprecation or near-miss action in the last 6 months that they can describe | The demo must land on a memory, not a hypothesis |
| Pressure | Operational-resilience or AI-governance expectations, or enterprise clients sending AI questionnaires | Gives the risk officer a reason to co-sponsor |
| Deployment | Willing to self-host in their own cloud account | Shortens their security review; keeps their data in their network |

**Disqualifiers.** The estate is mainly closed SaaS agents with no call path to intercept. SOC 2 Type II is required before any pilot. 24/7 vendor support is required. They want Sibyl to replace their tracing or evaluation tool.

## Buyer map

| Role | Position in the deal | What they want | Objection they raise | Our answer |
|---|---|---|---|---|
| Head of AI | Economic buyer, usually the champion | Ship more autonomous workflows without more incidents; a defensible answer to the board | "Integration will cost my team a quarter." | One base-URL change puts the gateway in front of an agent. In Python, one line (`sibyl.instrument()`) or none (`sibyl-run app.py`) instruments the clients and frameworks already in use. Pilot week one is observe-only. |
| Platform Admin | User; decides adoption | Zero-code onboarding, low overhead, no false failovers, undo | "Another proxy in my hot path." | Measured overhead is about 0.2 ms at p99 in the CI benchmark. Policy is a local signed snapshot, so there is no control-plane call on the hot path. Each agent declares fail-open or fail-closed. The eject path is the same two-line change in reverse. |
| On-call Operator | User | One queue, a packet they can act on in minutes | "More alerts, more noise." | Correlated failures collapse into one provider incident. Held actions arrive with the rule, the arguments and the reason. Handoff packets carry the original input, steps done and side effects. |
| Compliance Auditor | User, read-only | Evidence they can export without engineering help | "Logs I cannot read are not evidence." | Each decision record shows the rule, the arithmetic and the approver. `sibyl audit verify` checks the exported chain offline. |
| CISO | Approver with veto | Independent enforcement, isolation, credential custody, kill switch | "You are a new vendor with no attestation." | Self-hosted in their account. Row-level security tested on every table and role. Provider keys pass through and are not stored for the primary call. No SOC 2 yet; an external security assessment comes before the first paid tenant. |
| Risk or compliance officer | Approver or co-sponsor | Human oversight where it matters, retention, framework mapping | "Is this a compliance product?" | It supports human-oversight, inventory and record-keeping duties under NIST AI RMF, ISO/IEC 42001 and the EU AI Act. It does not certify compliance. |
| Procurement and legal | Process owner | Contracting entity, DPA, exit terms | "Who are we contracting with, and what happens when we leave?" | Pilot agreement with exit terms; full audit and payload export plus a crypto-shred erasure certificate on exit. (Entity and IP ownership must be settled before outreach; see the launch checklist.) |

The central risk is the split: the Platform Admin decides whether Sibyl is adopted, the Head of AI whether it is bought, and the CISO whether it is allowed. Every deal needs all three.

# Positioning and messaging

## One-liner

**Give your AI agents more autonomy, with guardrails, continuity and proof.**

Category line: the control layer for the AI workforce.

## Three pillars

| Pillar | Claim | Status |
|---|---|---|
| **Control** | Sibyl decides what an agent may do before it acts: allow, block, or hold for a person. Policy is signed and enforced outside the agent. | Built: enforcement points, signed policy, the Action Gate, approvals, four-eyes and kill switch. Harness scenarios are merged; the full gate suite is not yet green. |
| **Continuity** | When a model or provider fails, work moves to an approved alternative or to a person, automatically where safe and with approval where not. Sibyl also notices when a provider silently changes the model. | Built. Drift detection is watch-only: it alerts a person and never moves traffic on its own. |
| **Proof** | Every decision, approval and override is in a hash-chained, signed log that verifies offline. | Built. |

## Messaging by persona

| Persona | Message | Supporting line |
|---|---|---|
| Head of AI | Ship autonomous workflows without more incidents. | Raise an agent's authority one policy at a time, with a person on the cases that matter. |
| CISO | An independent control layer the agent cannot talk its way past. | No model in the decision path; signed policy at two enforcement points; a kill switch that works when SSO is down. |
| Risk and compliance | Human oversight where it matters, evidence for every decision. | Approvals, holds, legal holds and erasure certificates, all exportable. |
| Platform Admin | Change one URL, or add one line, to start. | Works with the OpenAI, Anthropic and Gemini clients and with LangChain/LangGraph, the OpenAI Agents SDK and CrewAI. Undo every automated move; automation pauses for 30 minutes after an undo. Plug in your own monitor agent with one MCP entry or one key. |
| On-call Operator | One queue with the context to finish the job. | Packets with input, steps done, side effects and the next action. |

## Proof points tied to built capabilities

Use only these in external material. Each maps to something a prospect can see or test.

| Proof point | Evidence |
|---|---|
| One-URL onboarding | Demo segment: an OpenAI client changes `base_url` and appears in the registry within seconds |
| One-line or zero-code monitoring | `sibyl.instrument()` or `sibyl-run app.py`; the console onboarding shows the snippet per client and framework |
| Native Anthropic and Gemini | Anthropic and Gemini SDKs change only base URL and key; the same kill switch, limits, routing and Action Gate apply. Fallback stays inside one protocol |
| Multi-agent visibility | A run tree shows each agent, step, model call, tool call and handoff; an unknown agent appears as discovered and is never routed until confirmed |
| Action control | Demo: an over-limit payout blocked before it runs; a mid-size payout held for two people; self-approval refused |
| Silent model swap detected | Demo: a new model snapshot raises `model_change`; a behaviour shift raises `silent_drift` after two drift verdicts; each report shows its per-feature numbers |
| Advisory explanations | Demo: Sentinel explains a failover and reviews a held payout, with model, tokens, cost and prompt hash on every finding |
| Bring your own monitor | Demo: the Monitors page lists a Claude reviewer over MCP, a webhook bridge to paging and a script; the held payout shows Sentinel's and the Claude monitor's reviews side by side, and the approver still decides. Live: `examples/monitors/` connects Claude, the OpenAI Agents SDK, Gemini, a webhook receiver and a rules script |
| Try it yourself | The public demo (https://sibyl-demo.onrender.com), the demo and real Codespaces links, or `make demo` and `make up` locally |
| Low overhead | Gateway CI benchmark, about 0.2 ms added at p99 |
| Explainable decisions | Every health score shows `100 minus penalties` with each factor named |
| One incident, not seven | Correlated failures on a provider collapse into one provider incident |
| Governed failover | Automatic on detected failure; tier-1 backup-agent moves need approval; self-approval refused |
| Undo and hold | Undo restores the route and pauses automation for 30 minutes |
| Kill switch | Agent, provider or tenant scope; enforced at gateway and SDK; break-glass key works without SSO |
| Shared-dependency safety | Failover viability check refuses targets that share the failed provider |
| Human handoff | Structured packet with input marked untrusted, steps, side effects and cost |
| Tamper evidence | `sibyl audit verify` passes on the export and fails on a one-byte edit |
| Isolation | Second tenant stays silent through the outage; RLS tests per table and role |
| Early warning (simulation only) | In simulated ramps, warnings fired 5 to 39 minutes before failure |
| Nightly gate report | Scenario harness across seeds, with CRITICAL gates at 100 percent (scenario runner still in the harness lane) |

The harness proof point for the Action Gate ("zero unauthorised actions executed across the harness scenarios") is added only when the A-5 gate is green. Drift detection and Sentinel have no harness numbers yet either; do not quote any. External monitors are never measured by Sibyl; there is no quality figure to quote for them.

## Bring your own monitor agents

**The positioning.** Sibyl is an open monitoring ecosystem with a closed enforcement core. Any agent the customer trusts can watch the fleet; only Sibyl's signed, deterministic policy can act.

| What the prospect has | How it plugs in | What it can do | What it cannot do |
|---|---|---|---|
| A Claude assistant (Desktop, Claude Code, Agent SDK) | `sibyl-mcp`, one MCP entry | Read agents, health, runs, drift, alerts, incidents and held actions; post findings and held-action advice | Allow, block, approve, fail over, change policy |
| An OpenAI Agents SDK or Gemini app | `sibyl-mcp`, or the SDK's `sibyl.monitor` client | The same | The same |
| Paging, chat or ticketing tools | Signed webhooks for alert, incident, held-action, drift and failed-run events | Receive events and post findings back | The same |
| A rules script or cron job | REST API with a monitor key | The same | The same |

**What to say.** "Bring the reviewer you already trust. Register it in the console, give it a key that can only read metadata and post advice, and its findings appear next to Sentinel's, on the very held action or incident they concern. It never decides: the Action Gate, the approver and the failover rules do."

**Why it matters to each buyer.**
- **Head of AI:** keeps their own model and prompt choices; Sibyl does not force a reviewer on them.
- **CISO:** the monitor's key holds two scopes, sees only its watched agent groups, reads metadata only, and cannot reach any route that acts. A compromised or prompt-injected monitor costs a bad recommendation, not a transfer.
- **Risk and compliance:** every registration, finding, rating and failed delivery is in the audit chain.
- **On-call Operator:** events arrive in the tools they already watch, signed and retried.

**Limits to state.** Monitors read metadata only (no prompts, outputs or held-action arguments). Monitor keys get webhooks or polling, not a live stream. The only run event is `run.failed`. A monitor can see other monitors' findings within its groups. A paused monitor's webhooks wait until it is resumed. Sibyl does not measure a monitor's quality. `sibyl-mcp` and `sibyl-sdk` install from the repository, not PyPI, for now.

## Demo and real: links for prospects

| | Demo (dummy data) | Real deployment (their agents) |
|---|---|---|
| Link | [Open in Codespaces (demo)](https://codespaces.new/MK-JKC/sibyl?devcontainer_path=.devcontainer/demo/devcontainer.json) | [Open in Codespaces (real)](https://codespaces.new/MK-JKC/sibyl?devcontainer_path=.devcontainer/real/devcontainer.json) |
| Locally | `make demo` (Node only) | `make up` (Docker with Compose) |
| Time to first screen | A couple of minutes | About 10 minutes |
| Use it for | Discovery calls and first demos: every screen, a scripted outage, held actions, drift, Sentinel and monitors | Technical validation (stage 3): the Platform Admin connects one real agent, approves a first policy and registers a monitor |

**Access.** The repository is public. Send the public demo (https://sibyl-demo.onrender.com: dummy data, shared by every visitor, no sign-up) for a first look, and the Codespaces links for a private copy of the demo or a real deployment. The real deployment in a codespace is for evaluation, not production; production is self-hosted in the prospect's own environment.

# Differentiation and competitive landscape

## Not just observability

Observability tools record what happened. Sibyl acts, under governance, and proves it.

| Capability | Observability tools | Sibyl |
|---|---|---|
| See calls, latency, errors, cost | Yes | Yes (not our point of difference) |
| Decide what an agent may do before it acts | No | Yes: signed policy at gateway and SDK, argument-level rules and cumulative caps |
| Notice a silent model swap or behaviour shift | Sometimes, as a chart | A `model_change` or `silent_drift` alert with per-feature statistics; watch-only by design |
| Let your own AI reviewer watch the fleet | Usually their own evaluator only | Any Claude, OpenAI, Gemini, MCP or script monitor, with a scoped key, signed webhooks and findings beside the decision they concern; advisory only |
| Act on failure | Alert only | Failover by risk tier, approvals, undo, hold, kill switch |
| Continue unfinished work | No | Handoff packet to a human queue |
| Tamper-evident evidence | Not a design goal | Hash chain, signed anchors, offline verification |

## What the technical differentiation is

None of these is novel alone. The combination, enforced in the path and evidenced end to end, is the product.

1. **In-path enforcement.** Two enforcement points: a gateway (OpenAI, Anthropic and Gemini protocols) that sees each model response, including proposed tool calls, before the agent acts on it; and an SDK check that runs immediately before each tool executes, including tools run by LangChain, the OpenAI Agents SDK and CrewAI.
2. **Signed policy.** Enforcement points act only on Ed25519-signed policy snapshots. A forged or stale snapshot is refused; the kill state is sticky.
3. **Approvals.** Risky actions are held for a person. Four-eyes for tier 1. The requester cannot approve their own request. Timeouts default to deny for held actions.
4. **Undo.** Every automated move can be reversed, and reversal pauses automation.
5. **Evidence.** Every decision carries its rule, its arithmetic and its approver in a hash-chained log.
6. **No LLM in the decision path.** Detection is deterministic rules and change-point statistics; drift detection is PSI and Jensen–Shannon against a frozen baseline. The Action Gate evaluator is a pure function over a JSON expression tree, with no `eval`. The agent cannot persuade it, because nothing in the decision reads the agent's prose. Sentinel and the customer's own monitor agents use models, but only to advise a person.

## The recovery boundary

Sales must state this boundary unprompted, because buyers who discover it later lose trust.

| Sibyl owns | The customer's infrastructure owns |
|---|---|
| Which model, provider or agent a call goes to | Business transaction integrity |
| Stopping traffic (kill switch, quarantine) | Idempotency of their tools and APIs |
| Handing unfinished work to a person, with context | Re-running or compensating side effects |
| Evidence of every decision | Their own data stores and backups |

- **Shared upstream dependencies.** If every alternative depends on the same failed API, switching achieves nothing. Sibyl records dependencies, refuses failover targets that share the failure, and sends the work to a person or a degraded mode instead.
- **Duplicate side effects.** A task whose recorded steps include an external side effect is never resumed automatically. A person decides, with the side-effect ledger in front of them. Automatic resume applies only to steps the agent declared idempotent. (Built: backlog item A-4.)
- **Defence in depth.** For the highest-risk tools, we recommend the downstream system keeps its own limits as well. Sibyl's gate is independent of the agent, not a replacement for the bank's own controls.

## Competitive landscape

Market facts below come from public sources summarised in October 2026 and have not been tested by us. Items marked **[unverified]** must not appear in external material without fresh confirmation.

| Category | Examples | Where they stop | Where Sibyl starts |
|---|---|---|---|
| LLM observability and evals | Langfuse (acquired by ClickHouse, Jan 2026), Arize Phoenix (ELv2), LangSmith, Datadog LLM Observability | Not in the request path; no routing, approvals, handoff or decision evidence | Control and continuity in the path; we accept their OTLP and sit next to them |
| Instrumentation | OpenLLMetry, OpenInference | Emit spans; make no decisions | An input to Sibyl, not a competitor |
| Gateways and routers | LiteLLM, Portkey, Kong AI Gateway, Helicone (reported in maintenance mode after acquisition **[unverified]**) | Request-level, config-driven fallbacks; no tier gating, human queue or tamper-evident decision record **[unverified: current approval and guardrail features in commercial tiers]** | Governed, explainable, undoable decisions; handoff; evidence. LiteLLM is the closest overlap |
| Content guardrails | Prompt and output filtering products **[unverified: feature scope]** | Typically judge text content, often with a model | Argument-level policy on actions (amounts, destinations, cumulative caps), deterministic and signed |
| Enterprise AI governance suites | ServiceNow AI Control Tower, Credo AI, Holistic AI, IBM watsonx.governance; Microsoft Agent 365 **[unverified: GA status]** | Strong on registers, assessments and framework content; mostly not in the request path **[unverified: ServiceNow states it can terminate agents beyond permissions]** | Evidence generated by operations, not assessments; vendor-neutral; self-hostable |

Market read: in 2026 several observability players were absorbed into larger platforms, and governance platforms are buying telemetry. A standalone observability pitch would be a race to the bottom.

## Where we do not compete

| We do not build | Instead |
|---|---|
| Trace waterfalls, span search, session replay | Show the slice that explains a decision; link out by trace id |
| Evals, datasets, LLM-as-judge, prompt playgrounds | Consume eval results as a signal |
| Prompt management | Record `prompt_version` as an attribute |
| Breadth across 100+ providers, semantic caching | Support the dialects that matter; chain behind LiteLLM where breadth is needed |
| Line-item cost dashboards | Budget as a health factor and limit |
| Closed SaaS agents with no interceptable call path | Disqualify; revisit with platform integrations later |

Tell prospects to keep their observability tool. A pilot that requires ripping one out will stall in week one.

# Objection handling

| # | Objection | Answer |
|---|---|---|
| 1 | "Isn't this just monitoring?" | Monitoring tells you what happened. Sibyl decides what is allowed to happen: it sits in the request path, holds or blocks actions against signed policy, moves work when a provider fails, and lets a person undo it. If we only showed dashboards, you should keep your current tool. |
| 2 | "An agent watching agents isn't a breakthrough." | Agreed, and that is not what this is. No LLM sits in the detection or decision path. Rules and the action evaluator are deterministic and explainable, and policy is signed. The agent cannot argue with a predicate like `amount <= 10000`. Sentinel, the optional model-based reviewer, only advises a person. |
| 3 | "You can't recover my business transaction." | Correct, and we say so. Your systems own transaction integrity, idempotency and compensation. Sibyl owns routing, stopping traffic, handing work to a person, and the evidence. A task with recorded external side effects is never resumed automatically; a person decides with the side-effect ledger. |
| 4 | "Where's your moat?" | We do not claim a data moat. Our advantage is integration in the path (one URL change), governance that holds up in an audit, and execution: self-hosted, one-command deploy, safe defaults. Candidates for a future moat are per-tenant verdict-labelled incident data, the scenario library and policy templates, each to be proven by measured lift. |
| 5 | "Can you predict failures?" | Today we raise statistical early warnings (trend and change-point detection, rate-limit and budget proximity). In simulated ramps they fired 5 to 39 minutes ahead. That is simulation, not your traffic. A learned model ships only if it beats the rules on your own labelled alerts, and you will see the numbers either way. |
| 6 | "How do you isolate our data?" | Partner one self-hosts in their own cloud. Row-level security on every tenant table, tested per table and role. Per-tenant envelope encryption. No pooling of signals or models across tenants (a standing decision). Capture can be full, redacted or metadata only, and secrets are scrubbed at three points. |
| 7 | "Another proxy in my hot path is a single point of failure." | Measured overhead is about 0.2 ms at p99. The gateway runs on a signed local snapshot with no control-plane call per request. Each agent is fail-open or fail-closed by declaration. If you want out, restore your original base URL. |
| 8 | "Our LLM gateway already does fallbacks." | Keep it if you like; Sibyl can sit in front of it. Static fallback chains do not know risk tier, do not wait for approval on tier 1, cannot be undone with a hold, do not refuse a target that shares the failed dependency, and do not hand unfinished work to a person. |
| 9 | "We already have guardrails." | Content guardrails judge text. The Action Gate judges actions: tool, arguments, destination, cumulative totals, data class. It is deterministic and signed, and it can hold an action for a human instead of only refusing it. They are complementary. |
| 10 | "What stops the agent bypassing Sibyl?" | Sibyl enforces where traffic flows through it. Tier-1 agents must use agent-bound keys, and auto-discovery registers unknown agents seen in traffic or as handoff targets; they are never routed until an admin confirms them. Code that calls tools without the SDK or gateway is outside coverage; that is why our north-star metric measures the share of actions under enforcement. For critical tools, keep downstream limits too. |
| 11 | "You have no SOC 2 and one operator." | True. That is why partner one self-hosts, support is business hours stated in writing, fail-open and the eject runbook cover out-of-hours, and an external security assessment comes before any paid contract. SOC 2 readiness is a Phase 3 item. |
| 12 | "Approvals will slow everything down." | Approvals apply only where policy says so: above a threshold, on sensitive tools, or on tier 1. Everything else is automatic. Timeouts are explicit, and held actions default to deny so nothing executes unseen. We measure approval latency in the pilot. |
| 13 | "Is this an EU AI Act compliance product?" | It supports human-oversight, inventory and record-keeping duties and produces evidence for them. It does not certify compliance. We lead with operational resilience; high-risk deadlines have reportedly moved to late 2027 **[unverified: Official Journal publication]**. |
| 14 | "What if Sibyl makes a wrong decision?" | Every automated move can be undone in one click, which pauses automation for 30 minutes. Two undone moves in seven days switch that agent to approval-only. A single weak signal never triggers automation. Every decision shows its arithmetic. |
| 15 | "Will this lock us in?" | The SDK is Apache-2.0. OTLP ingest means existing instrumentation keeps working. On exit you get full audit and payload export and a crypto-shred erasure certificate. |
| 16 | "Is the Action Gate real?" | Yes. The evaluator, enforcement at the gateway and SDK, held actions with four-eyes, self-approval refusal, cumulative caps and the console screens are built and tested. What is still in progress is the harness result across over-limit, cumulative-cap, exfiltration and injection scenarios; we will show you that number when it is green, not before. |
| 17 | "How much work is it to instrument our agents?" | For Python, one line (`sibyl.instrument()`) or none (`sibyl-run app.py`). It picks up the OpenAI, Anthropic and Google Gen AI clients and LangChain/LangGraph, the OpenAI Agents SDK and CrewAI. Libraries you do not use are skipped. If configuration is wrong, your app still starts and tells you why. Google ADK and AutoGen connectors are planned; OTLP works today. |
| 18 | "Can you tell us when our provider quietly changes the model?" | Yes, after it happens. Sibyl compares the model the provider says it served, and its fingerprint where the provider sends one, with what each agent was served before. It also compares output length, latency, refusals, tool use and errors against a frozen baseline, with a noise floor so small samples do not raise alarms. You get an alert with the numbers. We do not predict drift, and drift alone never moves traffic. |
| 19 | "Your Sentinel is an LLM. Why trust it?" | Do not trust it to decide, and it cannot. It explains incidents, gives the approver a second opinion on a held action, flags purpose drift and summarises the fleet. It cannot allow, block, approve, fail over or change policy. It runs on your own key, within a daily budget you set, sends no prompts or outputs for metadata-only agents, and records model, tokens, cost and a prompt hash on every finding. We have not yet measured its quality on our harness. |
| 20 | "We use Claude and Gemini, not OpenAI." | The gateway speaks the native Anthropic Messages and Gemini APIs, streaming included, with the same controls. Your SDK changes only its base URL and key. Fallback stays within one protocol: an Anthropic-protocol agent fails over to Anthropic-protocol targets. Sibyl does not translate between protocols. |
| 21 | "We already have our own agent reviewing our agents." | Good: plug it in. Register it as a monitor and connect it through the Sibyl MCP server, signed webhooks or the API. Its findings appear next to Sentinel's, on the held action or incident they concern. It stays advisory: its key reads metadata in the groups you choose and posts findings, and cannot reach any route that allows, blocks, approves or fails over. |
| 22 | "If our monitor agent gets prompt-injected, what can it do?" | Write a wrong finding, which a person reads and can rate as wrong. It cannot act: two scopes only, watched groups only, metadata only, no enforcement route, rate-limited, and every finding audited. Revoking the monitor revokes its keys and disables its webhooks at once. |
| 23 | "Can our monitor read the prompts and outputs?" | Not today. Monitor reads are metadata only, whatever your capture mode. For semantic review of content, Sentinel reads content within the capture mode; a content path for external monitors is on the roadmap, not built. |
| 24 | "Can we try it without a call?" | Yes: the public demo at https://sibyl-demo.onrender.com (dummy data, every screen), the demo Codespaces link or `make demo`; the real-deployment link or `make up` to connect your own agents. |

# Use cases by function

Each use case states the built continuity value and the Action Gate angle. Policy examples use the Action Gate rule model: tool, argument predicates, cumulative caps, data class and effect.

## Finance: payments and transfers

- **Workflow.** An agent prepares and executes vendor payments or treasury transfers.
- **Action Gate.** `payments.transfer`: allow when `amount <= 10000` and `destination in approved_beneficiaries`; escalate with dual control between 10,000 and 25,000; block above 25,000 or to any unlisted destination. Daily cumulative cap per agent with escalate on breach.
- **Continuity.** Tier 1. A backup-agent move needs approval. A transfer step with a recorded side effect is never auto-resumed.
- **Evidence.** Each held transfer shows the rule, the amount, both approvers and timestamps.

## Customer refunds

- **Workflow.** A support agent issues refunds and goodwill credits.
- **Action Gate.** Per-refund cap; cumulative caps per customer per day (sum) and per agent per minute (count, e.g. 20 per 60 seconds). The 40-refunds-in-a-minute pattern escalates at the 21st.
- **Continuity.** Tier 2. Provider failures move traffic automatically; unfinishable cases go to the exceptions team as packets.

## Data exfiltration prevention

- **Workflow.** Any agent with access to customer records and external tools (email, webhooks, file upload).
- **Action Gate.** Block when an argument scrubs as a secret or matches PII detectors and the tool is marked external. Tool allowlists block tools the agent never declared. An injection-driven call to a new destination is blocked by the destination predicate regardless of how the model was persuaded.
- **Continuity.** Kill switch for a compromised agent in seconds.

## Insurance claims

- **Workflow.** An agent triages claims and proposes settlements.
- **Action Gate.** Allow settlements below a threshold for low-risk claim classes; escalate above it or when the fraud flag is set; block payment to a bank account changed in the last N days.
- **Continuity.** Claims in flight during an outage go to adjusters with the full packet, so nothing is lost or paid twice.
- **Evidence.** Human-oversight records for each escalated settlement, exportable for internal audit.

## Customer service and communications

- **Workflow.** Agents answer, update orders, and send outbound messages.
- **Action Gate.** Escalate outbound messages to a segment above a size; block order cancellations above a value; allow read-only tools freely.
- **Continuity.** Rate-limit storms move traffic to the approved alternate model; quality loss (refusals, truncation, malformed tool calls) lowers the health score with the cause named.

# Demo script

Fifteen minutes, three role-based personas: Platform Admin, On-call Operator, Compliance Auditor. The demo runs on the console's demo-data mode (a purple **Demo data** chip is on every screen): the synthetic tenant `meridian` (Meridian Logistics) plays a scripted story in which Anthropic degrades and then goes down, while the Action Gate, run tree, drift and Sentinel beats play alongside. `northstar` is the isolation proof and `sandbox` is empty. Real providers are off. Three browser profiles are signed in. Say once, at the start, that this is demo data shaped exactly like the live API.

**What to say about the harness.** The Action Gate is built and works as shown. Do not claim a harness result for it until the A-5 gate is green. Do not quote any accuracy number for drift detection or Sentinel.

| Time | Segment | Persona | What the audience sees (console demo beat) | Proof point |
|---|---|---|---|---|
| 0:00 to 1:00 | The hook | Platform Admin | Fleet of agents, each with owner, tier and continuity plan. One tier-1 PII agent is parked on hold because its approval timed out and it was not moved without a human. | Governance by default |
| 1:00 to 2:30 | Onboard from nothing | Platform Admin | Onboarding: capture policy first, then the first key. The snippet tabs show one line or zero code for OpenAI, Anthropic, Gemini, LangChain/LangGraph, the OpenAI Agents SDK and CrewAI. A gateway call registers a new agent within seconds. | One line, or one URL |
| 2:30 to 4:00 | Blocked payout in a claims run | Platform Admin | A ₹2,50,000 payout (limit ₹1,00,000) is blocked by the Action Gate. Open the claims run tree: each step, the model calls with the served model, and the payout tool call blocked in the run. A second beat shows personal data to an outside email blocked. | Control before execution; multi-agent visibility |
| 4:00 to 5:30 | Outage and failover | Platform Admin | Anthropic latency climbs, then every call returns 503. Error-rate alerts on 7 agents collapse into one provider incident. Tiers 1, 2 and 3 fail over to OpenAI within their budgets. An agent's score shows its arithmetic. | Explainable, automatic, one incident |
| 5:30 to 7:30 | Handoff to an unknown agent | Platform Admin, On-call Operator | The claims run hands off to a payout agent Sibyl has never seen. It appears under Discovered agents as unconfirmed and not routed. The run's ₹75,000 transfer is held for two people. It was proposed acting for the Platform Admin, so the Platform Admin's own approval is refused (`self_approval`); the On-call Operator approves with step-up, and four-eyes needs a second approver. | Discovery; four-eyes; no self-approval |
| 7:30 to 9:00 | Sentinel advises | On-call Operator | Sentinel explains the claims-triage failover in plain language, and reviews the ₹75,000 hold: advice `needs_more_info`, reasons, risks, and provenance (model, tokens, cost, prompt hash). The banner says Sentinel never decides. | Advisory explanation, on the customer's key |
| 9:00 to 10:30 | Silent model change and drift | Platform Admin | The sales copilot is served a new gpt-5 snapshot: a `model_change` alert. The route optimizer's tool sequences and latency shift: after two drift verdicts in a row, a `silent_drift` alert. Open the agent's drift panel: each feature's value, noise floor and threshold. Sentinel then reads sampled runs and finds no sign of injection. Both alerts are watch-only. | Detects swaps and shifts; explains, never acts alone |
| 10:30 to 11:30 | Operator queue and refunds | On-call Operator | A refund burst hits the 5-a-minute cap and the sixth is held. A handoff packet arrives with input marked untrusted, steps done and side effects; it was not auto-resumed. Closing an alert needs a verdict. | Cumulative caps; human handoff |
| 11:30 to 12:30 | Undo and kill | On-call Operator | Undo one failover with a reason; the banner shows automation paused. Pull the kill switch on another agent with step-up. | The human always wins |
| 12:30 to 14:00 | The auditor | Compliance Auditor | Audit view filtered to Action Gate decisions: the blocked payout, the held transfer, the refused self-approval, the kill, each with its rule. Export; `sibyl audit verify` reports the chain intact; a one-byte edit fails. | Tamper-evident, verifiable offline |
| 14:00 to 15:00 | Isolation and close | Compliance Auditor | Switch to `northstar`: zero alerts and zero transitions throughout. Close on the recovery boundary and what is still in the harness lane. | Isolation; honesty |

**Optional Q&A beats.** Rate-limit early warning on a tier-1 agent shown as an approval card (state clearly: statistical, simulation-measured). Sentinel setup: provider, write-only key, daily budget, sampling rate. **Bring your own monitor** (2 minutes, for prospects who already run a reviewer agent): open **Monitors**, show the Claude reviewer over MCP, the webhook bridge with its delivery status and the paused script; register a new monitor and point at the key shown once with its two scopes; then open the ₹75,000 hold and show Sentinel's and the Claude monitor's reviews side by side, with the Decide card untouched. Tenant erasure in `sandbox` producing a certificate. A live terminal run against the compose stack for technical audiences.

**Rehearsal rule.** Three dress rehearsals from a cold start; two consecutive runs with no fallback before any external demo; a recorded, chaptered fallback video; never demo a build that failed that night's harness.

# Design-partner program

## Profile

The ideal customer profile in chapter 3, scored as a checklist. A prospect missing "pain" or "stack fit" is not a design partner, however enthusiastic. Add one Action Gate criterion: at least one workflow where the partner would grant more authority if an independent limit and an approval existed.

## What the partner commits to

| Commitment | Ask |
|---|---|
| Sponsor | Named Head of AI at kickoff, day 45 and day 90 reviews |
| Engineering | One Platform Admin equivalent, about 4 hours a week |
| Operators | Two people who already handle exceptions work the Sibyl queue and held actions |
| Risk and audit | One reviewer who reads an audit export at day 45 and day 90 and states in writing whether it is usable as evidence |
| Traffic | At least 3 agents (1 tier 1) via the gateway; target 60 percent of LLM calls by day 60 |
| Labels | A verdict on every alert and every blocked action |
| Drills | One game-day a month with operators present |
| Feedback | 30 minutes every two weeks; access to anonymised incident notes |
| Reference | Named or anonymised case study |
| Paperwork | Mutual NDA, DPA covering capture mode and retention, pilot agreement with exit terms |

## What the partner gets

Free use for 90 days; founding-partner pricing **[hypothesis]**; direct founder access with business-hours support; a say in sequencing two roadmap items; self-hosting in their account with a full exit path; their own per-tenant model in shadow once verdict volume allows.

## 90-day pilot plan

| Weeks | Phase | Activities | Exit check |
|---|---|---|---|
| 0 | Kickoff | Success criteria signed; onboarding workshop: capture mode, tiers, continuity plans, fail modes, agent-bound keys for tier 1; eject runbook rehearsed | Criteria and eject tested |
| 1 to 2 | Observe | 3+ agents through the gateway; no routing changes; action policies in simulate mode only | Zero Sibyl-caused incidents; overhead within budget |
| 3 to 6 | Govern continuity | Failover on for tiers 2 and 3; tier 1 under approvals; first drill | First real or drilled failover per tier-1 agent |
| 5 to 8 | Govern actions | Action policies enforced on one or two sensitive tools; escalations to operators; weekly review of blocks and holds | Day 45 evidence review; zero false blocks unexplained |
| 9 to 12 | Expand and prove | Coverage toward 80 percent; second drill; willingness-to-pay conversation at day 60 | Day 90 review; conversion decision |

## Success criteria (agreed in writing at kickoff)

| # | Criterion | Threshold |
|---|---|---|
| 1 | Governed autonomy (share of actions under approved policy) | At least 60 percent at day 60, 80 percent at day 90 |
| 2 | Sibyl-caused production incidents | 0 |
| 3 | Gateway overhead p95 on their traffic | At most 15 ms |
| 4 | Unauthorised actions executed on governed tools | 0 |
| 5 | Continuity proven | At least 1 failover per tier-1 agent; at least 90 percent of tier-1 tasks completed despite failure |
| 6 | False automated failovers on tier 1 | 0 |
| 7 | Alert precision from their verdicts | At least 70 percent; at least 90 percent verdicted |
| 8 | Operator usefulness | Median packet-to-complete at most 10 minutes |
| 9 | Evidence accepted | Written statement from their risk or audit owner |
| 10 | Retention and commercial signal | Sponsor "very disappointed" without Sibyl; signed intent at a price band, or a named reason why not |

A pilot that meets 1 to 9 but fails 10 is a product success and a positioning failure, and we record it as such.

## Finding the first partner on zero budget

Precondition: entity and IP ownership confirmed before any external conversation (an open founder item).

| Channel | Action | Expected yield **[estimate]** |
|---|---|---|
| Founder network | 30 direct messages to Heads of AI in regulated mid-market firms, asking for 20 minutes on "how do you limit what your agents can do, and what happens when a provider fails?" | 10 conversations |
| Proof content | A 3-minute demo video and a write-up using harness numbers; LinkedIn, Show HN, MLOps Community | 3 to 5 inbound |
| Incident timing | Same-week note with a reproducible scenario after a public provider outage | Interest spikes |
| Open-source SDK | Publish `sibyl-sdk` (Apache-2.0); examples for LangGraph and OpenAI Agents SDK | Engineer-led leads |
| Risk circles | A 30-minute talk on "evidence for AI human oversight" to ISACA or risk-practitioner chapters | 1 to 2 risk-side introductions |

Funnel target **[estimate]**: 40 touches, 15 discovery calls, 6 demos, 3 qualified, 1 signed pilot within 8 weeks of the Phase 1.5 exit.

# Packaging and pricing hypotheses

**Everything in this chapter is unvalidated.** No price is quoted to a prospect before at least three pricing conversations with qualified prospects.

## Packages

| Package | For | Includes |
|---|---|---|
| Developer (free) | Evaluation | SDK, gateway, registry, health, single tenant |
| Team | First production agents | Action Gate, failover, handoff queue, audit export |
| Business | Several teams and providers | Approvals and four-eyes, leading indicators, legal holds, erasure certificates, SSO |
| Enterprise | Regulated firms | Compliance packs, long audit retention, residency, support SLA |

## Price shape

- **Platform fee plus a per-governed-agent charge, weighted by tier** (hypothesis: tier 1 = 3 units, tier 2 = 2, tier 3 = 1), with a fair-use event band. Weighting must never reward under-declaring tier.
- **Indicative ranges [unvalidated]:** Team about USD 1,000 to 2,000 a month platform fee plus USD 40 to 80 per agent-unit a month; Business about USD 4,000 to 6,000 a month platform fee with a lower unit rate; Enterprise custom, floor about USD 75,000 a year.
- **Add-ons:** compliance packs per framework per year; audit retention beyond 400 days.
- **Founding partner [hypothesis]:** 50 percent off Team or Business list for 24 months if converted within 60 days of pilot exit.
- **Never paywalled:** the SDK, OTLP ingest and the kill switch.

Rationale: priced against the cost of one serious incident or one unauthorised payment, and a fraction of a compliance analyst's time, not against per-trace observability pricing. Validate with Van Westendorp questions at day 60 of the pilot.

# Sales process and qualification

## Stages

| Stage | Exit criteria | Owner artefact |
|---|---|---|
| 0. Target | Matches the ICP on paper | Account note |
| 1. Discovery | Pain described with a specific incident or blocked workflow; stack fit confirmed | Discovery notes |
| 2. Demo | 12-minute demo to Head of AI and Platform Admin; next step booked | Demo recording |
| 3. Technical validation | Platform Admin runs the real deployment (`make up`, or the real Codespaces link) in their sandbox; one agent through the gateway or the SDK; optionally their own monitor agent registered | Validation checklist |
| 4. Security review | CISO receives the security pack; no blocking finding | Review log |
| 5. Pilot agreement | Signed success criteria, DPA, exit terms | Pilot agreement |
| 6. Pilot | 90-day plan executed | Weekly status |
| 7. Conversion | Intent or contract at a stated band, or a documented no | Exit review |

## MEDDICC-style qualification

| Element | What we need to know | Disqualify if |
|---|---|---|
| Metrics | Which number improves: incidents, tasks completed, workflows granted more authority, audit effort | No measurable outcome |
| Economic buyer | Head of AI (or equivalent) with authority to sign an unpaid pilot | Buyer unknown after stage 2 |
| Decision criteria | Overhead, isolation, self-hosting, evidence quality, action control | Criteria require SOC 2 Type II now |
| Decision process | Who approves a pilot: security, legal, procurement steps and timing | Process exceeds 90 days for an unpaid pilot |
| Identify pain | A described outage, near-miss action, or workflow blocked by risk | Pain is hypothetical |
| Champion | Someone who will run the internal review and defend the pilot | No champion by stage 3 |
| Competition | What they use now (observability, gateway, governance suite) and what they would keep | They want a tracing replacement |

## Security review pack

Contents, with honest status:

| Item | Status |
|---|---|
| Security overview (architecture, data flow, encryption, isolation, audit chain) | To write before stage 4 |
| Data handling: capture modes, three-point secrets scrubbing with 23 detectors, per-tenant AES-256-GCM envelope encryption, retention | Built |
| Credential custody: passthrough for primary calls, vaulted fallback keys, hashed API keys | Built |
| Isolation evidence: RLS tests per table and role; second-tenant demo proof | Built |
| Signed policy and kill switch design, including break-glass key | Built |
| Harness gate report (latest nightly) | Built |
| SBOM and licence inventory (permissive dependencies only) | Built in CI |
| Known limits page (accepted residuals, business-hours support, declared residency) | To publish |
| Incident response and breach notification procedure | To write with counsel |
| DPA template and sub-processor list (none for self-hosted) | To write with counsel |
| External security assessment report | **Not done**; required before the first paid tenant |
| SOC 2 | **Not started**; Phase 3 |

# Metrics

## North star: governed autonomy

**Governed autonomy** is the share of a tenant's production agent actions that pass through Sibyl's enforcement points under a declared, approved policy.

It moves only when Sibyl is adopted (actions flow through it), governed (policies exist and are approved) and trusted (teams route more authority through it). It refines the earlier "verified governed coverage" measure, which counted calls from agents with an owner, a tier, a risk class and a recently proven fallback; those conditions remain as supporting checks. Sibyl cannot see actions that bypass it, so discovering unknown agents can lower the number. We report that drop as progress, not failure.

**Counter-metrics** (any one red blocks a claim of progress): Sibyl-caused incidents, false automated failovers, false blocks, gateway overhead p95, unverdicted backlog.

## Supporting product metrics

| Metric | Why |
|---|---|
| Unauthorised actions blocked or escalated | Direct value of the Action Gate |
| Unauthorised actions executed (harness and pilot) | Must be zero |
| Held-action decision time, median | Approvals must not stall work |
| Time to detect | Continuity |
| Failovers within recovery target | Continuity |
| False-failover rate by tier | Trust |
| Tasks completed despite agent failure | Business continuity |
| Verdict coverage | The only source of per-tenant learning |

## Funnel metrics [estimates]

| Stage | Target per cycle |
|---|---|
| Outreach touches | 40 |
| Discovery conversations | 15 |
| Demos | 6 |
| Qualified (ICP scorecard) | 3 |
| Signed pilots | 1 within 8 weeks of Phase 1.5 exit |
| Pilot to intent to convert | 1 of 1 for partner one; measured thereafter |

## Pilot metrics

The ten success criteria in chapter 9, reviewed every two weeks with the partner, plus founder support hours (target at most 6 a week by day 60).

# Launch readiness checklist

## Product

- [x] Action Gate A-1 to A-4 and A-6 merged, with the console on the live contract
- [ ] A-5 harness gate green (zero unauthorised actions executed)
- [x] A-4 enforced: side-effecting tasks never auto-resumed, with tests
- [ ] Silent model swap scenario in the harness; outage detection gap closed
- [ ] Sentinel quality measured on the harness before it is offered as on by default
- [ ] Full nightly harness green on five consecutive nights
- [ ] Backup restore drill passed, including re-application of erasures
- [ ] Gateway overhead benchmark within budget with scrubbing and encryption on
- [x] Self-host guide (`docs/setup/SETUP.md`) and the real deployment (`make up`) with OIDC and TLS options
- [x] External monitor agents: registration, monitor keys, `sibyl-mcp`, signed webhooks, examples
- [x] Release 1.0.0: GitHub Actions CI, release images on GHCR, demo and real Codespaces links
- [ ] Helm chart for partner one; eject runbook written
- [x] Public demo (https://sibyl-demo.onrender.com) and public repository with Codespaces links
## Sales and marketing

- [ ] Demo rehearsed three times; two consecutive clean runs; chaptered fallback video
- [ ] Security review pack complete (chapter 11), including Known limits
- [ ] Claims review: every external sentence checked against chapter 14 and the "What we say" table
- [ ] 3-minute demo video and technical write-up
- [ ] ICP scorecard and discovery script
- [ ] `sibyl-sdk` and `sibyl-mcp` published under Apache-2.0 (package name reservation is an open founder item)

## Legal and company

- [ ] Contracting entity and IP ownership confirmed (open founder item) before outreach
- [ ] Pilot agreement, DPA and privacy policy reviewed by counsel
- [ ] External security assessment scheduled; closed with no open Critical or High before the first invoice

## Support

- [ ] Business hours and timezone published; severity table with first-response targets
- [ ] Shared support alias; status page on separate infrastructure
- [ ] Breach notification procedure agreed with counsel

# Appendix

## What we say and what we never say

| What we say | What we never say |
|---|---|
| Sibyl controls what agents may do before they act. | "Sibyl makes your agents safe." |
| The Action Gate is built and blocks or holds actions before they run. In our harness runs, no unauthorised action executed in the Action Gate scenarios. | "Zero unauthorised actions" or "prevents all unauthorised actions" (before A-5 passes, and never as an absolute). |
| Early warnings are statistics; in simulation they fired 5 to 39 minutes ahead. | "Predictive intelligence" or "predicts failures." |
| We detect silent model swaps and behaviour shifts against each agent's own baseline, and show the numbers. | "Predicts model drift" or "prevents drift." |
| Drift alerts are watch-only: a person decides. | "Automatically fixes drift." |
| Sentinel runs on your own key, explains and recommends, and never enforces. | "Our AI agent stops your other AI agents" or "Sentinel catches attacks." |
| Sentinel's quality has not been measured yet. | Any accuracy, precision or "catches X percent" figure for Sentinel. |
| Bring your own monitor: your Claude, OpenAI, Gemini or script reviewer advises next to Sentinel; Sibyl's policy decides. | "Your AI agent can now control your fleet" or "monitors stop bad actions." |
| Monitors read metadata within the agent groups you choose. | "Your monitor sees everything" or "full visibility for your reviewer." |
| Try the public demo at https://sibyl-demo.onrender.com, or a Codespaces link for your own copy. | "Free sandbox" or "trial of your own data" (the public demo is shared dummy data). |
| Native Anthropic and Gemini at the gateway; fallback stays within one protocol. | "Fails over from Claude to GPT automatically" for a native Anthropic client. |
| One line or zero code for the listed clients and frameworks. | "Works with every framework" (Google ADK and AutoGen connectors are planned). |
| Learned models ship only if they beat the rules on your own labelled data. | "Learns from your data" or "gets smarter over time." |
| We do not claim a data moat. | "Data moat" or "network intelligence." |
| No LLM sits in the decision path. | "AI-powered governance." |
| Sibyl owns routing, stopping, handoff and evidence; you own transaction integrity. | "Sibyl recovers your transactions" or "guarantees no duplicates." |
| Supports human-oversight and record-keeping duties under named frameworks. | "EU AI Act compliant" or "certified." |
| Measured gateway overhead is about 0.2 ms at p99 in our benchmark. | "Zero latency." |
| Self-hosted; data stays in your cloud; no cross-tenant pooling. | "Bank-grade" or "military-grade security." |
| Business-hours support, stated in writing. | "24/7 support." |
| Enforcement covers traffic through the gateway and SDK. | "Covers every agent in your company." |

## Claims to avoid

Until measured or built, never use: "predictive intelligence", "learns from your data", "data moat", "prevents all unauthorised actions", "predicts drift", any quality figure for Sentinel or for an external monitor, "monitors enforce", "public demo", "AI that governs your AI", "compliant" or "certified" for any framework, "guaranteed recovery", "SOC 2", "24/7", "residency guaranteed" (residency is a declared field until region-pinned stacks exist), and any competitor feature claim marked **[unverified]** in chapter 5.

## Glossary

| Term | Meaning |
|---|---|
| Action Gate | Pre-execution allow, block or escalate on a proposed tool call, from signed policy |
| Action policy | Ordered rules on tool, arguments, cumulative caps and data class |
| Agent | An AI workflow Sibyl governs |
| Anchor | A signed checkpoint of the audit chain |
| Break-glass key | An emergency key that can only stop agents, usable when SSO is down |
| Continuity plan | Recovery targets and what to do on failure |
| Discovered agent | An agent seen in telemetry but not yet confirmed; never routed until an admin confirms it |
| Drift alert | `model_change` (a new served model or fingerprint) or `silent_drift` (a behaviour shift against the baseline); watch-only |
| External monitor | The customer's own agent or script registered to watch some or all agent groups and post advisory findings; never enforces |
| Monitor key | A key bound to one monitor that can only read metadata and post findings |
| Fallback chain | Ordered alternatives: model, provider, backup agent, human queue |
| Four-eyes | Two different people must approve |
| Governed autonomy | Share of production agent actions under an approved policy at an enforcement point |
| Handoff packet | Structured hand-over of unfinished work to a person |
| Held action | An escalated action waiting for a human decision; defaults to deny on timeout |
| Hold | A 30-minute pause on automation after an undo |
| Run tree | One multi-agent run: agents, steps, model and tool calls, handoffs |
| Sentinel | Optional advisory agent on the customer's own model key; explains and recommends, never enforces |
| Tier | Business criticality, 1 (critical) to 3 (routine) |
| Verdict | An operator's judgement on an alert: true positive, false positive or unsure |


# Addendum: plug-and-play monitoring, drift detection and Sibyl Sentinel (built)

Status for sales, 2026-10-12.

## Plug-and-play monitoring

**What to say.** "Add one line, or run your app with `sibyl-run`, and Sibyl picks up the OpenAI, Anthropic and Google Gen AI clients and LangChain/LangGraph, the OpenAI Agents SDK and CrewAI. Multi-agent systems show up as a run tree. Agents we have never seen appear as discovered and are not routed until you confirm them."

- Tools run by those frameworks go through the Action Gate before they execute.
- Prompts and outputs leave the process only if the capture mode allows, after the secrets scrub.
- **Limits to state.** Python only (TypeScript SDK planned). Google ADK and AutoGen connectors are planned.

## Native Anthropic and Gemini at the gateway

**What to say.** "Your Anthropic or Gemini SDK changes only its base URL and key. Kill switch, limits, routing and the Action Gate work the same way."

- **Limit to state.** Fallback stays inside one protocol. An agent on the native Anthropic protocol fails over to Anthropic-protocol targets only; Sibyl does not translate requests between providers. An agent that needs cross-provider failover uses the OpenAI-compatible protocol.

## Model drift detection

**What to say.** "Sibyl tells you when a provider serves a different model than before, and when an agent's behaviour shifts against its own baseline: output length, latency, refusals, truncation, tool use, schema failures, errors and tool sequences. Each alert shows the numbers, including a noise floor so small samples do not raise alarms."

- It is plain statistics (PSI and Jensen–Shannon), no LLM.
- It is watch-only: it alerts a person, and it never fails over, holds an action or changes a policy on its own.
- **We detect; we do not predict.** Never say "predicts drift".
- **Limits to state.** Thresholds are tunable per tenant through the API (no console screen yet). A baseline needs at least 500 calls over 6 hours before it is compared. Fingerprint checks need a provider that sends one. No harness result yet.

## Sibyl Sentinel

Prospects will ask for "an agent that watches our agents" built on Claude, GPT or Gemini. Our answer is **Sibyl Sentinel**: an optional, opt-in advisory agent. It runs on the customer's own Anthropic, OpenAI or Gemini key, and it explains incidents, reviews held actions for the approver, flags purpose drift and injection-like sequences, and writes a daily fleet summary.

**How to position it.**
- **Bring your own key.** The key is write-only, sealed in the tenant vault and never shown again. Calls go only to the provider's API host.
- **Advisory.** It cannot allow, block, approve, fail over or change policy. Allow, block, approve and failover stay deterministic, signed and auditable.
- **Bounded.** A daily budget the customer sets, reserved before each call so it is not overshot, and a sampling rate for drift reviews.
- **Respects capture mode.** Metadata-only agents send no prompts or outputs.
- **Accountable.** Every finding records provider, model, tokens, cost and a prompt hash. People rate findings as useful, not useful or wrong.
- Sell it as judgement and explanation on top of guarantees, not as the guarantee.
- If the prospect would rather use their own reviewer agent, that is now built too: see "Bring your own monitor agents" in chapter 4. Sentinel and external monitors can run side by side.

**What we say.** "Sentinel uses your preferred model to explain and recommend; Sibyl's enforcement never depends on a model's opinion."

**What we never say.** "Our AI agent stops your other AI agents." The Action Gate stops actions; Sentinel advises. Never quote a quality figure: Sentinel has not been measured on the harness yet.

## Action Gate status for sales

The policy evaluator, enforcement at the gateway (all three protocols) and in the SDK (including framework tools), and the approval workflow are built and tested: held actions, four-eyes approval, deny on timeout, cumulative caps, on-behalf-of with self-approval refused, and a decision history on every hold. The console screens run on the live API: the held-actions queue, the policy editor with simulate, and decision records in the audit log. In the merged harness runs, no unauthorised action executed in the Action Gate scenarios (S-29 at the SDK, S-30 at the gateway). The full gate suite is not yet green: every scenario still fails a known contract check (B-04), and the human-approval path is to be re-run after the B-09 fix, so we cite the scenario result, not a release gate. Known gaps to mention if asked: the held-actions list shows no arguments (the detail view shows them, scrubbed), and simulate does not read live counters.
