# Changelog

All notable changes to Sibyl are recorded here. Versions follow [Semantic Versioning](https://semver.org/).
The release workflow (`.github/workflows/release.yml`) publishes the section whose heading matches the
pushed `v*` tag as the GitHub Release notes, so keep one `## [x.y.z] - YYYY-MM-DD` heading per release.

## [1.0.0] - 2026-10-14

The first release of Sibyl: a self-hosted control plane that keeps an organisation's AI agents
reliable and governed. It watches every agent, stops unauthorised actions before they run, moves
traffic when a model or provider fails, and keeps an audit trail an auditor can verify offline.

### Highlights

- **Action Gate.** Every proposed tool call is decided before it executes: `allow`, `block` or
  `escalate` to a person. Policies (`sibyl-action-policy/1`) are JSON documents with argument
  predicates, cumulative caps, data-class checks (secrets, card numbers, IBANs, national ids) and
  tool allowlists, versioned, simulated before approval and signed into the policy snapshot.
  Enforced at two independent points: the SDK (`@sibyl.tool`, LangChain, OpenAI Agents SDK, CrewAI)
  and the gateway (OpenAI `tool_calls`, Anthropic `tool_use`, Gemini `functionCall`, streaming
  included). Held actions wait in a queue for a decision with four-eyes and self-approval refusal.
- **Plug-and-play monitoring.** `sibyl.instrument()` (one line) or `sibyl-run app.py` (zero code)
  instruments the OpenAI, Anthropic and Google Gen AI clients and the LangChain/LangGraph, OpenAI
  Agents SDK and CrewAI frameworks. Run trees connect parent runs, steps and handoffs; agents first
  seen in telemetry are discovered automatically and wait for an admin to confirm them.
- **Gateway.** A drop-in base URL for OpenAI-compatible, native Anthropic Messages and native Gemini
  clients: signed policy snapshots with key pinning, fail-open or fail-closed per agent, kill switch,
  quarantine, inline fallback before the first byte, and scrubbed telemetry.
- **Health, early warning and failover.** An explainable health score, detected and leading-indicator
  rules, provider-incident collapse, and a failover saga with tier gating, approvals, undo, operator
  hold, handoff packets to a human queue, and failback.
- **Model drift detection.** Detects a silently swapped or changed model (identity and behavioural
  drift) and raises watch-only alerts.
- **Sentinel.** A built-in advisory monitoring agent running on the tenant's own Anthropic, OpenAI or
  Gemini key, within a daily budget: it explains incidents, reviews held actions and drift, and
  writes findings people can rate. It can never allow, block, approve or fail over anything.
- **External monitors** (D53). Outside agents (a customer's Claude, OpenAI or Gemini agent, an MCP
  assistant, or a script) register as monitors with their own key, watch the fleet within their
  agent groups (metadata only) through the REST API, the `sibyl-mcp` MCP server or HMAC-signed
  webhooks, and report advisory findings shown next to Sentinel's. They can never allow, block,
  approve, fail over or change policy. Console Monitors page; examples in `examples/monitors/`.
- **Tenant-tunable drift thresholds** (`GET`/`PUT /api/v1/drift/thresholds`, API only for now).
- **Governance.** Per-tenant audit hash chain with Ed25519 anchors, exports verifiable offline with
  `sibyl audit verify`, legal holds, and crypto-shred erasure with a signed ledger and certificates.
- **Console.** Fleet, incidents, approvals, the operator queue, alerts with mandatory verdicts, the
  Action Gate editor and held-actions queue, drift, Sentinel, discovered agents, run trees, audit,
  onboarding and settings; a demo-data mode with a scripted outage scenario.
- **Harness.** `sibyl-sim` provider doubles, status feeds and chaos knobs, and a 33-scenario catalogue
  with an oracle, gates and load-scaled deadlines (development only; never part of a real deployment).

### Fixes

- API keys are limited to a route's key scopes (closed a key reaching the event stream on
  `agents:read` alone).
- A multi-tenant gateway posts each tenant's telemetry with that tenant's ingest key
  (`SIBYL_INGEST_KEYS`, B-03); before, all tenants' gateway telemetry went to the first tenant.
- Health snapshots always carry a feature snapshot, and engine bookkeeping rows no longer appear in
  `factors[]` (B-04); a band held below a live floor is always explained (B-07).
- A person's failover denial holds for the whole failure episode (S-26).
- Held actions naming a deactivated user are refused (B32); one shared key-set follower in the gateway
  and SDK (B33); the SDK persists a policy snapshot before publishing it.

### Deployment

- Two ways to run (D55): `make demo` (console with dummy data, Node only) and `make up` (the real
  deployment: Postgres 17, API, ingest, worker, gateway, console, Caddy TLS and OIDC, no simulator,
  first-run bootstrap of the tenant and Platform Admin). Both also open in GitHub Codespaces.
- OIDC is configurable: the bundled dex for a first install, or any OIDC issuer for production.
- TLS through Caddy: its local CA by default, ACME certificates for a public name, or your own files.
- Release images on GHCR: `ghcr.io/mk-jkc/sibyl-{control,gateway,console,sim}`, multi-arch, with SBOM
  and provenance; deploy one with `SIBYL_IMAGE_TAG=1.0.0 make up`.
- GitHub Actions CI: lint, format, import contracts, types, tests with coverage against Postgres 17,
  the licence gate, and console typecheck, lint, unit tests and performance budgets.

### Known limitations

- Early warning is statistics, not a learned model; drift detection detects a change, it does not
  predict one. Sentinel's behaviour is checked on the harness (S-33); its judgement is not yet
  measured.
- Harness gate suite: 20 scenarios pass; 12 wait on design rulings, unbuilt features (automated
  quarantine, observation-gap synthesis, prompt-injection detection) or a known coverage gap (B-10).
- Drift thresholds have no console screen yet. The two-tenant demo stack shows gateway telemetry for
  its first tenant only.
- Point-in-time recovery (pgBackRest), off-host backups and a Helm chart are planned; backups today
  are encrypted logical dumps (`ops/backup`).
- No external security assessment yet; treat a deployment as pre-production until one is done (D18).

### Licences

The SDK (`sibyl-sdk`) and the wire contracts (`sibyl-schemas`) are Apache-2.0. Everything else is
proprietary (D15). Runtime dependencies are permissive only, enforced by the licence gate.
