# Wave 4: external monitor agents, release 1.0, setup and deployment (chair, 2026-10-14)

The founder's request (2026-10-14): continue the open tasks; plug-and-play for **external agents that
monitor the agents in Sibyl**; finish the product today and publish it on GitHub; a setup document
with every prerequisite; two links: a **demo with dummy data** and the **real deployment** for real
agents. Decisions D53–D55. Rulings continue at B39.

## Decisions
- **D53 External monitor agents.** Any outside agent (a customer's Claude, OpenAI or Gemini agent,
  an Agent SDK app, an MCP-capable assistant, or a plain script) can monitor the fleet:
  1. **Register** a monitor (`POST /monitors`): name, kind (`mcp` | `webhook` | `api`), owner, the
     agent groups it may watch. Registration issues an API key bound to the monitor with scopes
     `monitor:read` (read-only fleet, health, runs, drift, incidents, held actions, metadata only
     unless the tenant capture mode allows content) and `findings:write`.
  2. **Observe**: pull through the REST API or the **Sibyl MCP server** (`sibyl-mcp`, stdio and
     streamable HTTP; tools: list_agents, get_agent, get_health, list_runs, get_run, get_drift,
     list_alerts, get_incident, list_held_actions, get_held_action, list_findings, submit_finding,
     recommend_on_held_action); or receive **signed webhooks** (HMAC-SHA256, timestamped, retried
     with backoff, egress allowlisted) for alert, incident, held_action, drift and run events.
  3. **Report**: `POST /findings` with the same shape as Sentinel findings plus `source:
     external` and `monitor_id`. Findings are advisory exactly like Sentinel (D52): they can open
     watch-only `external_finding` alerts and attach recommendations; they can never allow, block,
     approve, fail over or change policy. Rate-limited per monitor; audited.
  Sentinel becomes the built-in monitor; external monitors are first-class peers in the console.
- **D54 Release 1.0 on GitHub.** GitHub Actions CI (lint, types, tests with Postgres service,
  console checks) and a release workflow that builds and publishes the service images to GHCR on a
  `v*` tag; tag `v1.0.0` with release notes.
- **D55 Two ways to run, two links.**
  - **Demo** (dummy data, no external services): `make demo` locally, or the
    **Open in Codespaces (demo)** link (`.devcontainer/demo`). Console in demo mode, scripted
    scenario, every screen clickable.
  - **Real** (plug in real agents): `make up` locally, or **Open in Codespaces (real)**
    (`.devcontainer/real`): full stack (Postgres, API, ingest, worker, gateway, console, Caddy TLS,
    OIDC), no simulator, bootstrap creates the first tenant, admin and keys, then
    `docs/setup/SETUP.md` walks through connecting a real agent (gateway base URL or
    `sibyl.instrument()`), an Action Gate policy, and an external monitor.
  - `docs/setup/SETUP.md`: prerequisites per OS (macOS, Linux, Windows via WSL2), Docker or Colima,
    uv, Node, ports, corporate TLS-inspection proxies (CA bundle, never disable TLS), production
    hardening (OIDC provider, secrets, backups, TLS certificates, upgrades).

## Lanes (wave 4A)
| Lane | Owns |
|---|---|
| **EXTMON** | `api/monitors/**`, `api/findings/**`, `worker/webhooks/**`, `packages/sibyl-mcp/**` (new), SDK `sibyl/monitor/**`, examples `examples/monitors/**`, migration `0025_external_monitors.sql` |
| **HARDEN** | harness gate suite green (B-04), tick-lag-scaled deadlines (B38), S-29 approval re-run, Sentinel quality scenario, CI under 10 min, B32, B33, tenant-tunable drift thresholds (API), migration `0026_hardening.sql` |
| **SHIP** | `.github/**`, `.devcontainer/**`, `Makefile` targets, `deploy/**` real profile, `docs/setup/**`, root `README.md` |

Wave 4B (after EXTMON + HARDEN merge): console (Monitors page, external findings next to Sentinel,
Runs in the sidebar, drift threshold settings), screenshots, docs and PDFs, release tag.

## Rules
Same as WAVE3.md: TDD, strict contract scenarios, RLS on every tenant table, no LLM or external
monitor in any enforcement or detection path, fail closed, never print secrets, `UV_SYSTEM_CERTS=1`,
never disable TLS. Do not commit or push; hand back a report.
