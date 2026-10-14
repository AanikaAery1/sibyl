# Sibyl console

The web console for Sibyl: fleet health, incidents and approvals, the operator queue, alerts with verdicts, the audit chain, onboarding and settings. Next.js (App Router) + TypeScript (strict) + Tailwind v4, with a BFF route layer in `app/api/bff/**`.

It runs in **demo-data mode** by default: deterministic fixtures shaped exactly like the frozen OpenAPI contract, plus a scripted live scenario (Anthropic outage → one provider incident → tiered automatic failover → handoff packets → a tier-1 move waiting for four-eyes approval → recovery and canaried failback). The toolbar's purple **Demo data** chip says so on every screen.

## Start it (The founder)

```bash
cd console
npm install          # first time only; behind a TLS-inspecting proxy set NODE_EXTRA_CA_CERTS=<your CA bundle>
npm run dev          # http://localhost:3000
```

Port 3000 busy (another Next app)? `PORT=3100 npm run dev`.

Then open http://localhost:3000. You land on **Fleet** as the **Platform Admin** in **Meridian Logistics**. The scenario starts the moment the server starts:

| Time | What happens |
|---|---|
| 0:15 | Anthropic latency climbs |
| 0:30 | Anthropic hard outage; 7 tiles go red |
| 0:36 | One provider incident (not seven alerts); banner appears |
| 0:42 / 0:52 / 1:04 | Tier 1, then tier 2, then tier 3 fail over to OpenAI; packets land in the queue |
| 3:20 | Quote assistant: predicted rate limit, tier-1 move waits for approval (10-minute countdown) |
| 10:00 | Anthropic recovers; alerts resolve without a verdict (they appear under **Alerts → Unverdicted**) |
| 15:00–17:00 | Canaried failback 10 → 50 → 100 % |

Click the **Demo data** chip to replay, pause, or skip straight to the failover.

**External monitors (D53).** Meridian has four registered monitors under **Monitors** (sidebar, next to Sentinel): *Claude ops reviewer* (MCP, all groups), *PagerDuty bridge* (webhook, Claims & payouts + Logistics, one webhook delivering and one retrying on 503), *Nightly audit script* (REST API, paused) and *Legacy Slack relay* (revoked). At 0:40 the PagerDuty bridge files an anomaly finding about the claims-triage error burst, and at 0:55 the Claude ops reviewer reviews the ₹75,000 hold (advice: deny). Their findings appear on **Sentinel** (filter *Monitors*), labelled "Monitor: <name>", and beside Sentinel's review on the held action. As the Platform Admin, register a monitor (the key is shown once, with ready-to-paste `sibyl-mcp` and Python SDK setup), pause/resume it, add a webhook (its `whsec_` secret is shown once), send a test delivery, issue a key or revoke it. The Compliance Auditor sees monitors read-only. Monitor-written text is untrusted and always rendered as plain text.

### Personas and tenants

Switch from the card at the bottom of the sidebar (or ⌘K → "Switch to…"):

| Persona | Role | Try |
|---|---|---|
| Platform Admin | Admin (all tenants) | Request a backup-agent failover on a tier-1 agent, then try to approve it yourself (refused: four-eyes) |
| On-call Operator | operator + security admin (meridian, northstar) | Approve it; claim and complete a packet; close an alert without a verdict (refused) then with one; undo a failover (30-min hold); pull the kill switch (step-up) |
| Compliance Auditor | auditor (all tenants) | Audit → Verify chain, verify a tampered copy, open a `route.changed` row for the decision record, export; switch to **northstar** to see isolation |

Tenants: **meridian** (20 agents, 3 providers), **northstar** (3 agents, untouched by the outage), **sandbox** (empty; use **Onboarding**: capture policy → key shown once → the agent appears ~5 s later).

Role names follow chair ruling B17: the `owner` role is shown as **Admin** and the `admin` role as **Workspace admin** (`lib/auth/roles.ts`, `ROLE_LABEL`). RBAC keys are unchanged.

## Live mode

Live mode runs the console against the real control plane. You sign in as yourself through the API's OIDC flow, and every panel reads real data, apart from the routes the API cannot serve yet, which are marked.

### Setup (compose, behind Caddy)

The console, the API and dex share one origin behind Caddy. The API sets its session cookie (`__Host-sibyl_session`) on that origin, and the console must be able to read it, so a live console has to run behind Caddy, not on a separate host or port.

1. Caddy needs `/api/bff/*` sent to the console *ahead of* its `/api/*` rule. SSE must not be buffered:
   ```
   handle /api/bff/* {
   	reverse_proxy console:3000 {
   		import client_ip
   		flush_interval -1
   	}
   }
   ```
2. Set the console service's environment:
   ```bash
   SIBYL_CONSOLE_MODE=live
   SIBYL_API_URL=http://api:8000   # server-side only; the browser never calls the API directly
   SIBYL_KEY_ENV=test              # must equal the API's SIBYL_ENV (compose runs `test`)
   ```
3. Open `https://localhost:8443`. It asks for your workspace (`meridian`). The API's login sends you to dex, where the personas are `admin@demo.sibyl.example`, `operator@…` and `auditor@…` with the shared demo password. dex returns you to the API callback, which sets the session and brings you back to the page you asked for.

`SIBYL_DEMO_ROUTES=/incidents,/queue` serves *reads* on those routes from the demo engine, marked "Demo data" on every panel. Writes to them are refused with `409 demo_route_readonly`: live mode never fakes a change. Leaving `SIBYL_CONSOLE_MODE` unset (or misspelled) on a production server means **live**, never the open demo, so demo deployments set `demo` explicitly, as the console image does.

### How it works

| Concern | Behaviour |
|---|---|
| Sign-in | `/login` (glass, tenant first) → `GET /api/bff/auth/login?tenant=…` → the BFF calls the API's `/auth/login` and passes on its 302 to the IdP (http/https only) and the sealed `__Host-sibyl_oidc_state` cookie. Only the API's two `__Host-` cookies are ever relayed → dex → API `/auth/callback` sets `__Host-sibyl_session` → back to `return_to`. Refusals (unknown workspace, IdP down, bad slug) return to `/login` with a plain message. The form navigates instead of posting, because CSP `form-action 'self'` covers the redirect chain and would block a cross-origin IdP. |
| Identity | `/auth/me` per server render. The scopes are the API's; roles are the memberships in the session's tenant. Persona and tenant cookies are ignored. Switching workspace means signing in again, and the current session is signed out first. The menu has **Sign in to another workspace…**. |
| Every BFF call | `/api/bff/<path>` → `SIBYL_API_URL/api/v1/<path>` with `Authorization: Bearer sibyl_sess_<cookie>`. Only contract paths are forwarded (`lib/api/paths.gen.ts`, regenerated by `npm run gen:api`). `.`/`..` segments, `/auth/*`, the gateway-only `/policy/*` and non-contract paths get 404 without reaching the API. With no or malformed session, the BFF answers 401 itself without calling the API, and the browser goes to `/login`. |
| CSRF | This is unchanged from demo mode. Every mutation needs Origin/Sec-Fetch-Site to be same-origin plus the double-submit `x-sibyl-csrf` token. Behind Caddy, the console's own origin is the one in `X-Forwarded-Proto`/`Host`. Navigations that cause side effects (the step-up window, export download) need `Sec-Fetch-Site: same-origin`, and a missing header is refused. Logout is a CSRF-checked POST. |
| Step-up | `403 step_up_required` opens the "Confirm it's you" dialog. **Continue** opens a small window on `/api/bff/auth/step-up`, which calls the API's `POST /auth/step-up` and goes to dex with `prompt=login max_age=0`. The callback lands on `/auth/done`, which messages the tab and closes; the tab accepts the message only from its own origin and that window. The action then retries with the same Idempotency-Key. If the browser blocks the window, the whole page makes the trip and you run the action again. |
| Sign out | `POST /api/bff/auth/logout` revokes the session at the API (`access.logout`) and clears the cookie, even when the API is unreachable. |
| Demo fallback | A **GET** that the API answers with 501 is served from demo data, labelled `x-sibyl-console-source: demo-fallback`. The panel shows a purple **Demo data** ribbon and the toolbar shows "Live API · N on demo". A **write** that gets a 501 is never faked: it returns 501 with "not available on this control plane yet". |
| Events | `/api/bff/events/stream` relays the API's outbox stream (ids and versions only). Each event revalidates the SWR keys it can change. If a connection is refused (401/429/restart), the console reconnects with backoff, sending `?last_event_id=`, which the BFF forwards as `Last-Event-ID`, so nothing is missed. |
| Export download | The API's `download_url` points at the bearer-only `/api/v1/payloads/{ref}`. The console therefore streams the file through `/api/bff/audit/exports/{id}/download` and states a reveal reason, which the API audits as `data.revealed`. |

### What is live today (API at main `48e17ad`)

| Live | Demo fallback (API answers 501) |
|---|---|
| auth (login, callback, step-up, logout, me), `/tenant`, `/users`, `/api-keys` (list, create, rotate, revoke), `/tenant-keys` (+ rotate), `/fleet/health`, `/providers`, `/models`, `/agents` (+ detail, health, history, metrics, risk, routing, transitions, continuity plan, fallback chains), `/alerts` (+ actions), `/provider-incidents`, `/audit/events`, `/audit/anchors`, `/audit/verifications`, `/audit/exports`, `/capture-policies`, `/redaction-profiles`, `/blast-radius`, `/events/stream` | `/incidents` (+ detail, actions), `/approvals`, `/queue`, `/handoff-tasks/*`, `/kill-switches` (reads only; pulling returns 501), `/jobs/{id}` (no demo either) |

Live data is thinner than the demo's, and the console degrades rather than guessing:
- **Unscored agents** (no health snapshot) show "Not scored yet".
- **Agents with no routing row** show "No routing state yet".
- **The fleet** groups by tier, because the agent list carries no provider.
- **Primary and served models** come from `/models` plus the routing target.
- **Provider kill counts** come from `/blast-radius/provider/{id}`.
- **The audit log** lists the chain oldest first, 200 at a time, with **Newer events** paging.

### Live e2e

```bash
SIBYL_E2E_LIVE_URL=https://localhost:8443 SIBYL_E2E_PASSWORD=<dex persona password> npm run test:live
```

This needs a running, seeded stack. Nothing is started for you, and without `SIBYL_E2E_LIVE_URL` every test is skipped. It covers:
- sign-in, including an unknown workspace and sign-out revoking the session
- the Platform Admin as Admin on live data
- every API agent appearing as a fleet tile
- a scored agent's real factors, with the arithmetic checking
- closing an alert, which is refused without a verdict and recorded with one
- the Compliance Auditor verifying the chain
- minting a key (secret shown once) and revoking it
- tenant keys
- the demo marks on fallback panels

Tests that need seed data the stack doesn't have (no scored agent, no open alert) skip and say why.

## Checks

```bash
npm run typecheck
npm run lint
npm run build
npm run test:unit       # BFF live/fallback routing, auth relay, live principal, SSE resume, audit/agent helpers (no server)
npm run test:e2e        # e2e demo flow + axe accessibility (builds and serves on :3210)
npm run test:live       # live-mode e2e; needs SIBYL_E2E_LIVE_URL + SIBYL_E2E_PASSWORD (see Live e2e)
npm run test:visual     # screenshots at 320/768/1024/1440, light and dark
npm run test:budget     # needs a running prod server: BASE_URL=http://localhost:3000
npm run screenshots     # docs/screenshots/*.png against BASE_URL (default :3000)
```

Point any Playwright suite at an already running server with `PW_BASE_URL=http://localhost:3100`.

## Layout

```
app/(console)/        screens: fleet, agents/[id], incidents, queue, alerts, audit, runs, drift, sentinel, monitors, onboarding, settings
app/login, app/auth/  live sign-in (tenant first) and the step-up return page
app/api/bff/          BFF: [...path] (contract passthrough), auth/{login,step-up,logout} (OIDC relays), events/stream (SSE), session, demo
components/ui/        design system: Icon, StatePill, HealthRing, Sparkline, Timeline, Layer (sheet/dialog/palette), Toast, Bits
components/shell/     AppShell (glass sidebar + toolbar), persona/tenant switcher (sign-out in live), step-up, kill switch, ⌘K palette, demo menu
components/auth/      sign-in form, step-up done, brand mark
lib/api/              generated contract types (npm run gen:api), sibyl-health/1 and sibyl-handoff/1 types, problems
lib/bff/              dispatch; live.ts (live/fallback routing rules), auth relays, live principal (/auth/me), SSE resume, CSRF
lib/agent-data.ts     agent-detail paths per mode, metric folding, chain in force
lib/audit-query.ts    audit filters vs the API's exact-match rules
lib/demo/             fixtures, scenario, routing/saga/approval/handoff/audit-chain engine (server-only)
lib/monitors/view.ts  external monitors (D53) and the unified findings feed: labels, forms, untrusted-text handling, snippets
lib/health/scoring.ts ML §3 score: 100 − Σ penalty (+ the worker's stored _clamp) = score
tests/unit, tests/live unit suite (no server) and live-mode e2e (running stack)
styles/               tokens (light + dark), base, components, glass, viz
```

Regenerate contract types after the OpenAPI changes: `npm run gen:api`.
