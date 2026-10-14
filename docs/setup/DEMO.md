# Sibyl demo (dummy data)

The console with a scripted scenario and deterministic dummy data: no Docker, no database, nothing
to configure. Every screen is clickable.

**In the browser:** [Open in Codespaces (demo)](https://codespaces.new/MK-JKC/sibyl?devcontainer_path=.devcontainer/demo/devcontainer.json).
The console opens on port 3000 once it has built (a couple of minutes on first start).

**On your machine** (Node.js 20.18 or later, make, git):

```bash
git clone https://github.com/MK-JKC/sibyl.git && cd sibyl
make demo                 # http://localhost:3000   (PORT=3100 make demo for another port)
```

## What to look at

You start on **Fleet** as the **Platform Admin** of Meridian Logistics. The scenario starts with the
server:

| Time | What happens |
|---|---|
| 0:15 | Anthropic latency climbs |
| 0:30 | Hard Anthropic outage; seven agents go red |
| 0:36 | One provider incident, not seven alerts |
| 0:42 to 1:04 | Tier 1, 2 and 3 agents fail over to OpenAI; handoff packets land in the operator queue |
| 3:20 | A tier-1 move waits for a four-eyes approval |
| 10:00 | Anthropic recovers; alerts need a verdict |
| 15:00 to 17:00 | Canaried failback |

Also try the **Action policies** editor (simulate a tool call), **Held actions**, **Model drift**,
**Sentinel**, **Discovered agents**, **Runs** and **Audit** (verify the chain, then a tampered copy).
Switch persona (Admin, On-call Operator, Compliance Auditor) from the card at the bottom of the
sidebar; switch to the `northstar` tenant to see isolation. The purple **Demo data** chip replays,
pauses or skips the scenario.

## Next

- The same story on the real services, with simulated providers: `make demo-stack`, then
  [the quickstart](../quickstart.md).
- Your own agents: [REAL.md](REAL.md).
- Everything else: [SETUP.md](SETUP.md).

## Public demo on Render

`render.yaml` at the repository root deploys the console alone, in demo mode, as one always-on
web service (`sibyl-demo`). It serves only dummy data from memory: no API, database, keys or real
data, so nothing in it can reach a real deployment. Every visitor shares the same demo world, and it
resets when the service restarts (on Render's free plan, after 15 idle minutes).

1. In the Render dashboard choose **New > Blueprint**, connect GitHub and give Render's app access
   to this repository, then pick it. Render reads `render.yaml` and builds `console/Dockerfile`.
2. Render builds and serves it. The project's public demo runs this way at
   **https://sibyl-demo.onrender.com**; a new Blueprint gets its own `onrender.com` name. Every push
   to `main` that changes `console/` redeploys it.
