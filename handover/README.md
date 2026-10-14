# Handover folder

Start with **[HANDOVER.md](HANDOVER.md)**: links, accounts, how to run, test and release, the rules
the code depends on, and the open work in priority order. This page says which file has what.

## In this folder

| File | What it has | Read it when |
|---|---|---|
| [HANDOVER.md](HANDOVER.md) ([PDF](pdf/Sibyl-Handover.pdf)) | The pick-up guide: what Sibyl is, links and accounts, run/test/release commands, repository map, where decisions are recorded, rules, open work | First |
| [pdf/Sibyl-Setup.pdf](pdf/Sibyl-Setup.pdf) | The setup guide ([`docs/setup/SETUP.md`](../docs/setup/SETUP.md)): prerequisites per OS, demo and real installs, connecting agents, Action Gate, external monitors, Sentinel, production hardening, troubleshooting | Installing or deploying |
| [pdf/Sibyl-Product.pdf](pdf/Sibyl-Product.pdf) | What Sibyl does and for whom: every capability with console screenshots, the demo and real modes, known limits, roadmap ([source](../docs/product/PRODUCT.md)) | Understanding the product |
| [pdf/Sibyl-Technical.pdf](pdf/Sibyl-Technical.pdf) | Architecture, data model and every subsystem with its build status, API, security, deployment, CI and limits ([source](../docs/pdf/technical.md)) | Changing the code |
| [pdf/Sibyl-Technical-Thesis.pdf](pdf/Sibyl-Technical-Thesis.pdf) | Why it is built this way: deterministic enforcement, advisory AI, the open monitoring edge ([source](../docs/strategy/TECHNICAL-THESIS.md)) | Making design decisions |
| [pdf/Sibyl-Sales-GTM.pdf](pdf/Sibyl-Sales-GTM.pdf) | Positioning, buyers, pricing ideas, proof points, objections, demo script, launch checklist ([source](../docs/pdf/sales-gtm.md)) | Talking to prospects |

## Elsewhere in the repository

| Path | What it has |
|---|---|
| [`README.md`](../README.md) | Overview, live demo and Codespaces links, quick start |
| [`docs/setup/DEMO.md`](../docs/setup/DEMO.md), [`REAL.md`](../docs/setup/REAL.md) | The two ways to run, step by step, including the Render demo |
| [`docs/quickstart.md`](../docs/quickstart.md) | Ten-minute tour of the full stack with the simulator |
| [`docs/guide/`](../docs/guide/) | User guides: concepts, Python SDK, API, operations, governance, security |
| [`examples/monitors/`](../examples/monitors/README.md) | Ready-to-run external monitor agents |
| [`CHANGELOG.md`](../CHANGELOG.md) | Release notes (1.0.0) |
| [`docs/council/DECISIONS.md`](../docs/council/DECISIONS.md) | Decisions D1–D55 |
| [`docs/council/build/LANES.md`](../docs/council/build/LANES.md) | Build rulings and lane ownership; wave specs beside it |
| [`docs/council/`](../docs/council/) | Specifications: architecture, API, data model, ML, roadmap |
| [`ops/runbooks/`](../ops/runbooks/README.md) | Operational runbooks (backup and restore, incidents) |
