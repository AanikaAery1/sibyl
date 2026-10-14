# Sibyl for real agents

The full stack (Postgres 17, API, ingest, worker, gateway, console, Caddy TLS, OIDC sign-in) without
the simulator, bootstrapped with your first workspace and its Platform Admin.

**In the browser:** [Open in Codespaces (real)](https://codespaces.new/MK-JKC/sibyl?devcontainer_path=.devcontainer/real/devcontainer.json)
(4-core machine; about 10 minutes on first start). The terminal prints the console URL and the admin
email; `make password` shows the password.

**On your machine** (Docker with Compose 2.24.4+, make, git, openssl, htpasswd; see
[prerequisites](SETUP.md#prerequisites)):

```bash
git clone https://github.com/MK-JKC/sibyl.git && cd sibyl
export SIBYL_TENANT_SLUG=acme SIBYL_ADMIN_EMAIL=you@acme.example    # optional
make up                   # behind a TLS-inspection proxy: SIBYL_EXTRA_CA_FILE=~/.config/corp-ca.pem make up
make ca                   # trust ./sibyl-local-root.crt (Caddy's local CA)
make password             # the admin's password for the bundled sign-in
```

Open https://localhost:8443, enter the workspace slug and sign in. Then:

1. **Keys:** `make key NAME=my-agent` (SDK) and `make key NAME=my-agent KIND=gateway`.
2. **Connect an agent**, any of:
   - the gateway: base URL `https://localhost:8444/v1` (OpenAI) or `https://localhost:8444`
     (Anthropic, Gemini) plus the header `X-Sibyl-Key`;
   - `sibyl.instrument()` in code, or `sibyl-run app.py` with no code change, with
     `SIBYL_API_KEY`, `SIBYL_ENDPOINT=https://localhost:8445`, `SIBYL_API_URL=https://localhost:8443`.
3. **Action Gate:** write and approve a first policy (**Action policies**).
4. **Sentinel:** **Settings → Sentinel** with your own model key and a daily budget.
5. **External monitors:** register one under **Monitors** (to be confirmed, D53).

Day to day: `make status`, `make logs`, `make down` (`PURGE=1` deletes the data).

The full walkthrough, production hardening (your own OIDC provider, real certificates, backups,
upgrades) and troubleshooting: [SETUP.md](SETUP.md#real-deployment-walkthrough).
