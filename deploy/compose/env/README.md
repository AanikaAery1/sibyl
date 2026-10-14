# Compose environment and secrets

Committed: `*.env.example` only, and they hold **tunables only**. Every password, key, salt and
token is a compose **file secret** under `secrets/` (gitignored), granted per service. The image
entrypoint (`deploy/docker/sibyl-entrypoint.sh`) exports `/run/secrets/<VAR>` as `<VAR>`, so a
service sees only the secrets it was granted and nothing secret appears in `docker inspect`.

`../init-env.sh` creates everything that is missing: env files from the examples, `secrets/`
(0700) with one file per secret, `public/*.pem` (the three Ed25519 public keys) and
`demo-password.env`. Run it once; `--force` regenerates everything and invalidates the database
role passwords (re-run `docker compose run --rm bootstrap` afterwards).

| File | Used by | Holds |
|---|---|---|
| `compose.env.example` → `../.env` | compose interpolation | project name, image tag, DB name, host ports, public URL, edge subnet + Caddy address, `SIBYL_EXTRA_CA_FILE` |
| `control.env` | api, ingest, worker | env flags, log settings, `SIBYL_KEK_ID` |
| `postgres.env` / `migrate.env` / `dex.env` / `gateway.env` / `sim.env` | one service each | non-secret settings only |
| `secrets/*` | per the matrix at the top of `../docker-compose.yml` | all secret material |
| `public/*.pem` | operators | ledger / snapshot / anchor public keys (the restore needs `ledger_signing.pem`) |
| `public/snapshot_pin.json` | gateway (config `snapshot_pin`) | pinned first snapshot signing key (B12) |

Secret matrix (enforced by `ci/tests/test_secrets.py`; `ci/tests/test_runtime_env.py` checks every
process starts with what it is granted): the KEK in api, ingest (B7: payload blobs are encrypted at
write time) and worker; the snapshot signing key only in api; the ledger and anchor signing keys
only in worker; each DB role password only in its process (plus the one-shot `bootstrap`); the
Postgres superuser password only in postgres and `bootstrap`; the pepper in api, ingest and gateway
(B12: the gateway verifies API keys locally); the scrub salt in ingest and gateway; the gateway's
tenant keys and its `ingest:write` key (`gateway_ingest_key`) only in the gateway.

`public/snapshot_pin.json` (not secret) is the gateway's pinned first snapshot signing key, derived
from `secrets/snapshot_signing_key` on every `init-env.sh` run and mounted as the compose config
`snapshot_pin`. Its `kid` must be the active `snapshot` row in `sibyl.signing_key` (with
`private_key_ref = env:SIBYL_SNAPSHOT_SIGNING_KEY`); `ops/demo/up.sh` registers it.

`SIBYL_ENV=live` in every env file, also for the local demo: D20 break-glass keys exist only as
live keys and the api refuses keys of another env. `SIBYL_DEMO=1` keeps the demo safe (R55:
credentials and snapshots only for the sibyl-sim doubles).

Secret files are mode 0444 inside the 0700 directory: compose bind-mounts file secrets and ignores
`uid`/`gid`/`mode` outside Swarm, so the container user (10001, postgres 999, dex 1001) must be able
to read them; the directory is the host-side boundary. Under Colima the env dir must be inside a
VM-mounted path (your home directory).

**Upgrading from the pre-split layout** (secrets in `control.env`, `api.env`, …): run `init-env.sh`
(it writes `secrets/` and exits non-zero while any env file still holds secret values), copy the old
values into the matching `secrets/` files if you must keep them (the old `SIBYL_MASTER_KEK` becomes
`secrets/kek`), then delete the secret lines and the obsolete `api.env`/`ingest.env`/`worker.env`.
Existing `blobstore` / `gateway_snapshot` volumes created by the old root-owned images need a one-off
`docker run --rm -v <project>_gateway_snapshot:/d alpine chown -R 10001:10001 /d` (fresh volumes
inherit uid 10001 from the images).

Escrow `secrets/kek`, `secrets/ledger_signing_key`, `secrets/anchor_signing_key` and
`secrets/key_pepper` offline in two places, never next to backups. Losing the KEK shreds every tenant
(project-shipper 3.5).

## Building images behind a TLS-re-signing proxy

If your network re-signs TLS (corporate inspection proxies), dependency downloads in the
image build fail certificate verification. Do **not** disable verification. Point
`SIBYL_EXTRA_CA_FILE` at the proxy's CA bundle (PEM) in `../.env` or the shell:

```sh
export SIBYL_EXTRA_CA_FILE=~/corp-ca.pem
BUILDX_BAKE_ENTITLEMENTS_FS=0 docker compose build
```

Compose v5 builds through Bake, which asks for an `fs.read` entitlement for a secret file
outside the build context. `BUILDX_BAKE_ENTITLEMENTS_FS=0` grants it for this invocation; the
alternative is answering the interactive prompt.

Compose passes the file as the optional BuildKit secret `extra_ca`. The Dockerfiles join it
with the system bundle on a tmpfs inside the two `uv sync` steps only, so the CA never lands
in an image layer and release images never contain it. Unset, compose passes the empty
`deploy/docker/no-extra-ca.pem` and the build uses the system bundle alone.

The proxy CA is a build-host concern only. Running containers that call out (provider
doubles excepted) use their own system trust store.
