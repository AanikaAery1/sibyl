#!/usr/bin/env bash
# Bring the whole Sibyl demo stack up in compose, healthy, ready for `sibyl seed`.
#
# usage: ops/demo/up.sh [--env-dir DIR] [--compose-env FILE] [--project NAME] [--no-build]
#                       [--timeout SECONDS]
#
# Steps: init-env (only what is missing) -> build the four images -> postgres -> bootstrap (roles,
# idempotent) -> migrate -> register the snapshot + audit-anchor signing keys and the `sim` dev host
# (ops/demo/register.py, as sibyl_migrate) -> every service with the sim profile, waiting for
# healthy -> print the URLs.
#
# Defaults: env dir deploy/compose/env, compose env deploy/compose/.env, project from that file
# (COMPOSE_PROJECT_NAME, else sibyl). Under Colima the env dir must be under $HOME (compose
# bind-mounts the file secrets). Behind a TLS-re-signing proxy set SIBYL_EXTRA_CA_FILE (shell or
# compose env) to its CA bundle; it is a build secret only.
# Stop with ops/demo/down.sh (same flags; --purge also deletes the volumes).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
compose_dir="$repo/deploy/compose"
env_dir="${SIBYL_ENV_DIR:-$compose_dir/env}"
compose_env="$compose_dir/.env"
project=""
build=1
timeout=300

die() { echo "up.sh: $*" >&2; exit "${2:-1}"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-dir) env_dir="${2:?--env-dir needs a path}"; shift ;;
    --compose-env) compose_env="${2:?--compose-env needs a path}"; shift ;;
    --project) project="${2:?--project needs a name}"; shift ;;
    --no-build) build=0 ;;
    --timeout) timeout="${2:?--timeout needs seconds}"; shift ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1" 2 ;;
  esac
  shift
done
[[ "$timeout" =~ ^[0-9]+$ ]] || die "--timeout must be whole seconds" 2
command -v docker >/dev/null || die "docker is not installed"
docker info >/dev/null 2>&1 || die "no Docker daemon (start Colima: colima start)"

# 1. Env and secrets: create only what is missing (never overwrites).
if [[ ! -s "$env_dir/secrets/kek" || ! -f "$compose_env" || ! -f "$env_dir/public/snapshot_pin.json" \
  || ! -f "$env_dir/public/anchor_key.json" ]]; then
  echo "==> init-env"
  bash "$compose_dir/init-env.sh" --env-dir "$env_dir" --compose-env "$compose_env" >/dev/null
fi
env_value() { # KEY -> value from the compose env file (last wins), empty if absent
  { grep -E "^$1=" "$compose_env" || true; } | tail -n 1 | cut -d= -f2-
}
[[ -n "$project" ]] || project="$(env_value COMPOSE_PROJECT_NAME)"
project="${project:-sibyl}"
extra_ca="${SIBYL_EXTRA_CA_FILE:-$(env_value SIBYL_EXTRA_CA_FILE)}"
extra_ca="${extra_ca/#\~/$HOME}"
[[ -z "$extra_ca" || -f "$extra_ca" ]] || die "SIBYL_EXTRA_CA_FILE=$extra_ca does not exist"

dc() {
  SIBYL_ENV_DIR="$env_dir" SIBYL_EXTRA_CA_FILE="$extra_ca" BUILDX_BAKE_ENTITLEMENTS_FS=0 \
    docker compose -p "$project" -f "$compose_dir/docker-compose.yml" \
    --env-file "$compose_env" --profile sim "$@"
}

# 2. Images: control (api/ingest/worker/migrate/bootstrap), gateway, console, sim.
if [[ $build -eq 1 ]]; then
  echo "==> build (project $project)"
  dc build api gateway console sibyl-sim
fi

# 3. Database: roles (bootstrap, admin credentials, idempotent), then the schema.
echo "==> postgres"
dc up -d --wait --wait-timeout "$timeout" postgres
echo "==> bootstrap"
dc --profile bootstrap run --rm bootstrap
echo "==> migrate"
dc run --rm --no-deps migrate

# 4. Signing keys (sibyl_migrate only): the snapshot key the gateway pins and the audit-anchor
#    key the worker signs anchors with, plus the `sim` dev host.
echo "==> register signing keys"
dc run --rm -T --no-deps \
  -e "SIBYL_SNAPSHOT_PIN=$(cat "$env_dir/public/snapshot_pin.json")" \
  -e "SIBYL_ANCHOR_PIN=$(cat "$env_dir/public/anchor_key.json")" \
  migrate python - < "$here/register.py"

# 5. Everything, healthy.
echo "==> up (every service, sim profile)"
if ! dc up -d --wait --wait-timeout "$timeout"; then
  dc ps -a >&2 || true
  die "the stack did not become healthy within ${timeout}s; see: docker compose -p $project logs"
fi

# 6. Status and URLs (published ports as compose mapped them).
port() { dc port "$1" "$2" 2>/dev/null | head -n 1 | sed 's/.*://'; }
echo
echo "==> services"
dc ps -a --format '  {{.Service}}\t{{.State}}\t{{.Health}}' | sort
cat <<EOF

Sibyl demo stack is up (project $project).
  console   https://localhost:$(port caddy 8443)
  api       https://localhost:$(port caddy 8443)/api/v1
  gateway   https://localhost:$(port caddy 8444)/v1
  ingest    https://localhost:$(port caddy 8445)/v1
  sim       http://localhost:$(port sibyl-sim 8300)   (doubles: https://localhost:$(port sibyl-sim 18082)/v1)
Trust Caddy's local CA once for curl / SDK use:
  docker compose -p $project cp caddy:/data/caddy/pki/authorities/local/root.crt ./sibyl-local-root.crt
Demo persona password (admin / operator / auditor): $env_dir/demo-password.env
Offline verification keys: sibyl audit verify --public-key $env_dir/public/anchor_signing.pem
  (erasure ledger: $env_dir/public/ledger_signing.pem; ops/runbooks/backup-restore.md)
Next: seed (sibyl seed --sim-host sim), mint the gateway keys into secrets/gateway_tenant_keys and
secrets/gateway_ingest_key, then re-create the gateway so it re-reads them:
  docker compose -p $project up -d --force-recreate gateway
EOF
