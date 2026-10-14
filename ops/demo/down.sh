#!/usr/bin/env bash
# Stop the Sibyl demo stack started by ops/demo/up.sh.
#
# usage: ops/demo/down.sh [--env-dir DIR] [--compose-env FILE] [--project NAME] [--purge]
#
# Keeps the volumes (database, blobs, ledger, gateway snapshot, Caddy CA) unless --purge, which
# deletes them: the next up.sh starts from an empty database. Env and secret files are never
# touched (delete deploy/compose/env/secrets yourself to rotate everything).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_dir="$(cd "$here/../.." && pwd)/deploy/compose"
env_dir="${SIBYL_ENV_DIR:-$compose_dir/env}"
compose_env="$compose_dir/.env"
project=""
purge=()

die() { echo "down.sh: $*" >&2; exit "${2:-1}"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-dir) env_dir="${2:?--env-dir needs a path}"; shift ;;
    --compose-env) compose_env="${2:?--compose-env needs a path}"; shift ;;
    --project) project="${2:?--project needs a name}"; shift ;;
    --purge) purge=(--volumes) ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1" 2 ;;
  esac
  shift
done
[[ -f "$compose_env" ]] || die "no compose env file at $compose_env (nothing was brought up?)"
if [[ -z "$project" ]]; then
  project="$({ grep -E '^COMPOSE_PROJECT_NAME=' "$compose_env" || true; } | tail -n 1 | cut -d= -f2-)"
fi
project="${project:-sibyl}"

SIBYL_ENV_DIR="$env_dir" docker compose -p "$project" -f "$compose_dir/docker-compose.yml" \
  --env-file "$compose_env" --profile sim --profile bootstrap \
  down --remove-orphans ${purge[@]+"${purge[@]}"}
