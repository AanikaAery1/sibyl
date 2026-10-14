#!/usr/bin/env bash
# Create a lane worktree with its own branch, ports and database name (ROADMAP 4.6).
#
# usage: ci/worktree.sh [options] <lane> <slot>
#   <lane>   lane id, e.g. W1-A, G-hot (letters, digits, - and _)
#   <slot>   0-9; host ports are offset by 100 x slot (0 = the main checkout)
# options:
#   --dry-run        print the computed KEY=VALUE environment and do nothing else
#   --wave W         branch prefix wave (default: lane prefix "w<N>" if present, else w0)
#   --repo DIR       repository to branch from (default: this script's repository)
#   --root DIR       parent directory for worktrees (default: <repo>/../sibyl-wt)
#   --base REF       start point for the branch (default: HEAD)
#   --create-db      create database sibyl_<lane> on the shared PG17 dev cluster (:5433)
#   -h, --help       show this help
#
# Writes <worktree>/.env.lane (source it for uv-run services) and the same content to
# <worktree>/deploy/compose/.env (compose interpolation). Both paths are gitignored.
set -euo pipefail

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "worktree.sh: $*" >&2; exit 2; }

dry_run=0 wave="" repo="" root="" base="HEAD" create_db=0
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1 ;;
    --wave) wave="${2:?--wave needs a value}"; shift ;;
    --repo) repo="${2:?--repo needs a path}"; shift ;;
    --root) root="${2:?--root needs a path}"; shift ;;
    --base) base="${2:?--base needs a ref}"; shift ;;
    --create-db) create_db=1 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; args+=("$@"); break ;;
    -*) die "unknown option $1" ;;
    *) args+=("$1") ;;
  esac
  shift
done
[[ ${#args[@]} -eq 2 ]] || { usage >&2; exit 2; }
lane_raw="${args[0]}" slot="${args[1]}"

[[ "$lane_raw" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ ]] || die "invalid lane '$lane_raw'"
[[ "$slot" =~ ^[0-9]$ ]] || die "slot must be 0-9, got '$slot'"
lane="$(printf '%s' "$lane_raw" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
[[ -n "$lane" ]] || die "lane '$lane_raw' has no letters or digits"
if [[ -z "$wave" ]]; then
  if [[ "$lane" =~ ^(w[0-9]) ]]; then wave="${BASH_REMATCH[1]}"; else wave="w0"; fi
fi
[[ "$wave" =~ ^[a-z0-9]+$ ]] || die "invalid wave '$wave'"

repo="${repo:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
root="${root:-$(cd "$repo/.." && pwd)/sibyl-wt}"
offset=$((slot * 100))
dev_pg_port="${SIBYL_DEV_PGPORT:-5433}"

# Base ports for slot 0. Compose-published: HTTPS/GATEWAY_TLS/INGEST_TLS/SIM/PG (must match
# docker-compose.yml defaults; tested). Native uv-run services: API/INGEST/WORKER/GATEWAY/
# CONSOLE. No two bases differ by a multiple of 100, so slots never collide (tested).
# Each slot also gets its own edge subnet, pinned Caddy/console addresses (trusted proxies, M4)
# and a dynamic range (upper half) that keeps Docker off the pinned addresses.
lane_env() {
  cat <<EOF
COMPOSE_PROJECT_NAME=sibyl_${lane}
SIBYL_LANE=${lane}
SIBYL_SLOT=${slot}
SIBYL_PORT_OFFSET=${offset}
SIBYL_BRANCH=lane/${wave}-${lane}
SIBYL_WORKTREE=${root}/${lane}
SIBYL_DB_NAME=sibyl_${lane}
SIBYL_PG_DSN=postgresql://postgres@localhost:${dev_pg_port}/sibyl_${lane}
SIBYL_PORT_HTTPS=$((8443 + offset))
SIBYL_PORT_GATEWAY_TLS=$((8444 + offset))
SIBYL_PORT_INGEST_TLS=$((8445 + offset))
SIBYL_PORT_SIM=$((8300 + offset))
SIBYL_PORT_SIM_DOUBLES=$((18082 + offset))
SIBYL_PORT_PG=$((5434 + offset))
SIBYL_PUBLIC_URL=https://localhost:$((8443 + offset))
SIBYL_EDGE_SUBNET=172.30.${slot}.0/24
SIBYL_CADDY_IP=172.30.${slot}.10
SIBYL_CONSOLE_IP=172.30.${slot}.11
SIBYL_EDGE_IP_RANGE=172.30.${slot}.128/25
SIBYL_API_PORT=$((8010 + offset))
SIBYL_INGEST_PORT=$((8011 + offset))
SIBYL_WORKER_PORT=$((8012 + offset))
SIBYL_GATEWAY_PORT=$((8080 + offset))
SIBYL_CONSOLE_PORT=$((3000 + offset))
EOF
}

if [[ $dry_run -eq 1 ]]; then
  lane_env
  exit 0
fi

wt="${root}/${lane}"
branch="lane/${wave}-${lane}"
[[ -e "$wt" ]] && die "$wt already exists; remove it with: git worktree remove $wt"
if git -C "$repo" show-ref --verify --quiet "refs/heads/${branch}"; then
  die "branch ${branch} already exists"
fi
mkdir -p "$root"
git -C "$repo" worktree add -q -b "$branch" "$wt" "$base"

mkdir -p "$wt/deploy/compose"
lane_env > "$wt/.env.lane"
cp "$wt/.env.lane" "$wt/deploy/compose/.env"

if [[ $create_db -eq 1 ]]; then
  pgbin="${PGBIN:-/opt/homebrew/opt/postgresql@17/bin}"
  if "$pgbin/psql" -X -q -At -h localhost -p "$dev_pg_port" -U postgres -d postgres \
      -c "SELECT 1 FROM pg_database WHERE datname = 'sibyl_${lane}'" | grep -q 1; then
    echo "database sibyl_${lane} already exists"
  else
    "$pgbin/createdb" -h localhost -p "$dev_pg_port" -U postgres "sibyl_${lane}"
    echo "created database sibyl_${lane} on :${dev_pg_port}"
  fi
fi

echo "worktree ${wt} on ${branch}, ports +${offset}; next: cd ${wt} && set -a && . ./.env.lane && set +a"
