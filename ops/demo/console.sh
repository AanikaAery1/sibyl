#!/usr/bin/env bash
# The console in demo mode (D55 "demo"): dummy data and the scripted scenario, no Postgres, no
# Docker, Node only. `make demo` runs this.
#
# usage: ops/demo/console.sh [--dev] [--port N] [--public-origin URL]
#   --dev                 next dev (hot reload) instead of the production build
#   --port N              listen port (default $PORT or 3000)
#   --public-origin URL   the origin browsers use when a forwarding proxy sits in front and
#                         rewrites Host (GitHub Codespaces: https://<codespace>-3000.app.github.dev).
#                         The console then runs on N+1 behind ops/demo/origin-proxy.mjs on N, which
#                         sets X-Forwarded-Host/-Proto to that origin so the CSRF origin check
#                         accepts it. Default: $SIBYL_PUBLIC_ORIGIN; in a Codespace it is derived.
# Env: SIBYL_DEMO_ANCHOR (fixed scenario start, ISO 8601) is passed through.
# The production build is cached in console/.next and redone when console sources change.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
console="$(cd "$here/../../console" && pwd)"
dev=0
port="${PORT:-3000}"
origin="${SIBYL_PUBLIC_ORIGIN:-}"

die() { echo "console.sh: $*" >&2; exit "${2:-1}"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) dev=1 ;;
    --port) port="${2:?--port needs a number}"; shift ;;
    --public-origin) origin="${2:?--public-origin needs a URL}"; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1" 2 ;;
  esac
  shift
done
[[ "$port" =~ ^[0-9]+$ ]] || die "--port must be a number" 2
if [[ -z "$origin" && -n "${CODESPACE_NAME:-}" && -n "${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-}" ]]; then
  origin="https://${CODESPACE_NAME}-${port}.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
fi
[[ -z "$origin" || "$origin" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
  || die "--public-origin must be scheme://host[:port]" 2

command -v node >/dev/null || die "Node.js 20.18 or later is required (docs/setup/SETUP.md)"
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>20||(a===20&&b>=18)?0:1)' \
  || die "Node.js 20.18 or later is required (found $(node --version))"

cd "$console"
if [[ ! -d node_modules || package-lock.json -nt node_modules/.package-lock.json ]]; then
  echo "==> npm ci (console)"
  npm ci --no-audit --no-fund
fi

export SIBYL_CONSOLE_MODE=demo NEXT_TELEMETRY_DISABLED=1
app_port="$port"
if [[ -n "$origin" ]]; then
  app_port=$((port + 1))
  echo "==> origin proxy :$port -> :$app_port for $origin"
  SIBYL_PUBLIC_ORIGIN="$origin" PROXY_PORT="$port" TARGET_PORT="$app_port" \
    node "$here/origin-proxy.mjs" &
  proxy_pid=$!
  trap 'kill "$proxy_pid" 2>/dev/null || true' EXIT
fi

if [[ $dev -eq 1 ]]; then
  echo "==> next dev on :$app_port (demo data)"
  PORT="$app_port" npm run dev
  exit $?
fi

stamp=.next/standalone/.sibyl-demo-build
if [[ ! -f "$stamp" ]] || [[ -n "$(find app components hooks lib styles proxy.ts next.config.ts package-lock.json -newer "$stamp" -print -quit 2>/dev/null)" ]]; then
  echo "==> next build (first run takes a minute or two)"
  npx next build
  rm -rf .next/standalone/.next/static
  cp -R .next/static .next/standalone/.next/static
  [[ ! -d public ]] || cp -R public .next/standalone/public
  touch "$stamp"
fi
echo "==> Sibyl console (demo data) on http://localhost:$port${origin:+  (public: $origin)}"
cd .next/standalone
PORT="$app_port" HOSTNAME="${HOSTNAME_BIND:-0.0.0.0}" node server.js
