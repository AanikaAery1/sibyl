#!/usr/bin/env bash
# Codespace (real deployment): wait for Docker, run `make up` with the codespace's public URL,
# then print where to sign in. Safe to run again (make up is idempotent).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
docker info >/dev/null 2>&1 || { echo "start.sh: Docker did not start" >&2; exit 1; }

domain="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
if [[ -n "${CODESPACE_NAME:-}" ]]; then
  # The browser-facing origin: OIDC issuer, redirect URI and the console's CSRF origin follow it.
  export SIBYL_PUBLIC_URL="https://${CODESPACE_NAME}-8443.${domain}"
fi
make up

if [[ -n "${CODESPACE_NAME:-}" ]]; then
  cat <<EOF

Codespace URLs (forwarded ports are private to you by default):
  console   https://${CODESPACE_NAME}-8443.${domain}
  gateway   https://${CODESPACE_NAME}-8444.${domain}/v1   (inside the codespace: https://localhost:8444/v1)
  ingest    https://${CODESPACE_NAME}-8445.${domain}      (inside the codespace: https://localhost:8445)
Sign in as $(sed -n 's/^SIBYL_ADMIN_EMAIL=//p' deploy/compose/.env.real) with the password from: make password
Agents outside the codespace: make ports 8444/8445 public (Ports tab) or use
  gh codespace ports forward 8444:8444 8445:8445   (docs/setup/SETUP.md, Codespaces)
EOF
fi
