#!/bin/sh
# Render dex's static config from env, then exec dex. Runs inside the dex image
# (busybox sh, sed, base64). POSIX sh on purpose: there is no bash in the image.
#
# DEX_CONFIG_TEMPLATE picks the template: /etc/sibyl-dex/config.yaml (the demo personas, the
# default) or /etc/sibyl-dex/config.real.yaml (the real deployment: one Platform Admin from
# SIBYL_ADMIN_EMAIL and SIBYL_ADMIN_SUBJECT; deploy/compose/docker-compose.real.yml).
set -eu

# Compose file secrets granted to dex (/run/secrets/DEX_*) become env vars; dex reads the
# client secrets via secretEnv. Nothing secret is passed through env files.
for f in /run/secrets/DEX_*; do
  [ -f "$f" ] || continue
  name="${f##*/}"
  case "$name" in *[!A-Z0-9_]*) continue ;; esac
  value="$(cat "$f")"
  export "$name=$value"
done

: "${SIBYL_PUBLIC_URL:?SIBYL_PUBLIC_URL is required}"
: "${DEX_PERSONA_HASH_B64:?DEX_PERSONA_HASH_B64 is required (file secret dex_persona_hash)}"
: "${DEX_CONSOLE_CLIENT_SECRET:?DEX_CONSOLE_CLIENT_SECRET is required}"
: "${DEX_API_CLIENT_SECRET:?DEX_API_CLIENT_SECRET is required}"
template="${DEX_CONFIG_TEMPLATE:-/etc/sibyl-dex/config.yaml}"

case "$SIBYL_PUBLIC_URL" in
  https://*) ;;
  *) echo "render.sh: SIBYL_PUBLIC_URL must be https://" >&2; exit 1 ;;
esac
case "$SIBYL_PUBLIC_URL" in
  *'|'*|*' '*|*'"'*) echo "render.sh: SIBYL_PUBLIC_URL holds an invalid character" >&2; exit 1 ;;
esac

# The real template binds one admin; refuse values that could break out of the YAML scalar.
admin_email="${SIBYL_ADMIN_EMAIL:-}"
admin_subject="${SIBYL_ADMIN_SUBJECT:-}"
if grep -q '__SIBYL_ADMIN_' "$template"; then
  case "$admin_email" in
    ''|*[!A-Za-z0-9.@_+-]*) echo "render.sh: SIBYL_ADMIN_EMAIL is missing or invalid" >&2; exit 1 ;;
    ?*@?*.?*) ;;
    *) echo "render.sh: SIBYL_ADMIN_EMAIL is not an email address" >&2; exit 1 ;;
  esac
  case "$admin_subject" in
    ''|*[!A-Za-z0-9-]*) echo "render.sh: SIBYL_ADMIN_SUBJECT is missing or invalid" >&2; exit 1 ;;
  esac
fi

persona_hash=$(printf '%s' "$DEX_PERSONA_HASH_B64" | base64 -d)
case "$persona_hash" in
  '$2a$'*|'$2b$'*|'$2y$'*) ;;
  *) echo "render.sh: DEX_PERSONA_HASH_B64 does not decode to a bcrypt hash" >&2; exit 1 ;;
esac

out=/tmp/dex-config.yaml
umask 077
sed -e "s|__SIBYL_PUBLIC_URL__|${SIBYL_PUBLIC_URL}|g" \
    -e "s|__DEX_PERSONA_HASH__|\"${persona_hash}\"|g" \
    -e "s|__SIBYL_ADMIN_EMAIL__|${admin_email}|g" \
    -e "s|__SIBYL_ADMIN_SUBJECT__|${admin_subject}|g" \
    "$template" > "$out"

exec dex serve "$out"
