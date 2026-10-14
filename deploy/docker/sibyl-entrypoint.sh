#!/bin/sh
# Sibyl image entrypoint: export compose file secrets as environment variables, then exec.
#
# Compose mounts each secret a service is granted at /run/secrets/<target>; the target is
# the environment variable name the process reads (e.g. SIBYL_KEK, SIBYL_DB_PASSWORD).
# Key material therefore never appears in `docker inspect`, in env files, or in any other
# container: a service only sees the secrets compose granted it (deploy/compose, M8).
#
# POSIX sh on purpose (python slim images have dash, not bash). Trailing newlines are
# stripped. A value already set in the environment is overridden by the file, with a
# warning, so a stale env_file can never shadow the granted secret.
set -eu

dir="${SIBYL_SECRETS_DIR:-/run/secrets}"
if [ -d "$dir" ]; then
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    name="${f##*/}"
    case "$name" in
      SIBYL_*|DEX_*) ;;
      *) continue ;;
    esac
    case "$name" in
      *[!A-Z0-9_]*)
        echo "sibyl-entrypoint: ignoring secret with invalid name: $name" >&2
        continue
        ;;
    esac
    if eval "[ -n \"\${$name+x}\" ]"; then
      echo "sibyl-entrypoint: $name from $dir overrides the environment" >&2
    fi
    value="$(cat "$f")"
    export "$name=$value"
  done
fi

[ "$#" -gt 0 ] || { echo "sibyl-entrypoint: no command given" >&2; exit 64; }
exec "$@"
