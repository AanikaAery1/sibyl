#!/usr/bin/env bash
# Create deploy/compose/.env, env/*.env (tunables, from the committed examples) and the runtime
# file secrets in env/secrets/ (directory 0700). Never overwrites an existing file.
# Real env and secret files are gitignored (deploy/compose/.gitignore).
#
#   deploy/compose/init-env.sh            # create what is missing
#   deploy/compose/init-env.sh --force    # regenerate everything (destroys old secrets!)
#   deploy/compose/init-env.sh --env-dir DIR --compose-env FILE   # elsewhere (tests, lanes);
#     then run compose with SIBYL_ENV_DIR=DIR and --env-file FILE. Under Colima, DIR must be
#     inside a VM-mounted path ($HOME) because compose bind-mounts the secret files.
#
# Outputs besides the env files:
#   env/secrets/<name>       one file per compose secret (see docker-compose.yml matrix)
#   env/public/<name>.pem    Ed25519 public keys of the three signing keys (not secret; the
#                            restore needs ledger_signing.pem, ops/runbooks/backup-restore.md)
#   env/public/snapshot_pin.json  the gateway's pinned first snapshot signing key (B12,
#                            $defs/signing_key: kid snapshot-<sha256(pub)[:16]>), always re-derived
#                            from secrets/snapshot_signing_key; register the same kid in
#                            sibyl.signing_key (ops/demo/up.sh does it for the demo)
#   env/public/anchor_key.json  the audit-anchor key (kid audit-anchor-<sha256(pub)[:16]>),
#                            registered as purpose audit_anchor; anchor_signing.pem is its PEM
#                            for `sibyl audit verify --public-key` (offline)
#   env/demo-password.env    the shared demo persona password (dex), 0600
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
examples="$here/env"
env_dir="${SIBYL_ENV_DIR:-$here/env}"
compose_env="$here/.env"
force=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) force=1 ;;
    --env-dir) env_dir="${2:?--env-dir needs a path}"; shift ;;
    --compose-env) compose_env="${2:?--compose-env needs a path}"; shift ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "init-env.sh: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

command -v openssl >/dev/null || { echo "init-env.sh: openssl is required" >&2; exit 1; }
umask 077
mkdir -p "$env_dir"
secrets="$env_dir/secrets"
public="$env_dir/public"
mkdir -p "$secrets" "$public"
chmod 700 "$secrets"

hex32() { openssl rand -hex 32; }
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
b64url32() { openssl rand 32 | b64url; }

# Secret name -> generator. Formats: passwords and salts hex(32 bytes); the KEK base64url of
# 32 bytes (LocalKek); signing keys base64url Ed25519 seeds (32 bytes).
HEX_SECRETS=(postgres_password db_password_migrate db_password_app db_password_ingest
  db_password_worker key_pepper session_secret oidc_client_secret dex_api_client_secret
  subject_salt scrub_salt)
SIGNING_KEYS=(snapshot_signing_key ledger_signing_key anchor_signing_key)
EMPTY_SECRETS=(gateway_tenant_keys gateway_ingest_key sim_gateway_key sim_ingest_key) # minted after first boot

write_secret() { # name value
  local target="$secrets/$1"
  if [[ -f "$target" && $force -eq 0 ]]; then
    echo "kept secrets/$1"
    return
  fi
  rm -f "$target"
  printf '%s' "$2" > "$target.tmp"
  # Compose bind-mounts file secrets and ignores uid/gid/mode, so the container user (10001,
  # postgres 999, dex 1001) must be able to read the file; the 0700 directory protects it.
  chmod 0444 "$target.tmp"
  mv "$target.tmp" "$target"
  echo "wrote secrets/$1"
}

signing_key() { # name -> seed secret + public PEM
  local name="$1" tmp
  if [[ -f "$secrets/$name" && $force -eq 0 ]]; then
    echo "kept secrets/$name"
    return
  fi
  tmp="$(mktemp -d)"
  openssl genpkey -algorithm ed25519 -out "$tmp/key.pem" 2>/dev/null
  write_secret "$name" "$(openssl pkey -in "$tmp/key.pem" -outform DER | tail -c 32 | b64url)"
  openssl pkey -in "$tmp/key.pem" -pubout -out "$public/${name%_key}.pem"
  chmod 0644 "$public/${name%_key}.pem"
  rm -rf "$tmp"
}

for name in "${HEX_SECRETS[@]}"; do
  [[ -f "$secrets/$name" && $force -eq 0 ]] && { echo "kept secrets/$name"; continue; }
  write_secret "$name" "$(hex32)"
done
[[ -f "$secrets/kek" && $force -eq 0 ]] && echo "kept secrets/kek" || write_secret kek "$(b64url32)"
for name in "${SIGNING_KEYS[@]}"; do signing_key "$name"; done
for name in "${EMPTY_SECRETS[@]}"; do
  [[ -f "$secrets/$name" && $force -eq 0 ]] && { echo "kept secrets/$name"; continue; }
  write_secret "$name" ""
done

# Public material, derived from the kept seeds on every run (never secret, always consistent;
# an Ed25519 PKCS#8 DER is a fixed 16-byte prefix + the 32-byte seed):
#   public/<name>.pem       re-created when missing (backup/restore need ledger_signing.pem;
#                           `sibyl audit verify --public-key` takes anchor_signing.pem)
#   public/snapshot_pin.json  the gateway's pinned first snapshot key (B12), kid snapshot-<sha16>
#   public/anchor_key.json    the audit-anchor key (lane U), kid audit-anchor-<sha16>
# The two JSON files are $defs/signing_key; ops/demo/up.sh registers both kids in
# sibyl.signing_key (purposes snapshot and audit_anchor).
derive_public() { # seed-secret-name [kid-prefix json-file]
  local name="$1" prefix="${2:-}" json="${3:-}" seed_b64 pad tmp pub kid
  seed_b64="$(tr '_-' '/+' < "$secrets/$name")"
  pad=$(( (4 - ${#seed_b64} % 4) % 4 ))
  seed_b64="$seed_b64$(printf '%*s' "$pad" '' | tr ' ' '=')"
  tmp="$(mktemp -d)"
  printf '%b' '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20' > "$tmp/seed.der"
  printf '%s' "$seed_b64" | openssl base64 -d -A >> "$tmp/seed.der"
  if [[ ! -f "$public/${name%_key}.pem" ]]; then
    openssl pkey -inform DER -in "$tmp/seed.der" -pubout -out "$public/${name%_key}.pem"
    chmod 0644 "$public/${name%_key}.pem"
    echo "wrote public/${name%_key}.pem"
  fi
  openssl pkey -inform DER -in "$tmp/seed.der" -pubout -outform DER | tail -c 32 > "$tmp/pub.raw"
  pub="$(b64url < "$tmp/pub.raw")"
  kid="$prefix$(openssl dgst -sha256 -r < "$tmp/pub.raw" | cut -c1-16)"
  rm -rf "$tmp"
  [[ -n "$json" ]] || return 0
  [[ ${#pub} -eq 43 && "$kid" =~ ^${prefix}[0-9a-f]{16}$ ]] || {
    echo "init-env.sh: cannot derive the public key of secrets/$name" >&2
    return 1
  }
  printf '{"kid":"%s","alg":"Ed25519","public_key":"%s"}\n' "$kid" "$pub" > "$public/$json.tmp"
  chmod 0644 "$public/$json.tmp"
  mv "$public/$json.tmp" "$public/$json"
  echo "wrote public/$json ($kid)"
}
derive_public snapshot_signing_key snapshot- snapshot_pin.json
derive_public anchor_signing_key audit-anchor- anchor_key.json
derive_public ledger_signing_key

demo_pw_file="$env_dir/demo-password.env"
if [[ -f "$demo_pw_file" && $force -eq 0 ]]; then
  # shellcheck disable=SC1090
  . "$demo_pw_file"
else
  SIBYL_DEMO_PERSONA_PASSWORD="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16)"
  printf 'SIBYL_DEMO_PERSONA_PASSWORD=%s\n' "$SIBYL_DEMO_PERSONA_PASSWORD" > "$demo_pw_file"
  echo "demo persona password (admin/operator/auditor) written to $demo_pw_file"
  rm -f "$secrets/dex_persona_hash" # the hash must follow the password
fi
if [[ ! -f "$secrets/dex_persona_hash" ]]; then
  if command -v htpasswd >/dev/null; then
    write_secret dex_persona_hash \
      "$(htpasswd -bnBC 10 "" "$SIBYL_DEMO_PERSONA_PASSWORD" | tr -d ':\n' | base64 | tr -d '\n')"
  else
    echo "init-env.sh: htpasswd not found; write the base64 bcrypt hash to secrets/dex_persona_hash" >&2
  fi
fi

for example in "$examples"/*.env.example; do
  name="$(basename "$example" .example)"
  [[ "$name" == "compose.env" ]] && continue
  target="$env_dir/$name"
  if [[ -f "$target" && $force -eq 0 ]]; then
    echo "kept $target"
  else
    cp "$example" "$target.tmp"
    mv "$target.tmp" "$target"
    echo "wrote $target"
  fi
done

# Env files from before the per-service split held every secret; compose would still pass
# them to every container that loads the file. Refuse to leave that in place silently.
legacy=0
for f in "$env_dir"/*.env; do
  [[ "$(basename "$f")" == "demo-password.env" ]] && continue
  if grep -Eq '^[A-Z0-9_]*(PASSWORD|SECRET|PEPPER|SALT|KEK|SIGNING_KEY|_KEYS?|_HASH(_B64)?)=.+' "$f"; then
    echo "init-env.sh: $f still holds secret values (pre-split layout); move them to" \
      "secrets/ and delete them from the env file, or rerun with --force" >&2
    legacy=1
  fi
done

if [[ ! -f "$compose_env" || $force -eq 1 ]]; then
  cp "$examples/compose.env.example" "$compose_env"
  echo "wrote $compose_env"
fi
exit "$legacy"
