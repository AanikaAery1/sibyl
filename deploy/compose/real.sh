#!/usr/bin/env bash
# Sibyl REAL deployment (D55): the full stack for real agents, without the simulator.
#
# usage: deploy/compose/real.sh <command> [options]
#   up        first run: env + secrets, build (or pull with SIBYL_IMAGE_TAG), Postgres roles,
#             migrations, signing keys, every service healthy, then the tenant, the Platform
#             Admin, a default capture policy and the gateway's keys; prints how to log in.
#             Later runs are idempotent (they keep secrets, data and keys).
#   down      stop (keeps volumes); --purge also deletes the database, blobs and Caddy CA
#   status    services, health and URLs
#   logs      follow logs (all services, or the ones named after --)
#   key       mint an API key for an agent (printed ONCE):
#               real.sh key --name NAME [--kind sdk|gateway] [--agent SLUG] [--days N]
#   password  print the bundled-dex admin password (only when asked)
#   ca        copy Caddy's local root CA to ./sibyl-local-root.crt (trust it for SDK/curl use)
# options:
#   --project NAME      compose project (default: COMPOSE_PROJECT_NAME in the env file, sibyl-real)
#   --env-dir DIR       secrets and env files (default deploy/compose/env-real; under $HOME on Colima)
#   --compose-env FILE  compose interpolation file (default deploy/compose/.env.real)
#   --no-build          up: use the images already built
#   --timeout SECONDS   up: wait this long for healthy services (default 300)
# Settings live in the compose env file (created from env/compose.env.example + real.env.example);
# these shell variables, when set, are written into it on every run: SIBYL_PUBLIC_URL,
# SIBYL_SITE_HOST, SIBYL_TLS, SIBYL_TLS_CERT_DIR, SIBYL_BIND_ADDRESS, SIBYL_PORT_HTTPS,
# SIBYL_PORT_GATEWAY_TLS, SIBYL_PORT_INGEST_TLS, SIBYL_PORT_PG, SIBYL_OIDC_ISSUER,
# SIBYL_OIDC_CLIENT_ID, SIBYL_OIDC_EMAIL_DOMAINS, SIBYL_ADMIN_EMAIL, SIBYL_ADMIN_SUBJECT,
# SIBYL_TENANT_SLUG, SIBYL_TENANT_NAME, SIBYL_BOOTSTRAP_CAPTURE_MODE, SIBYL_IMAGE_TAG,
# SIBYL_IMAGE_REGISTRY, SIBYL_EXTRA_CA_FILE, SIBYL_EDGE_SUBNET, SIBYL_CADDY_IP, SIBYL_CONSOLE_IP,
# SIBYL_EDGE_IP_RANGE, SIBYL_UPSTREAM_CA_HOST_FILE. Optional: SIBYL_OIDC_CLIENT_SECRET_FILE (your IdP's client secret, copied
# into the file secret oidc_client_secret). Guide: docs/setup/SETUP.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
env_dir="${SIBYL_REAL_ENV_DIR:-$here/env-real}"
compose_env="${SIBYL_REAL_COMPOSE_ENV:-$here/.env.real}"
project=""
build=1
timeout=300
purge=()
key_name="" key_kind="sdk" key_agent="" key_days=""
extra=()

OVERRIDABLE=(SIBYL_PUBLIC_URL SIBYL_SITE_HOST SIBYL_TLS SIBYL_TLS_CERT_DIR SIBYL_BIND_ADDRESS
  SIBYL_PORT_HTTPS SIBYL_PORT_GATEWAY_TLS SIBYL_PORT_INGEST_TLS SIBYL_PORT_PG SIBYL_OIDC_ISSUER
  SIBYL_OIDC_CLIENT_ID SIBYL_OIDC_EMAIL_DOMAINS SIBYL_ADMIN_EMAIL SIBYL_ADMIN_SUBJECT
  SIBYL_TENANT_SLUG SIBYL_TENANT_NAME SIBYL_BOOTSTRAP_CAPTURE_MODE SIBYL_IMAGE_TAG
  SIBYL_IMAGE_REGISTRY SIBYL_EXTRA_CA_FILE SIBYL_EDGE_SUBNET SIBYL_CADDY_IP SIBYL_CONSOLE_IP
  SIBYL_EDGE_IP_RANGE SIBYL_UPSTREAM_CA_HOST_FILE)

die() { echo "real.sh: $*" >&2; exit "${2:-1}"; }
say() { echo "==> $*"; }
usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

[[ $# -gt 0 ]] || { usage; exit 2; }
cmd="$1"; shift
case "$cmd" in
  up|down|status|logs|key|password|ca) ;;
  -h|--help|help) usage; exit 0 ;;
  *) die "unknown command $cmd (try --help)" 2 ;;
esac
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) project="${2:?--project needs a name}"; shift ;;
    --env-dir) env_dir="${2:?--env-dir needs a path}"; shift ;;
    --compose-env) compose_env="${2:?--compose-env needs a path}"; shift ;;
    --no-build) build=0 ;;
    --timeout) timeout="${2:?--timeout needs seconds}"; shift ;;
    --purge) purge=(--volumes) ;;
    --name) key_name="${2:?--name needs a value}"; shift ;;
    --kind) key_kind="${2:?--kind needs sdk or gateway}"; shift ;;
    --agent) key_agent="${2:?--agent needs a slug}"; shift ;;
    --days) key_days="${2:?--days needs a number}"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; extra=("$@"); break ;;
    *) die "unknown argument $1" 2 ;;
  esac
  shift
done
[[ "$timeout" =~ ^[0-9]+$ ]] || die "--timeout must be whole seconds" 2

# --- compose env file: KEY=value lines, last one wins -------------------------------------------
env_get() { # KEY -> value (empty if absent)
  [[ -f "$compose_env" ]] || return 0
  { grep -E "^$1=" "$compose_env" || true; } | tail -n 1 | cut -d= -f2-
}
env_set() { # KEY VALUE: replace the key's lines with one, or append
  local tmp
  case "$2" in *$'\n'*) die "$1 must be a single line" 2 ;; esac
  tmp="$(mktemp "${compose_env}.XXXXXX")"
  { grep -vE "^$1=" "$compose_env" || true; } > "$tmp"
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$compose_env"
}

write_compose_env() {
  if [[ ! -f "$compose_env" ]]; then
    say "create $compose_env"
    # The demo defaults, minus every key real.env.example sets, then the real defaults.
    local keys
    keys="$(sed -n 's/^\([A-Z0-9_]*\)=.*/\1/p' "$here/real.env.example" | paste -sd'|' -)"
    (
      umask 077
      { grep -vE "^($keys)=" "$here/env/compose.env.example" || true; echo; cat "$here/real.env.example"; } \
        > "$compose_env"
    )
  fi
  local name
  for name in "${OVERRIDABLE[@]}"; do
    if [[ -n "${!name+x}" ]]; then env_set "$name" "${!name}"; fi
  done
  [[ -z "$project" ]] || env_set COMPOSE_PROJECT_NAME "$project"
  # Derived values (recomputed every run, so compose can run without this script later).
  local port host url issuer
  port="$(env_get SIBYL_PORT_HTTPS)"; port="${port:-8443}"
  host="$(env_get SIBYL_SITE_HOST)"; host="${host:-localhost}"
  url="$(env_get SIBYL_PUBLIC_URL)"
  if [[ -z "$url" ]]; then
    url="https://$host"; [[ "$port" == "443" ]] || url="$url:$port"
    env_set SIBYL_PUBLIC_URL "$url"
  fi
  [[ "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
    || die "SIBYL_PUBLIC_URL must be https://host[:port] with no path (got $url)" 2
  env_set SIBYL_PUBLIC_AUTHORITY "${url#https://}"
  issuer="$(env_get SIBYL_OIDC_ISSUER)"
  if [[ -z "$issuer" ]]; then
    env_set SIBYL_OIDC_ISSUER_EFFECTIVE "$url/dex"
    env_set SIBYL_OIDC_INTERNAL_EFFECTIVE "http://dex:5556/dex"
  else
    [[ "$issuer" == https://* ]] || die "SIBYL_OIDC_ISSUER must be https://" 2
    env_set SIBYL_OIDC_ISSUER_EFFECTIVE "${issuer%/}"
    env_set SIBYL_OIDC_INTERNAL_EFFECTIVE ""
  fi
  # The bundled dex's user id for the admin (dex derives the token `sub` from it; Sibyl binds the
  # admin by verified email at the first sign-in, so this never needs to be known elsewhere).
  [[ -n "$(env_get SIBYL_DEX_ADMIN_ID)" ]] || env_set SIBYL_DEX_ADMIN_ID "$(new_uuid)"
}

new_uuid() {
  if command -v uuidgen >/dev/null; then uuidgen | tr 'A-Z' 'a-z'
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then cat /proc/sys/kernel/random/uuid
  else
    local h; h="$(openssl rand -hex 16)"
    printf '%s-%s-4%s-a%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" "${h:17:3}" "${h:20:12}"
  fi
}

# --- compose ------------------------------------------------------------------------------------
compose_files=()
profiles=()
setup_compose() {
  [[ -f "$compose_env" ]] || die "no $compose_env yet: run \`make up\` (real.sh up) first"
  project="${project:-$(env_get COMPOSE_PROJECT_NAME)}"
  project="${project:-sibyl-real}"
  compose_files=(-f "$here/docker-compose.yml" -f "$here/docker-compose.real.yml")
  [[ -z "$(env_get SIBYL_IMAGE_TAG)" ]] || compose_files+=(-f "$here/docker-compose.images.yml")
  profiles=()
  [[ -n "$(env_get SIBYL_OIDC_ISSUER)" ]] || profiles+=(--profile dex)
}
extra_ca_file() {
  local ca; ca="$(env_get SIBYL_EXTRA_CA_FILE)"; ca="${ca/#\~/$HOME}"
  [[ -z "$ca" || -f "$ca" ]] || die "SIBYL_EXTRA_CA_FILE=$ca does not exist"
  printf '%s' "$ca"
}
dc() {
  SIBYL_ENV_DIR="$env_dir" SIBYL_EXTRA_CA_FILE="$(extra_ca_file)" BUILDX_BAKE_ENTITLEMENTS_FS=0 \
    docker compose -p "$project" "${compose_files[@]}" --env-file "$compose_env" \
    ${profiles[@]+"${profiles[@]}"} "$@"
}
need_docker() {
  command -v docker >/dev/null || die "docker is not installed (docs/setup/SETUP.md, prerequisites)"
  docker info >/dev/null 2>&1 || die "no Docker daemon (Docker Desktop: start it; Colima: colima start)"
  local v; v="$(docker compose version --short 2>/dev/null || true)"
  [[ -n "$v" ]] || die "Docker Compose v2 is required (docker compose version)"
  v="${v#v}"
  local major minor patch
  IFS=. read -r major minor patch <<< "${v%%-*}"
  if (( major < 2 || (major == 2 && (minor < 24 || (minor == 24 && ${patch:-0} < 4))) )); then
    die "Docker Compose >= 2.24.4 is required (found $v)"
  fi
}
port_free() { # host port -> 0 when nothing listens on it locally
  ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}
check_ports() {
  local name port mine
  mine="$(dc ps -q caddy 2>/dev/null || true)"
  [[ -z "$mine" ]] || return 0 # our own stack holds them
  for name in SIBYL_PORT_HTTPS SIBYL_PORT_GATEWAY_TLS SIBYL_PORT_INGEST_TLS SIBYL_PORT_PG; do
    port="$(env_get "$name")"
    [[ -z "$port" ]] && continue
    port_free "$port" || die "port $port ($name) is in use; set $name=<free port> in $compose_env or stop what holds it (the demo stack: make demo-stack-down)"
  done
}
put_secret() { # name value: overwrite one file secret without echoing it
  local f="$env_dir/secrets/$1"
  rm -f "$f.tmp"
  (umask 077; printf '%s' "$2" > "$f.tmp")
  chmod 0444 "$f.tmp"
  mv -f "$f.tmp" "$f"
}
url_of() { env_get SIBYL_PUBLIC_URL; }
url_port() { # service-port-name default -> https://host:port
  local authority host port
  authority="$(env_get SIBYL_PUBLIC_AUTHORITY)"; host="${authority%%:*}"
  port="$(env_get "$1")"; port="${port:-$2}"
  printf 'https://%s:%s' "$host" "$port"
}

# --- commands -----------------------------------------------------------------------------------
cmd_up() {
  need_docker
  command -v openssl >/dev/null || die "openssl is required"
  write_compose_env
  setup_compose
  check_ports
  say "init-env ($env_dir)"
  bash "$here/init-env.sh" --env-dir "$env_dir" --compose-env "$compose_env" >/dev/null
  local secret_file; secret_file="$(env_get SIBYL_OIDC_CLIENT_SECRET_FILE)"
  secret_file="${SIBYL_OIDC_CLIENT_SECRET_FILE:-$secret_file}"
  if [[ -n "$secret_file" ]]; then
    [[ -s "$secret_file" ]] || die "SIBYL_OIDC_CLIENT_SECRET_FILE=$secret_file is missing or empty"
    put_secret oidc_client_secret "$(tr -d '\r\n' < "$secret_file")"
    say "oidc_client_secret taken from $secret_file"
  fi

  if [[ -n "$(env_get SIBYL_IMAGE_TAG)" ]]; then
    say "pull images ($(env_get SIBYL_IMAGE_REGISTRY):$(env_get SIBYL_IMAGE_TAG))"
    dc pull --quiet postgres caddy api gateway console ${profiles[@]+dex}
  elif [[ $build -eq 1 ]]; then
    say "build images (project $project)"
    dc build api gateway console
  fi

  say "postgres"
  dc up -d --wait --wait-timeout "$timeout" postgres
  say "bootstrap (roles)"
  dc --profile bootstrap run --rm bootstrap >/dev/null
  say "migrate"
  dc run --rm --no-deps migrate
  say "register signing keys"
  dc run --rm -T --no-deps -e SIBYL_REGISTER_DEV_HOST= \
    -e "SIBYL_SNAPSHOT_PIN=$(cat "$env_dir/public/snapshot_pin.json")" \
    -e "SIBYL_ANCHOR_PIN=$(cat "$env_dir/public/anchor_key.json")" \
    migrate python - < "$repo/ops/demo/register.py"

  say "start services"
  if ! dc up -d --wait --wait-timeout "$timeout"; then
    dc ps -a >&2 || true
    die "the stack did not become healthy within ${timeout}s; see: make logs"
  fi

  say "bootstrap tenant and admin"
  local mint=0 out k v tenant_key="" ingest_key="" capture=""
  [[ -s "$env_dir/secrets/gateway_tenant_keys" && -s "$env_dir/secrets/gateway_ingest_key" ]] || mint=1
  out="$(dc run --rm -T --no-deps \
    -e "SIBYL_BOOTSTRAP_TENANT=$(env_get SIBYL_TENANT_SLUG)" \
    -e "SIBYL_BOOTSTRAP_TENANT_NAME=$(env_get SIBYL_TENANT_NAME)" \
    -e "SIBYL_BOOTSTRAP_ISSUER=$(env_get SIBYL_OIDC_ISSUER_EFFECTIVE)" \
    -e "SIBYL_BOOTSTRAP_CLIENT_ID=$(env_get SIBYL_OIDC_CLIENT_ID)" \
    -e "SIBYL_BOOTSTRAP_ADMIN_SUBJECT=$(env_get SIBYL_ADMIN_SUBJECT)" \
    -e "SIBYL_BOOTSTRAP_ADMIN_EMAIL=$(env_get SIBYL_ADMIN_EMAIL)" \
    -e "SIBYL_BOOTSTRAP_EMAIL_DOMAINS=$(env_get SIBYL_OIDC_EMAIL_DOMAINS)" \
    -e "SIBYL_BOOTSTRAP_CAPTURE_MODE=$(env_get SIBYL_BOOTSTRAP_CAPTURE_MODE)" \
    -e "SIBYL_BOOTSTRAP_GATEWAY_KEYS=$mint" \
    api python - < "$here/real/bootstrap.py")" || die "bootstrap failed (see above)"
  while IFS='=' read -r k v; do
    case "$k" in
      gateway_tenant_key) tenant_key="$v" ;;
      gateway_ingest_key) ingest_key="$v" ;;
      capture_policy) capture="$v" ;;
    esac
  done <<< "$out"
  if [[ -n "$tenant_key" && -n "$ingest_key" ]]; then
    put_secret gateway_tenant_keys "$tenant_key"
    put_secret gateway_ingest_key "$ingest_key"
    say "gateway keys written to $env_dir/secrets (not shown); restarting the gateway"
    dc up -d --force-recreate --wait --wait-timeout "$timeout" gateway
  fi
  print_next "$capture"
}

print_next() {
  local capture="${1:-}" slug url email
  slug="$(env_get SIBYL_TENANT_SLUG)"; url="$(url_of)"; email="$(env_get SIBYL_ADMIN_EMAIL)"
  cat <<EOF

Sibyl is up (project $project, tenant "$slug").
  console   $url        (sign in to workspace "$slug")
  api       $url/api/v1
  gateway   $(url_port SIBYL_PORT_GATEWAY_TLS 8444)/v1      OpenAI / Anthropic / Gemini clients
  ingest    $(url_port SIBYL_PORT_INGEST_TLS 8445)          SDK (sibyl.instrument(), sibyl-run)
EOF
  if [[ -z "$(env_get SIBYL_OIDC_ISSUER)" ]]; then
    cat <<EOF
Admin login (bundled dex): $email
  password: make password   (stored in $env_dir/demo-password.env, mode 0600)
EOF
  else
    echo "Admin login: $email through $(env_get SIBYL_OIDC_ISSUER)"
  fi
  [[ "$capture" != "skipped" ]] || echo "No capture policy yet: set one in the console (Settings) before minting keys."
  cat <<EOF
Next steps (docs/setup/SETUP.md):
  1. make ca                                   trust Caddy's local CA (skip with ACME/your own cert)
  2. make key NAME=my-agent                    SDK key: SIBYL_API_KEY for sibyl.instrument() / sibyl-run
     make key NAME=my-agent KIND=gateway       gateway key: X-Sibyl-Key header for the gateway
  3. connect an agent, then write an Action Gate policy and enable Sentinel in the console
  make status | make logs | make down
EOF
}

cmd_status() {
  need_docker; setup_compose
  dc ps -a --format '  {{.Service}}\t{{.State}}\t{{.Health}}' | sort
  echo "  console: $(url_of)"
}

cmd_logs() {
  need_docker; setup_compose
  dc logs -f --tail 200 ${extra[@]+"${extra[@]}"}
}

cmd_down() {
  need_docker; setup_compose
  dc --profile bootstrap down --remove-orphans ${purge[@]+"${purge[@]}"}
}

cmd_key() {
  need_docker; setup_compose
  [[ "$key_name" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || die "key: --name NAME is required (letters, digits, . _ -)" 2
  local scopes=()
  case "$key_kind" in
    sdk) scopes=(ingest:write routing:read handoff:write actions:hold) ;;
    gateway) scopes=(gateway:proxy routing:read actions:hold) ;;
    monitor) die "key: monitor keys belong to a registered monitor: console Monitors > Register, or POST /api/v1/monitors" 2 ;;
    *) die "key: --kind must be sdk or gateway" 2 ;;
  esac
  local argv=(keys create "$(env_get SIBYL_TENANT_SLUG)" --name "$key_name" --env live)
  local s; for s in "${scopes[@]}"; do argv+=(--scope "$s"); done
  [[ -z "$key_agent" ]] || argv+=(--agent "$key_agent")
  [[ -z "$key_days" ]] || argv+=(--expires-days "$key_days")
  echo "Minting a $key_kind key '$key_name' (scopes: ${scopes[*]}). The secret is shown once:" >&2
  dc run --rm -T --no-deps api python -m sibyl_control.cli "${argv[@]}"
}

cmd_password() {
  [[ -f "$env_dir/demo-password.env" ]] || die "no $env_dir/demo-password.env (run make up first)"
  sed -n 's/^SIBYL_DEMO_PERSONA_PASSWORD=//p' "$env_dir/demo-password.env"
}

cmd_ca() {
  need_docker; setup_compose
  dc cp caddy:/data/caddy/pki/authorities/local/root.crt ./sibyl-local-root.crt
  echo "wrote ./sibyl-local-root.crt; use it as SSL_CERT_FILE / --cacert, or add it to your trust store"
}

"cmd_$cmd"
