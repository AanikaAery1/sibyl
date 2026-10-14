#!/usr/bin/env bash
# Encrypted, signed logical backup of a Sibyl database (pg_dump custom format piped into age),
# with a manifest recording the erasure-ledger head, an off-host copy and D26 expiry.
# Runbook: ops/runbooks/backup-restore.md.
#
# usage: ops/backup/backup.sh [--dsn URI] [--out DIR] [--offhost DIR]
#                             (--blob-root DIR | --ledger FILE | --no-ledger)
#                             [--recipient AGE1.. | --recipients-file F] [--signing-key F]
#                             [--retention-days N] [--globals] [--no-encrypt] [--no-sign]
#                             [--prune-only] [--dry-run]
#   --dsn URI          database to dump (default $SIBYL_PG_DSN). Prefer ~/.pgpass or
#                      PGPASSWORD over a password inside the URI.
#   --out DIR          local backup directory (default $SIBYL_BACKUP_DIR or
#                      ~/.local/share/sibyl/backups)
#   --offhost DIR      second copy on another disk/host (default $SIBYL_BACKUP_OFFHOST).
#   --blob-root DIR    the BlobStore root holding the live ledger (default
#                      $SIBYL_BACKUP_BLOB_ROOT): reads ledger/erasure/ledger.jsonl and checks it
#                      ends exactly at the signed ledger/erasure/head.json (lane U layout)
#   --ledger FILE      live erasure ledger (default $SIBYL_ERASURE_LEDGER). Its head
#                      {count, head_hash} goes into the manifest (H1) and an encrypted
#                      reference copy is kept for the restore's prefix check.
#   --ledger-public-key FILE  ledger signer's public key (default
#                      $SIBYL_LEDGER_PUBLIC_KEY_FILE; init-env.sh writes
#                      env/public/ledger_signing.pem); the ledger is verified before its
#                      head is recorded
#   --no-ledger        no ledger exists yet (no erasure ever ran); recorded as count 0
#   --recipient R      age public key (default $SIBYL_BACKUP_AGE_RECIPIENT); the matching
#                      identity lives offline, never next to the backups
#   --recipients-file F  age recipients file (default $SIBYL_BACKUP_AGE_RECIPIENTS_FILE)
#   --signing-key F    ssh ed25519 private key that signs the manifest (default
#                      $SIBYL_BACKUP_SIGNING_KEY); restore verifies it (allowed_signers)
#   --retention-days N prune sets older than N days by manifest date (default
#                      $SIBYL_BACKUP_RETENTION_DAYS or 7: D26/R30), in --out and --offhost
#   --globals          also dump roles/grants (pg_dumpall --globals-only, no role passwords)
#   --no-encrypt       dev only: write a plaintext dump (restore then needs
#                      --allow-unencrypted); logged loudly
#   --no-sign          dev only: unsigned manifest (restore then needs --allow-unsigned)
#   --prune-only       only apply retention to --out and --offhost, take no backup
#   --dry-run          print the plan, run nothing
#
# WAL note: this is a logical dump, so RPO = time since the last run, and it cannot do
# point-in-time recovery. PITR (pgBackRest + WAL archiving, RPO 1 min, D18) is lane O's
# wave-2 work; until then schedule this script (e.g. hourly) and keep the off-host copy.
set -euo pipefail
# shellcheck source=ops/backup/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { sed -n '2,43p' "$0" | sed 's/^# \{0,1\}//'; }

dsn="${SIBYL_PG_DSN:-}"
out="${SIBYL_BACKUP_DIR:-$HOME/.local/share/sibyl/backups}"
offhost="${SIBYL_BACKUP_OFFHOST:-}"
ledger="${SIBYL_ERASURE_LEDGER:-}"
ledger_pub="${SIBYL_LEDGER_PUBLIC_KEY_FILE:-}"
recipient="${SIBYL_BACKUP_AGE_RECIPIENT:-}"
recipients_file="${SIBYL_BACKUP_AGE_RECIPIENTS_FILE:-}"
signing_key="${SIBYL_BACKUP_SIGNING_KEY:-}"
retention="${SIBYL_BACKUP_RETENTION_DAYS:-7}"
no_ledger=0 globals=0 encrypt=1 sign=1 prune_only=0 dry_run=0
blob_root="${SIBYL_BACKUP_BLOB_ROOT:-}" head_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dsn) dsn="${2:?--dsn needs a value}"; shift ;;
    --out) out="${2:?--out needs a value}"; shift ;;
    --offhost) offhost="${2:?--offhost needs a value}"; shift ;;
    --ledger) ledger="${2:?--ledger needs a value}"; shift ;;
    --blob-root) blob_root="${2:?--blob-root needs a directory}"; shift ;;
    --ledger-public-key) ledger_pub="${2:?--ledger-public-key needs a file}"; shift ;;
    --no-ledger) no_ledger=1 ;;
    --recipient) recipient="${2:?--recipient needs a value}"; shift ;;
    --recipients-file) recipients_file="${2:?--recipients-file needs a value}"; shift ;;
    --signing-key) signing_key="${2:?--signing-key needs a value}"; shift ;;
    --retention-days) retention="${2:?--retention-days needs a value}"; shift ;;
    --globals) globals=1 ;;
    --no-encrypt) encrypt=0 ;;
    --no-sign) sign=0 ;;
    --prune-only) prune_only=1 ;;
    --dry-run) dry_run=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
  shift
done

[[ "$retention" =~ ^[1-9][0-9]{0,4}$ ]] || die "--retention-days must be a positive integer"

if [[ $prune_only -eq 1 ]]; then
  if [[ $dry_run -eq 1 ]]; then
    echo "plan: prune sets older than ${retention}d in $out${offhost:+ and $offhost}"
    exit 0
  fi
  prune_sets "$out" "$retention" ""
  [[ -n "$offhost" ]] && prune_sets "$offhost" "$retention" ""
  exit 0
fi

if [[ -n "$blob_root" ]]; then
  [[ -z "$ledger" ]] || die "choose one of --blob-root and --ledger"
  [[ $no_ledger -eq 0 ]] || die "choose one of --blob-root and --no-ledger"
  { read -r ledger; read -r head_file; } < <(blob_ledger "$blob_root") || exit 2
  [[ -n "$head_file" ]] || exit 2
fi
[[ -n "$dsn" ]] || die "no database: pass --dsn or set SIBYL_PG_DSN"
check_dsn_query "$dsn"
if [[ $no_ledger -eq 1 && -n "$ledger" ]]; then
  die "choose one of --ledger and --no-ledger"
elif [[ $no_ledger -eq 0 && -z "$ledger" ]]; then
  die "no erasure ledger: pass --ledger FILE (H1: the manifest records its head) or --no-ledger"
elif [[ -n "$ledger" && ! -f "$ledger" ]]; then
  die "ledger not found: $ledger"
fi
if [[ -n "$ledger" ]]; then
  [[ -n "$ledger_pub" ]] || die "no ledger public key: pass --ledger-public-key or set SIBYL_LEDGER_PUBLIC_KEY_FILE"
  [[ -f "$ledger_pub" ]] || die "ledger public key not found: $ledger_pub"
fi
age_args=()
if [[ $encrypt -eq 1 ]]; then
  [[ -n "$recipient" || -n "$recipients_file" ]] \
    || die "no age recipient: pass --recipient or set SIBYL_BACKUP_AGE_RECIPIENT (or --no-encrypt for dev)"
  while IFS= read -r a; do age_args+=("$a"); done < <(age_encrypt_args "$recipient" "$recipients_file")
  need age "install age (BSD-3-Clause): brew install age / apt install age"
else
  log "WARN: --no-encrypt: the dump holds plaintext tenant data; dev clusters only"
fi
if [[ $sign -eq 1 ]]; then
  [[ -n "$signing_key" ]] \
    || die "no manifest signing key: pass --signing-key or set SIBYL_BACKUP_SIGNING_KEY (or --no-sign for dev)"
  [[ -f "$signing_key" ]] || die "signing key not found: $signing_key"
  need ssh-keygen "OpenSSH ssh-keygen signs the manifest"
else
  log "WARN: --no-sign: the manifest is unauthenticated; restore will need --allow-unsigned"
fi

pg_dump="$(pg_tool pg_dump)"
psql="$(pg_tool psql)"
masked="$(mask_dsn "$dsn")"
[[ "$masked" != "$dsn" ]] && log "WARN: password in DSN; prefer ~/.pgpass or PGPASSWORD"
[[ -z "$offhost" ]] && log "WARN: no off-host copy configured (--offhost / SIBYL_BACKUP_OFFHOST); C0 says off-host first"

ledger_count=0 ledger_hash="$LEDGER_GENESIS"
if [[ -n "$ledger" ]]; then
  read -r ledger_count ledger_hash < <(ledger_head "$ledger" "$ledger_pub") \
    || die "erasure ledger $ledger does not verify against $ledger_pub"
  valid_count "$ledger_count" && valid_hash "$ledger_hash" || die "could not read the ledger head of $ledger"
  if [[ -n "$head_file" ]]; then
    verify_signed_head "$ledger" "$ledger_pub" "$ledger_count" "$ledger_hash" "$head_file" \
      || die "the signed head $head_file does not match the ledger (forged, or a truncated tail)"
    log "erasure ledger signed head ok: $ledger_count entries, head $ledger_hash"
  fi
fi

suffix=".dump"
[[ $encrypt -eq 1 ]] && suffix=".dump.age"
if [[ $dry_run -eq 1 ]]; then
  echo "plan: $pg_dump --format=custom --no-password --dbname=$masked$([[ $encrypt -eq 1 ]] && echo " | age ${age_args[*]}") -> $out/<db>_<UTC>$suffix"
  echo "plan: manifest (sha256, ledger_count=$ledger_count, ledger_head_hash=$ledger_hash, expires after ${retention}d)$([[ $sign -eq 1 ]] && echo ", signed with $signing_key")"
  [[ $globals -eq 1 ]] && echo "plan: pg_dumpall --globals-only --no-role-passwords -> <set>.globals.sql$([[ $encrypt -eq 1 ]] && echo .age)"
  [[ -n "$ledger" ]] && echo "plan: reference copy of erasure ledger $ledger -> <set>.erasure-ledger.jsonl$([[ $encrypt -eq 1 ]] && echo .age)"
  if [[ -n "$offhost" ]]; then echo "plan: copy to off-host $offhost and verify checksum"
  else echo "plan: no off-host copy (WARN)"; fi
  echo "plan: prune sets older than ${retention}d (manifest created_epoch) in $out${offhost:+ and $offhost}"
  exit 0
fi

server_num="$("$psql" -X -q -At --no-password -d "$dsn" -c 'SHOW server_version_num')"
server_ver="$("$psql" -X -q -At --no-password -d "$dsn" -c 'SHOW server_version')"
db="$("$psql" -X -q -At --no-password -d "$dsn" -c 'SELECT current_database()')"
valid_db_name "$db" || die "unexpected database name '$db'"
client_major="$(tool_major "$pg_dump")"
(( client_major >= server_num / 10000 )) \
  || die "pg_dump $client_major is older than server $server_ver; set PGBIN to PG17 tools"

mkdir -p "$out"
chmod 700 "$out"
umask 077
ts="$(date -u +%Y%m%dT%H%M%SZ)"
created_epoch="$(date -u +%s)"
name="${db}_${ts}${suffix}"
dump="$out/$name"
partials=()
cleanup() { local p; for p in ${partials[@]+"${partials[@]}"}; do rm -f "$p"; done; }
trap cleanup EXIT

encrypt_to() { # target <- stdin
  if [[ $encrypt -eq 1 ]]; then age "${age_args[@]}" -o "$1"
  else cat > "$1"; fi
}

log "dumping $masked -> $dump"
partials+=("$dump.partial")
"$pg_dump" --format=custom --no-password --dbname="$dsn" | encrypt_to "$dump.partial"
mv "$dump.partial" "$dump"
digest="$(sha256_of "$dump")"
printf '%s  %s\n' "$digest" "$name" > "$dump.sha256"

files=("$dump" "$dump.sha256" "$dump.manifest")
globals_file="none"
if [[ $globals -eq 1 ]]; then
  globals_file="$name.globals.sql$([[ $encrypt -eq 1 ]] && echo .age)"
  partials+=("$out/$globals_file.partial")
  "$(pg_tool pg_dumpall)" --globals-only --no-role-passwords --no-password --dbname="$dsn" \
    | encrypt_to "$out/$globals_file.partial"
  mv "$out/$globals_file.partial" "$out/$globals_file"
  files+=("$out/$globals_file")
fi
ledger_copy="none"
if [[ -n "$ledger" ]]; then
  ledger_copy="$name.erasure-ledger.jsonl$([[ $encrypt -eq 1 ]] && echo .age)"
  encrypt_to "$out/$ledger_copy" < "$ledger"
  files+=("$out/$ledger_copy")
fi

expires_epoch=$((created_epoch + retention * 86400))
recipient_desc="none"
[[ $encrypt -eq 1 ]] && recipient_desc="${recipient:-file:$(basename "$recipients_file")}"
cat > "$dump.manifest" <<EOF
format=sibyl-backup/2
kind=logical
file=$name
created_at=$(date -u -r "$created_epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$created_epoch" +%Y-%m-%dT%H:%M:%SZ)
created_epoch=$created_epoch
retention_days=$retention
expires_epoch=$expires_epoch
database=$db
source=$masked
server_version=$server_ver
pg_dump_version=$("$pg_dump" --version | awk '{print $NF}')
sha256=$digest
encryption=$([[ $encrypt -eq 1 ]] && echo age || echo none)
age_recipient=$recipient_desc
globals=$globals_file
ledger=$([[ -n "$ledger" ]] && echo yes || echo none)
ledger_count=$ledger_count
ledger_head_hash=$ledger_hash
ledger_copy=$ledger_copy
pitr=no (logical dump; see WAL note in ops/backup/backup.sh)
EOF
if [[ $sign -eq 1 ]]; then
  sign_file "$signing_key" "$dump.manifest"
  files+=("$dump.manifest.sig")
fi

if [[ -n "$offhost" ]]; then
  mkdir -p "$offhost"
  chmod 700 "$offhost"
  if [[ "$(device_of "$offhost")" == "$(device_of "$out")" ]]; then
    log "WARN: off-host target $offhost is on the same device as $out; that is not off-host"
  fi
  cp "${files[@]}" "$offhost/"
  [[ "$(sha256_of "$offhost/$name")" == "$digest" ]] || die "off-host copy checksum mismatch"
  log "off-host copy verified in $offhost"
fi

prune_sets "$out" "$retention" "$name"
[[ -n "$offhost" ]] && prune_sets "$offhost" "$retention" "$name"

log "backup ok: $dump (sha256 $digest, ledger head $ledger_count/$ledger_hash)"
printf '%s\n' "$dump"
