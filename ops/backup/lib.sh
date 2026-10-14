#!/usr/bin/env bash
# Shared helpers for ops/backup/{backup,restore}.sh. Sourced, not executed.
set -euo pipefail

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# Signature namespace for ssh-keygen -Y over backup manifests.
SIG_NAMESPACE="sibyl-backup"
# Genesis head of an empty erasure ledger (migrate/ledger.py GENESIS_PREV_HASH).
LEDGER_GENESIS="0000000000000000000000000000000000000000000000000000000000000000"

# PG17 client tools: $PGBIN, else the Homebrew postgresql@17 keg, else PATH.
pg_tool() {
  local tool="$1"
  if [[ -n "${PGBIN:-}" && -x "$PGBIN/$tool" ]]; then
    printf '%s\n' "$PGBIN/$tool"
  elif [[ -x "/opt/homebrew/opt/postgresql@17/bin/$tool" ]]; then
    printf '%s\n' "/opt/homebrew/opt/postgresql@17/bin/$tool"
  else
    command -v "$tool" || die "$tool not found; set PGBIN to the PostgreSQL 17 bin directory"
  fi
}

need() { command -v "$1" >/dev/null || die "$1 not found: $2"; }

# Hide the password in a postgres URI for logs.
mask_dsn() { printf '%s\n' "$1" | sed -E 's#(://[^:/@]+):[^@]*@#\1:***@#'; }

# Refuse URI query parameters that silently redirect the connection to another database or
# service (L7): the database is always the path component, set by dsn_with_db.
check_dsn_query() {
  local dsn="$1" query=""
  [[ "$dsn" =~ ^postgres(ql)?:// ]] || die "only postgresql:// URIs are supported: $(mask_dsn "$dsn")"
  [[ "$dsn" == *\?* ]] && query="${dsn#*\?}"
  if [[ "&$query" =~ \&(dbname|service|servicefile)= ]]; then
    die "DSN query sets ${BASH_REMATCH[1]}=; pass the database in the URI path only: $(mask_dsn "$dsn")"
  fi
}

# Replace the database in a postgres URI (keeps query parameters).
dsn_with_db() {
  local dsn="$1" db="$2" base query=""
  check_dsn_query "$dsn"
  base="${dsn%%\?*}"
  [[ "$dsn" == *\?* ]] && query="?${dsn#*\?}"
  local rest="${base#*://}"
  if [[ "$rest" == */* ]]; then
    base="${base%/*}"
  fi
  printf '%s/%s%s\n' "$base" "$db" "$query"
}

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Major version of a client tool (pg_dump --version -> 17).
tool_major() { "$1" --version | sed -E 's/.* ([0-9]+)(\.[0-9]+)*.*/\1/' | head -1; }

# Filesystem/device identifier, to warn when a "second" location shares the disk.
device_of() { df -P "$1" 2>/dev/null | awk 'NR==2 {print $1}'; }

valid_db_name() { [[ "$1" =~ ^[a-z_][a-z0-9_]{0,62}$ ]]; }
valid_hash() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
valid_count() { [[ "$1" =~ ^(0|[1-9][0-9]{0,17})$ ]]; }

# Value of KEY in a key=value manifest (first match; empty when absent).
manifest_get() { awk -F= -v k="$2" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$1"; }

# How to run `python -m sibyl_control.migrate` (ledger-verify / ledger-head, FIX-DB):
# $SIBYL_MIGRATE_CMD (word-split), else `uv run` in this repository, else python3 on PATH.
migrate_cmd() {
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  if [[ -n "${SIBYL_MIGRATE_CMD:-}" ]]; then
    printf '%s\n' "$SIBYL_MIGRATE_CMD"
  elif command -v uv >/dev/null && [[ -f "$root/pyproject.toml" ]]; then
    printf '%s\n' "uv run --project $root --frozen --quiet python -m sibyl_control.migrate"
  else
    printf '%s\n' "python3 -m sibyl_control.migrate"
  fi
}

# "<count> <head_hash>" of a VERIFIED erasure ledger: every Ed25519 signature and the hash
# chain are checked by `sibyl_control.migrate ledger-head` (the head is sha256 of the last
# entry's JCS form, so it cannot be computed here). An empty ledger is "0 <genesis>".
ledger_head() { # ledger public_key
  local -a cmd
  local json
  read -r -a cmd <<< "$(migrate_cmd)"
  json="$("${cmd[@]}" ledger-head --ledger "$1" --public-key "$2")" || return 1
  need python3 "needed to parse the ledger head"
  printf '%s' "$json" | python3 -I -c '
import json, sys
head = json.loads(sys.stdin.read().strip().splitlines()[-1])
print(int(head["count"]), head["head_hash"])'
}

# The erasure ledger as the worker's erasure_ledger loop keeps it in the BlobStore (lane U,
# worker/housekeeping/ledger_store.py): <blob root>/ledger/erasure/ledger.jsonl (the verified
# ledger) and head.json (its signed head {count, head_hash, at, sig}). With the compose fs
# backend the blob root is the `blobstore` volume (copy it out first, see the runbook).
BLOB_LEDGER="ledger/erasure/ledger.jsonl"
BLOB_HEAD="ledger/erasure/head.json"
blob_ledger() { # blob_root -> "<ledger.jsonl>\n<head.json>" or die
  [[ -d "$1" ]] || die "blob root not found: $1 (--blob-root)"
  [[ -f "$1/$BLOB_LEDGER" ]] || die "no erasure ledger at $1/$BLOB_LEDGER: the worker has" \
    "not materialised one (no erasure has completed); pass --no-ledger only if none ever ran"
  [[ -f "$1/$BLOB_HEAD" ]] || die "no signed ledger head at $1/$BLOB_HEAD beside the ledger"
  printf '%s\n%s\n' "$1/$BLOB_LEDGER" "$1/$BLOB_HEAD"
}

# Verify LEDGER against PUBKEY, COUNT/HEAD and the signed head record HEAD_FILE (exit != 0 if
# the record is forged or the ledger does not end exactly at it).
verify_signed_head() { # ledger public_key count head_hash head_file
  local -a cmd
  read -r -a cmd <<< "$(migrate_cmd)"
  "${cmd[@]}" ledger-verify --ledger "$1" --public-key "$2" \
    --expected-count "$3" --expected-head "$4" --head "$5"
}

# age encryption: recipients from --recipient / $SIBYL_BACKUP_AGE_RECIPIENT (age1... public
# key) or a recipients file. Plaintext never touches the disk: pg_dump pipes into age.
age_encrypt_args() { # recipient recipients_file -> args on stdout, one per line
  if [[ -n "$1" ]]; then
    [[ "$1" =~ ^age1[0-9a-z]{58}$ ]] || die "not an age X25519 recipient: $1"
    printf '%s\n' -r "$1"
  fi
  if [[ -n "$2" ]]; then
    [[ -f "$2" ]] || die "recipients file not found: $2"
    printf '%s\n' -R "$2"
  fi
}

# ssh-keygen -Y signatures over the manifest (OpenSSH, BSD; on every macOS and Debian host).
sign_file() { # key file -> file.sig
  ssh-keygen -q -Y sign -f "$1" -n "$SIG_NAMESPACE" "$2" >/dev/null 2>&1 \
    || die "signing $2 with $1 failed"
}
verify_signature() { # allowed_signers file -> 0 if valid
  local principal
  [[ -f "$2.sig" ]] || return 1
  principal="$(ssh-keygen -Y find-principals -f "$1" -s "$2.sig" 2>/dev/null | head -1)" || return 1
  [[ -n "$principal" ]] || return 1
  ssh-keygen -Y verify -f "$1" -I "$principal" -n "$SIG_NAMESPACE" -s "$2.sig" < "$2" >/dev/null 2>&1
}

# Backup-set file names: <db>_<UTC>.dump[.age]; sidecars share the prefix.
valid_set_name() { [[ "$1" =~ ^[a-z_][a-z0-9_]{0,62}_[0-9]{8}T[0-9]{6}Z\.dump(\.age)?$ ]]; }

# Delete backup sets in DIR whose manifest created_epoch is older than DAYS (D26: pre-shred
# backups expire). Never touches KEEP (the set just written). Prints one line per removal.
prune_sets() { # dir days keep
  local dir="$1" days="$2" keep="$3" now cutoff m file epoch
  [[ -d "$dir" ]] || return 0
  [[ "$days" =~ ^[1-9][0-9]{0,4}$ ]] || die "retention days must be a positive integer: $days"
  now="$(date -u +%s)"
  cutoff=$((now - days * 86400))
  for m in "$dir"/*.manifest; do
    [[ -f "$m" ]] || continue
    file="$(manifest_get "$m" file)"
    epoch="$(manifest_get "$m" created_epoch)"
    if ! valid_set_name "$file" || [[ ! "$epoch" =~ ^[0-9]{1,12}$ ]]; then
      log "WARN: $m has no valid file/created_epoch (pre-v2 manifest?); not pruned"
      continue
    fi
    [[ "$file" == "$keep" ]] && continue
    if (( epoch < cutoff )); then
      rm -f "${dir:?}/$file" "${dir:?}/$file".*
      log "pruned $dir/$file (created $(manifest_get "$m" created_at), retention ${days}d)"
    fi
  done
}
