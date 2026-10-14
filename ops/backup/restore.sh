#!/usr/bin/env bash
# Restore a Sibyl backup set into a NEW database, re-apply the signed erasure ledger, and only
# then swap it in place of the target (R63, H1, M10). Runbook: ops/runbooks/backup-restore.md.
#
# usage: ops/backup/restore.sh --dump FILE --target-db NAME [--admin-dsn URI]
#          ((--blob-root DIR | --ledger FILE) --ledger-public-key FILE
#           [--expected-head H --expected-count N] | --no-ledger)
#          [--identity FILE] [--allowed-signers FILE] [--manifest-dir DIR]
#          [--replace] [--drop-old] [--verify-only] [--dry-run]
#          [--allow-unsigned] [--allow-unencrypted] [--allow-missing-checksum]
#   --dump FILE          <db>_<UTC>.dump.age (or .dump) from backup.sh; FILE.manifest beside it
#   --target-db NAME     database to end up with (lowercase identifier, <= 40 chars)
#   --admin-dsn URI      superuser connection to the target cluster (default
#                        $SIBYL_PG_ADMIN_DSN); a dbname=/service= query is refused (L7)
#   --blob-root DIR      the LIVE BlobStore root (default $SIBYL_BACKUP_BLOB_ROOT): the ledger is
#                        DIR/ledger/erasure/ledger.jsonl and must also end exactly at the
#                        signed DIR/ledger/erasure/head.json (where the worker writes them)
#   --ledger FILE        the LIVE erasure ledger (default $SIBYL_ERASURE_LEDGER), never the
#                        copy inside the backup set: erasures after the backup must win
#   --ledger-public-key FILE  Ed25519 public key of the ledger signer (default
#                        $SIBYL_LEDGER_PUBLIC_KEY_FILE; init-env.sh writes env/public/ledger_signing.pem)
#   --expected-head H / --expected-count N
#                        the live ledger head from an independent record (WORM export,
#                        incident log). Default: the newest signed manifest in --manifest-dir
#   --manifest-dir DIR   where to look for the newest manifest (default: the dump's directory)
#   --no-ledger          restore without re-shred: only for databases that never held tenant
#                        data; logged loudly
#   --identity FILE      age identity for .age dumps (default $SIBYL_BACKUP_AGE_IDENTITY)
#   --allowed-signers F  ssh allowed_signers for manifest signatures (default
#                        $SIBYL_BACKUP_ALLOWED_SIGNERS)
#   --replace            the target exists: swap it out (kept closed as <target>_old_<ts>)
#   --confirm-destroy    alias of --replace (pre-v2 runbooks)
#   --drop-old           after a successful swap, drop <target>_old_<ts>
#   --verify-only        run every offline check (signature, checksum, decrypt, pg_restore
#                        --list, ledger verification) and stop before touching the cluster
#   --dry-run            cheap checks (manifest, signature, checksum), print the plan, stop
#   --allow-unsigned / --allow-unencrypted / --allow-missing-checksum   dev escape hatches
#
# Order (nothing on the cluster changes until every offline check passed):
#   1. manifest signature, checksum, decrypt to a private temp dir, pg_restore --list and a
#      full offline read of the archive (pg_restore --file=/dev/null)
#   2. ledger: `python -m sibyl_control.migrate ledger-verify` against the expected head; the
#      backup's own ledger head must not be ahead of it; the backup's ledger copy must be a
#      byte prefix of the live ledger
#   3. CREATE DATABASE <target>_restore_<ts> CONNECTION LIMIT 0; pg_restore --exit-on-error
#   4. SELECT sibyl.erasure_reapply_from_ledger(ledger, expected_count, expected_head)
#   5. only now: close the old target, rename old -> <target>_old_<ts>, new -> <target> (one
#      transaction), open the new target.
# Any failure after 3 leaves the staging database closed (CONNECTION LIMIT 0) for forensics and
# the target untouched. $SIBYL_MIGRATE_CMD overrides how `sibyl_control.migrate` is invoked.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ops/backup/lib.sh
. "$here/lib.sh"

usage() { sed -n '2,49p' "$0" | sed 's/^# \{0,1\}//'; }

dump="" target_db="" admin_dsn="${SIBYL_PG_ADMIN_DSN:-}" ledger="${SIBYL_ERASURE_LEDGER:-}"
pubkey="${SIBYL_LEDGER_PUBLIC_KEY_FILE:-}" identity="${SIBYL_BACKUP_AGE_IDENTITY:-}"
signers="${SIBYL_BACKUP_ALLOWED_SIGNERS:-}" manifest_dir="" exp_head="" exp_count=""
no_ledger=0 replace=0 drop_old=0 verify_only=0 dry_run=0
blob_root="${SIBYL_BACKUP_BLOB_ROOT:-}" head_file=""
allow_unsigned=0 allow_unencrypted=0 allow_nosum=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dump) dump="${2:?--dump needs a file}"; shift ;;
    --target-db) target_db="${2?--target-db needs a name}"; shift ;;
    --admin-dsn) admin_dsn="${2:?--admin-dsn needs a URI}"; shift ;;
    --ledger) ledger="${2:?--ledger needs a file}"; shift ;;
    --blob-root) blob_root="${2:?--blob-root needs a directory}"; shift ;;
    --ledger-public-key) pubkey="${2:?--ledger-public-key needs a file}"; shift ;;
    --expected-head) exp_head="${2:?--expected-head needs a hash}"; shift ;;
    --expected-count) exp_count="${2:?--expected-count needs a number}"; shift ;;
    --manifest-dir) manifest_dir="${2:?--manifest-dir needs a directory}"; shift ;;
    --no-ledger) no_ledger=1 ;;
    --identity) identity="${2:?--identity needs a file}"; shift ;;
    --allowed-signers) signers="${2:?--allowed-signers needs a file}"; shift ;;
    --replace|--confirm-destroy) replace=1 ;;
    --drop-old) drop_old=1 ;;
    --verify-only) verify_only=1 ;;
    --dry-run) dry_run=1 ;;
    --allow-unsigned) allow_unsigned=1 ;;
    --allow-unencrypted) allow_unencrypted=1 ;;
    --allow-missing-checksum) allow_nosum=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
  shift
done

# --- argument checks ----------------------------------------------------------------------
if [[ -n "$blob_root" ]]; then
  [[ -z "$ledger" ]] || die "choose one of --blob-root and --ledger"
  [[ $no_ledger -eq 0 ]] || die "choose one of --blob-root and --no-ledger"
  { read -r ledger; read -r head_file; } < <(blob_ledger "$blob_root") || exit 2
  [[ -n "$head_file" ]] || exit 2
fi
[[ -f "$dump" ]] || die "dump not found: ${dump:-<none>} (--dump)"
valid_db_name "$target_db" && [[ ${#target_db} -le 40 ]] \
  || die "invalid --target-db '$target_db' (lowercase identifier, at most 40 characters)"
[[ -n "$admin_dsn" ]] || die "no admin DSN: pass --admin-dsn or set SIBYL_PG_ADMIN_DSN"
check_dsn_query "$admin_dsn"
if [[ $no_ledger -eq 1 && -n "$ledger" ]]; then
  die "choose one of --ledger and --no-ledger"
elif [[ $no_ledger -eq 0 && -z "$ledger" ]]; then
  die "no erasure ledger: pass --ledger FILE (R63) or --no-ledger if no tenant data ever existed"
elif [[ -n "$ledger" && ! -f "$ledger" ]]; then
  die "erasure ledger not found: $ledger; refusing to restore without re-shred (R63)"
fi
if [[ $no_ledger -eq 0 ]]; then
  [[ -n "$pubkey" ]] || die "no ledger public key: pass --ledger-public-key or set SIBYL_LEDGER_PUBLIC_KEY_FILE"
  [[ -f "$pubkey" ]] || die "ledger public key not found: $pubkey"
fi
[[ -z "$exp_head" ]] || valid_hash "$exp_head" || die "--expected-head must be 64 lowercase hex"
[[ -z "$exp_count" ]] || valid_count "$exp_count" || die "--expected-count must be a non-negative integer"
[[ -n "$exp_head" && -z "$exp_count" || -z "$exp_head" && -n "$exp_count" ]] \
  && die "pass --expected-head and --expected-count together"

manifest="$dump.manifest"
dump_dir="$(cd "$(dirname "$dump")" && pwd)"
manifest_dir="${manifest_dir:-$dump_dir}"

# --- 1a. manifest + signature + checksum ----------------------------------------------------
check_signature() { # manifest
  if [[ $allow_unsigned -eq 1 ]]; then
    log "WARN: --allow-unsigned: $1 is not authenticated"
    return 0
  fi
  [[ -n "$signers" ]] || die "no allowed_signers: pass --allowed-signers or set SIBYL_BACKUP_ALLOWED_SIGNERS (or --allow-unsigned)"
  [[ -f "$signers" ]] || die "allowed_signers not found: $signers"
  need ssh-keygen "OpenSSH ssh-keygen verifies manifest signatures"
  verify_signature "$signers" "$1" || die "manifest signature invalid or missing: $1.sig"
  log "manifest signature ok: $1"
}

expected_sum=""
if [[ -f "$manifest" ]]; then
  check_signature "$manifest"
  [[ "$(manifest_get "$manifest" file)" == "$(basename "$dump")" ]] \
    || die "manifest $manifest describes $(manifest_get "$manifest" file), not $(basename "$dump")"
  expected_sum="$(manifest_get "$manifest" sha256)"
elif [[ $allow_unsigned -eq 0 ]]; then
  die "manifest not found: $manifest (pass --allow-unsigned for a pre-v2 backup)"
fi
if [[ -f "$dump.sha256" ]]; then
  side="$(awk '{print $1}' "$dump.sha256")"
  [[ -z "$expected_sum" || "$side" == "$expected_sum" ]] || die "checksum mismatch: $dump.sha256 disagrees with the manifest"
  expected_sum="$side"
fi
if [[ -n "$expected_sum" ]]; then
  [[ "$(sha256_of "$dump")" == "$expected_sum" ]] || die "checksum mismatch for $dump"
  log "checksum ok"
elif [[ $allow_nosum -eq 1 ]]; then
  log "WARN: --allow-missing-checksum: integrity of $dump not verified"
else
  die "no checksum for $dump (manifest or .sha256); pass --allow-missing-checksum to override"
fi

encrypted=0
if [[ "$dump" == *.age ]] || [[ -f "$manifest" && "$(manifest_get "$manifest" encryption)" == "age" ]]; then
  encrypted=1
elif [[ $allow_unencrypted -eq 0 ]]; then
  die "$dump is not encrypted; pass --allow-unencrypted to restore a plaintext dev dump"
fi

# --- ledger head resolution -----------------------------------------------------------------
newest_manifest() { # dir -> path of the manifest with the largest created_epoch
  local m best="" best_epoch=-1 e
  for m in "$1"/*.manifest; do
    [[ -f "$m" ]] || continue
    e="$(manifest_get "$m" created_epoch)"
    [[ "$e" =~ ^[0-9]{1,12}$ ]] || continue
    (( e > best_epoch )) && { best="$m"; best_epoch="$e"; }
  done
  printf '%s\n' "$best"
}

head_source="explicit"
if [[ $no_ledger -eq 0 && -z "$exp_head" ]]; then
  newest="$(newest_manifest "$manifest_dir")"
  [[ -n "$newest" ]] || die "no v2 manifest in $manifest_dir to take the ledger head from; pass --expected-head/--expected-count"
  [[ "$newest" == "$manifest" ]] || check_signature "$newest"
  exp_count="$(manifest_get "$newest" ledger_count)"
  exp_head="$(manifest_get "$newest" ledger_head_hash)"
  valid_count "$exp_count" && valid_hash "$exp_head" \
    || die "$newest records no ledger head; pass --expected-head/--expected-count"
  head_source="newest manifest $(basename "$newest")"
fi
if [[ $no_ledger -eq 0 && -f "$manifest" ]]; then
  backup_count="$(manifest_get "$manifest" ledger_count)"
  if valid_count "$backup_count" && (( backup_count > exp_count )); then
    die "the backup saw $backup_count ledger entries but the expected head has $exp_count: the live ledger was truncated or the head is stale"
  fi
fi

ts="$(date -u +%Y%m%d%H%M%S)"
staging="${target_db}_restore_${ts}"
old="${target_db}_old_${ts}"
staging_dsn="$(dsn_with_db "$admin_dsn" "$staging")"
reapply_sql="SELECT sibyl.erasure_reapply_from_ledger(<ledger>, ${exp_count:-N}, '${exp_head:-H}');"

if [[ $dry_run -eq 1 ]]; then
  echo "plan: verify (done): manifest signature, checksum$([[ $encrypted -eq 1 ]] && echo ", then age -d into a private temp dir")"
  echo "plan: pg_restore --list <dump>; pg_restore --file=/dev/null <dump> (full offline read)"
  if [[ $no_ledger -eq 1 ]]; then echo "plan: NO re-shred (--no-ledger)"
  else echo "plan: ledger-verify --ledger $ledger --public-key $pubkey --expected-head $exp_head --expected-count $exp_count${head_file:+ --head $head_file} ($head_source)"; fi
  echo "plan: CREATE DATABASE \"$staging\" TEMPLATE template0 CONNECTION LIMIT 0;"
  echo "plan: pg_restore --exit-on-error --dbname=$(mask_dsn "$staging_dsn") <dump>"
  [[ $no_ledger -eq 0 ]] && echo "plan: $reapply_sql  -- in $staging"
  echo "plan: BEGIN; ALTER DATABASE \"$target_db\" RENAME TO \"$old\" (if it exists; needs --replace); ALTER DATABASE \"$staging\" RENAME TO \"$target_db\"; COMMIT;"
  echo "plan: ALTER DATABASE \"$target_db\" CONNECTION LIMIT -1;$([[ $drop_old -eq 1 ]] && echo " DROP DATABASE \"$old\";")"
  exit 0
fi

# --- 1b. decrypt + pg_restore --list -------------------------------------------------------
work="$(mktemp -d "${TMPDIR:-/tmp}/sibyl-restore.XXXXXX")"
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT
plain="$dump"
if [[ $encrypted -eq 1 ]]; then
  [[ -n "$identity" ]] || die "encrypted dump: pass --identity or set SIBYL_BACKUP_AGE_IDENTITY"
  [[ -f "$identity" ]] || die "age identity not found: $identity"
  need age "install age (BSD-3-Clause): brew install age / apt install age"
  plain="$work/restore.dump"
  age -d -i "$identity" -o "$plain" "$dump" || die "cannot decrypt $dump with $identity"
fi
pg_restore="$(pg_tool pg_restore)"
psql="$(pg_tool psql)"
"$pg_restore" --list "$plain" > "$work/toc.list" 2> "$work/toc.err" \
  || die "pg_restore --list rejects $dump: $(head -3 "$work/toc.err")"
# --list only reads the TOC at the head of the archive; a truncated dump keeps it. Reading the
# whole archive into a script (discarded) proves every data block is present, still offline.
"$pg_restore" --file=/dev/null "$plain" 2> "$work/read.err" \
  || die "pg_restore --list ok but the archive is incomplete or corrupt: $(head -3 "$work/read.err")"
log "archive ok: $(grep -cv '^;' "$work/toc.list") TOC entries, all data blocks readable"

# --- 2. ledger verification (offline) ---------------------------------------------------------
read -r -a migrate <<< "$(migrate_cmd)"

if [[ $no_ledger -eq 0 ]]; then
  log "verifying erasure ledger $ledger against head $exp_count/$exp_head ($head_source)"
  # From a blob root the ledger must also end exactly at its signed head.json (lane U).
  head_args=()
  [[ -n "$head_file" ]] && head_args=(--head "$head_file")
  "${migrate[@]}" ledger-verify --ledger "$ledger" --public-key "$pubkey" \
      --expected-head "$exp_head" --expected-count "$exp_count" ${head_args[@]+"${head_args[@]}"} \
      > "$work/verify.out" 2>&1 \
    || { cat "$work/verify.out" >&2; die "erasure ledger verification failed; nothing was restored"; }
  [[ -n "$head_file" ]] && log "erasure ledger signed head ok: $head_file"
  copy="$(manifest_get "$manifest" ledger_copy 2>/dev/null || true)"
  if [[ -n "$copy" && "$copy" != "none" && -f "$dump_dir/$copy" ]]; then
    ref="$dump_dir/$copy"
    if [[ "$copy" == *.age ]]; then
      age -d -i "$identity" -o "$work/ledger-copy.jsonl" "$ref" || die "cannot decrypt the ledger copy $ref"
      ref="$work/ledger-copy.jsonl"
    fi
    size="$(wc -c < "$ref" | tr -d ' ')"
    [[ "$size" -eq 0 ]] || head -c "$size" "$ledger" | cmp -s - "$ref" \
      || die "the backup's ledger copy is not a prefix of the live ledger $ledger: the live ledger was rewritten"
    log "ledger copy in the backup set is a prefix of the live ledger"
  fi
  log "erasure ledger ok"
fi

if [[ $verify_only -eq 1 ]]; then
  log "verify-only: every offline check passed; the cluster was not touched"
  exit 0
fi

# --- 3. restore into a new, closed database -----------------------------------------------------
admin() { "$psql" -X -q -At --no-password -v ON_ERROR_STOP=1 -d "$admin_dsn" "$@"; }
db_exists() { [[ "$(admin -c "SELECT 1 FROM pg_database WHERE datname = '$1'")" == "1" ]]; }

target_exists=0
if db_exists "$target_db"; then
  target_exists=1
  [[ $replace -eq 1 ]] || die "database $target_db exists; pass --replace to swap it out after the new one is verified"
fi
db_exists "$staging" && die "staging database $staging already exists"

admin -c "CREATE DATABASE \"$staging\" TEMPLATE template0 CONNECTION LIMIT 0"
log "restoring into $(mask_dsn "$staging_dsn") (closed to application roles)"
if ! "$pg_restore" --exit-on-error --no-password --dbname="$staging_dsn" "$plain" 2> "$work/restore.err"; then
  cat "$work/restore.err" >&2
  admin -c "DROP DATABASE IF EXISTS \"$staging\" WITH (FORCE)" || true
  die "pg_restore failed; staging database dropped, $target_db untouched"
fi

# --- 4. re-shred ------------------------------------------------------------------------------
if [[ $no_ledger -eq 1 ]]; then
  log "WARN: --no-ledger: erasure ledger NOT re-applied; only valid if no tenant data ever existed"
else
  tag="sibyl_ledger_$(openssl rand -hex 8 2>/dev/null || date +%s%N)"
  grep -qF "\$${tag}\$" "$ledger" && die "ledger contains the quoting tag; retry"
  log "re-applying erasure ledger $ledger"
  if ! reshredded="$({
      printf 'SELECT sibyl.erasure_reapply_from_ledger($%s$' "$tag"
      cat "$ledger"
      printf '$%s$, %s, %s);\n' "$tag" "$exp_count" "'$exp_head'"
    } | "$psql" -X -q -At --no-password -v ON_ERROR_STOP=1 -d "$staging_dsn" -f - 2>&1)"; then
    log "$reshredded"
    die "re-shred failed: $staging is NOT safe to serve; it stays closed (CONNECTION LIMIT 0) and $target_db is untouched"
  fi
  log "re-shred ok: $reshredded erasure(s) re-applied"
fi

# --- 5. swap ------------------------------------------------------------------------------------
if [[ $target_exists -eq 1 ]]; then
  log "closing $target_db and swapping it out as $old"
  old_limit="$(admin -c "SELECT datconnlimit FROM pg_database WHERE datname = '$target_db'")"
  admin -c "ALTER DATABASE \"$target_db\" CONNECTION LIMIT 0"
  admin -c "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = '$target_db' AND pid <> pg_backend_pid()" >/dev/null
  if ! admin -c "BEGIN" -c "ALTER DATABASE \"$target_db\" RENAME TO \"$old\"" \
      -c "ALTER DATABASE \"$staging\" RENAME TO \"$target_db\"" -c "COMMIT"; then
    admin -c "ALTER DATABASE \"$target_db\" CONNECTION LIMIT ${old_limit:--1}" || true
    die "swap failed: $target_db unchanged and reopened; the verified restore stays closed in $staging"
  fi
else
  admin -c "ALTER DATABASE \"$staging\" RENAME TO \"$target_db\""
fi
admin -c "ALTER DATABASE \"$target_db\" CONNECTION LIMIT -1"
log "restore ok: $target_db is open"
if [[ $target_exists -eq 1 ]]; then
  if [[ $drop_old -eq 1 ]]; then
    admin -c "DROP DATABASE \"$old\" WITH (FORCE)"
    log "dropped the previous database $old"
  else
    log "previous database kept CLOSED as $old; drop it once the restore is accepted: DROP DATABASE \"$old\";"
  fi
fi
cat >&2 <<EOF
next (runbook): run the next release's migrations, then 'sibyl audit verify' for every
tenant chain (anchor heads must match the off-DB anchor exports), then start services.
EOF
