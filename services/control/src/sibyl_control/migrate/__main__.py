"""CLI: ``python -m sibyl_control.migrate [up|status|verify|rules-seed|ledger-verify|ledger-head]``.

``up`` (the default) bootstraps with the admin credentials when needed and applies pending
migrations as ``sibyl_migrate``. ``ledger-verify`` checks every signature and the hash chain
of the erasure ledger and that it reaches the head a backup manifest recorded (restore runs
it before ``sibyl.erasure_reapply_from_ledger``); ``ledger-head`` prints ``{count,
head_hash}`` of a verified ledger for the manifest. Exit codes: 0 ok, 1 migration error,
2 usage, 3 drift, 4 invalid ledger.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from sibyl_control.migrate import ledger, rules_seed
from sibyl_control.migrate.config import from_env
from sibyl_control.migrate.runner import (
    MigrationError,
    apply,
    default_migrations_dir,
    discover,
    status,
)

log = logging.getLogger("sibyl.migrate")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m sibyl_control.migrate")
    parser.add_argument("--dir", type=Path, default=None, help="migrations directory")
    sub = parser.add_subparsers(dest="command")
    up = sub.add_parser("up", help="apply pending migrations (default)")
    up.add_argument("--target", type=int, default=None)
    up.add_argument("--allow-superuser", action="store_true", help="dev only")
    sub.add_parser("status", help="list applied / pending / modified migrations")
    sub.add_parser("verify", help="validate migration files without connecting")
    seed = sub.add_parser("rules-seed", help="compile rules/v1/defaults.yaml into SQL")
    mode = seed.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        type=Path,
        nargs="?",
        const=None,
        default=False,
        help="write the seed migration (default: the latest *_rules_*seed*.sql)",
    )
    mode.add_argument("--check", action="store_true", help="exit 3 when the committed SQL drifted")
    seed.add_argument("--yaml", type=Path, default=None)
    verify_ledger = sub.add_parser("ledger-verify", help="verify the signed erasure ledger")
    head = sub.add_parser("ledger-head", help="print {count, head_hash} of a verified ledger")
    for cmd in (verify_ledger, head):
        cmd.add_argument("--ledger", type=Path, required=True)
        cmd.add_argument("--public-key", type=Path, required=True)
    verify_ledger.add_argument("--expected-head", required=True, help="head_hash from the manifest")
    verify_ledger.add_argument("--expected-count", type=int, required=True)
    verify_ledger.add_argument("--head", type=Path, default=None, help="signed head record")
    return parser


def _ledger(args: argparse.Namespace) -> int:
    try:
        public_key = ledger.load_public_key(args.public_key.read_bytes())
        if args.command == "ledger-head":
            entries = ledger.verify(args.ledger.read_text("utf-8"), public_key)
            count, head = ledger.head_of(entries)
            sys.stdout.write(json.dumps({"count": count, "head_hash": head}) + "\n")
            return 0
        entries = ledger.verify(
            args.ledger.read_text("utf-8"),
            public_key,
            expected_count=args.expected_count,
            expected_head=args.expected_head,
        )
        if args.head is not None:
            ledger.verify_head(ledger.load_head(args.head.read_text("utf-8")), entries, public_key)
    except (ledger.LedgerError, OSError, ValueError) as exc:
        log.error("erasure ledger invalid: %s", exc)
        return 4
    log.info("erasure ledger ok: %d entries, head %s", *ledger.head_of(entries))
    return 0


def _rules_seed(args: argparse.Namespace) -> int:
    directory = args.dir or default_migrations_dir()
    sql = rules_seed.render_sql(rules_seed.load(args.yaml))
    target = rules_seed.latest_seed_migration(directory)
    if args.check:
        if target is None or target.read_text() != sql:
            log.error("rules seed drifted from rules/v1/defaults.yaml (%s)", target)
            return 3
        return 0
    if args.write is not False:
        out = args.write or target
        if out is None:
            log.error("no seed migration found; pass --write PATH")
            return 2
        out.write_text(sql)
        log.info("wrote %s", out)
        return 0
    sys.stdout.write(sql)
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = _parser().parse_args(argv)
    command = args.command or "up"
    try:
        if command == "rules-seed":
            return _rules_seed(args)
        if command in ("ledger-verify", "ledger-head"):
            return _ledger(args)
        if command == "verify":
            log.info("%d migrations ok", len(discover(args.dir)))
            return 0
        config = from_env(os.environ)
        if command == "status":
            for item in asyncio.run(status(config, args.dir)):
                sys.stdout.write(f"{item.version:04d} {item.name:<32} {item.state}\n")
            return 0
        applied = asyncio.run(
            apply(
                config,
                args.dir,
                target=getattr(args, "target", None),
                allow_superuser=getattr(args, "allow_superuser", False),
            )
        )
        log.info("applied %s", ", ".join(f"{v:04d}" for v in applied) or "nothing (up to date)")
        return 0
    except MigrationError as exc:
        log.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
