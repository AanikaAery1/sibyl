"""Operator CLI: ``python -m sibyl_control.cli <group> <command> …``.

Groups: ``tenant`` (create/list/show tenants, bootstrap issuers and first users, seed the demo
tenants from ``deploy/compose/dex/personas.yaml``), ``keys`` (issue/list/revoke tenant API keys,
incl. the D20 break-glass key) and, when lane R ships it, ``seed``. Every command module exposes
``register(subparsers)``; a handler is ``async def run(args, ctx) -> int``.

The CLI is an operator tool: it connects with the api's settings (``SIBYL_PG_DSN`` or
``SIBYL_DB_*`` as ``sibyl_app``), holds the KEK (``SIBYL_KEK``) to wrap new DEKs and the pepper
(``SIBYL_KEY_PEPPER``) to hash new keys, and goes through the same database functions and checks
as the api (``tenant_create``, ``audit_append``, RLS via ``set_tenant``). Its audit rows are
``system`` actors with the reason ``operator CLI: <command>``. Secrets are printed exactly once
and never logged.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, TextIO
from uuid import UUID

from ..core.db import Database
from ..core.problems import ProblemError
from ..core.settings import Settings

Handler = Callable[[argparse.Namespace, "CliContext"], Awaitable[int]]


@dataclass
class CliContext:
    settings: Settings
    db: Database
    out: TextIO
    as_json: bool

    def emit(self, value: Any, text: str | None = None) -> None:
        if self.as_json:
            self.out.write(json.dumps(value, default=str, indent=2, sort_keys=True) + "\n")
        else:
            self.out.write((text if text is not None else str(value)) + "\n")


class CliError(Exception):
    """A refusal with a message for the operator (exit code 2)."""


async def tenant_id_for(db: Database, slug_or_id: str) -> UUID:
    async with db.pre_tenant() as conn:
        try:
            value = await conn.fetchval(
                "SELECT id FROM sibyl.tenant WHERE id = $1", UUID(slug_or_id)
            )
        except ValueError:
            value = await conn.fetchval("SELECT id FROM sibyl.tenant WHERE slug = $1", slug_or_id)
    if value is None:
        raise CliError(f"no tenant {slug_or_id!r}")
    tenant: UUID = value
    return tenant


def build_parser(modules: Sequence[Any]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sibyl_control.cli", description=__doc__.split("\n")[0]
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    groups = parser.add_subparsers(dest="group", required=True)
    for module in modules:
        module.register(groups)
    return parser


async def _run(handler: Handler, args: argparse.Namespace, out: TextIO, settings: Settings) -> int:
    db = await Database.connect(
        settings.dsn(), min_size=1, max_size=2, application_name="sibyl-cli"
    )
    try:
        return await handler(args, CliContext(settings, db, out, args.json))
    finally:
        await db.close()


def main(
    argv: Sequence[str] | None = None, *, out: TextIO | None = None, err: TextIO | None = None
) -> int:
    from . import keys, tenant

    modules: list[Any] = [tenant, keys]
    try:  # lane R's ``seed`` group, when it exposes ``register(subparsers)``
        seed = importlib.import_module(f"{__name__}.seed")
        if hasattr(seed, "register"):
            modules.append(seed)
    except ImportError:
        pass
    parser = build_parser(modules)
    args = parser.parse_args(argv)
    out, err = out or sys.stdout, err or sys.stderr
    try:
        return asyncio.run(_run(args.handler, args, out, Settings()))
    except CliError as exc:
        err.write(f"error: {exc}\n")
        return 2
    except ProblemError as exc:
        err.write(f"error: {exc.code}: {exc.detail or exc.title}\n")
        return 2
