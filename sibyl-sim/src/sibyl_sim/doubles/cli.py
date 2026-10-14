"""`serve`: control port (http, default 8300) plus the https doubles port (default 18082);
`run`: the evaluation harness (`sibyl_sim.harness.cli`).

    python -m sibyl_sim.doubles serve --host 0.0.0.0 --port 8300
    python -m sibyl_sim run --scenario S-01 [--seed N] [--report out/]   # the harness
    # once the sim package entry point delegates here: python -m sibyl_sim serve ...

Env: SIBYL_SIM_SEED, SIBYL_SIM_DOUBLES_PORT, SIBYL_SIM_TLS_DIR, SIBYL_SIM_TLS_HOSTS
(comma separated SANs), SIBYL_SIM_ADMIN_TOKEN, SIBYL_SIM_DEFAULT_DOUBLE.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import tempfile

import uvicorn

from sibyl_sim.doubles import tls
from sibyl_sim.doubles.app import control_app, doubles_app
from sibyl_sim.doubles.state import build_state

log = logging.getLogger("sibyl_sim")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sibyl_sim", description="sibyl-sim (dev-only, D38)")
    sub = root.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the provider doubles and status feeds")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=int(os.environ.get("SIBYL_SIM_PORT", 8300)))
    serve.add_argument(
        "--doubles-port", type=int, default=int(os.environ.get("SIBYL_SIM_DOUBLES_PORT", 18082))
    )
    serve.add_argument("--seed", type=int, default=None)
    serve.add_argument("--tls-dir", default=os.environ.get("SIBYL_SIM_TLS_DIR"))
    serve.add_argument(
        "--tls-host",
        action="append",
        default=None,
        help="extra SAN for the dev certificate (repeatable)",
    )
    from sibyl_sim.harness.cli import add_run_parser  # the evaluation harness (lane M)

    add_run_parser(sub)
    return root


def _hosts(extra: list[str] | None) -> tuple[str, ...]:
    env = [h for h in os.environ.get("SIBYL_SIM_TLS_HOSTS", "").split(",") if h.strip()]
    return tuple(dict.fromkeys([*tls.DEFAULT_HOSTS, *env, *(extra or [])]))


async def serve(args: argparse.Namespace) -> None:
    state = build_state(seed=args.seed)
    directory = args.tls_dir or tempfile.mkdtemp(prefix="sibyl-sim-tls-")
    certs = tls.generate(directory, _hosts(args.tls_host))
    state.ca_path = str(certs.ca_path)
    log.warning(
        "sibyl-sim: doubles on https://%s:%d/v1 (CA %s); control on http://%s:%d",
        args.host,
        args.doubles_port,
        certs.ca_path,
        args.host,
        args.port,
    )
    control = uvicorn.Server(
        uvicorn.Config(
            control_app(state),
            host=args.host,
            port=args.port,
            log_level="warning",
            access_log=False,
        )
    )
    doubles = uvicorn.Server(
        uvicorn.Config(
            doubles_app(state),
            host=args.host,
            port=args.doubles_port,
            log_level="warning",
            access_log=False,
            ssl_certfile=str(certs.cert_path),
            ssl_keyfile=str(certs.key_path),
        )
    )
    await asyncio.gather(control.serve(), doubles.serve())


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "serve":
        asyncio.run(serve(args))
    elif args.command == "run":
        from sibyl_sim.harness.cli import main as run_main

        return run_main(args)
    return 0
