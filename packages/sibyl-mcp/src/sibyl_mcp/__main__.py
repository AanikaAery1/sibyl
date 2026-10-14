"""``sibyl-mcp``: run the Sibyl monitor MCP server.

    SIBYL_API_URL=https://sibyl.example.com SIBYL_MONITOR_KEY=sbl_live_... sibyl-mcp
    sibyl-mcp --transport streamable-http --host 127.0.0.1 --port 8765

Streamable HTTP has no authentication of its own: it binds loopback by default; put it behind
your own authenticating proxy before exposing it. The key is never printed.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence

from sibyl.monitor import AsyncClient, MonitorConfigError

from .server import build_server

EXIT_CONFIG = 2


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sibyl-mcp",
        description="Sibyl monitor MCP server (env: SIBYL_API_URL, SIBYL_MONITOR_KEY,"
        " optional SIBYL_CA_FILE).",
    )
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1", help="streamable-http bind address")
    parser.add_argument("--port", type=int, default=8765, help="streamable-http port")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    args = parse_args(argv)
    env = os.environ if environ is None else environ
    try:
        client = AsyncClient.from_env(env, ca_file=env.get("SIBYL_CA_FILE") or None)
    except MonitorConfigError as exc:
        print(f"sibyl-mcp: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    server = build_server(client, close_client=True)
    if args.transport == "stdio":
        server.run("stdio")
    else:
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print(
                "sibyl-mcp: warning: streamable HTTP has no auth of its own; serve it only"
                " behind an authenticating proxy",
                file=sys.stderr,
            )
        server.run("streamable-http", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
