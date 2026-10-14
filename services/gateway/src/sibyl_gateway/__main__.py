"""``python -m sibyl_gateway``: serve the data plane on ``SIBYL_HTTP_PORT`` (default 8080)."""

from __future__ import annotations

import logging
import os

import uvicorn

from .config import GatewayConfig
from .runtime import build_gateway


def main() -> None:
    logging.basicConfig(level=os.environ.get("SIBYL_LOG_LEVEL", "info").upper())
    config = GatewayConfig.from_env()
    uvicorn.run(
        build_gateway(config),
        host=os.environ.get("SIBYL_HTTP_HOST", "0.0.0.0"),  # noqa: S104  (container port)
        port=config.http_port,
        lifespan="on",
        access_log=False,
        server_header=False,
        date_header=False,
        timeout_graceful_shutdown=100,
    )


if __name__ == "__main__":
    main()
