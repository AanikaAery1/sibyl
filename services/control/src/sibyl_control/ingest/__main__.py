"""``python -m sibyl_control.ingest``: serve ingest on ``SIBYL_HTTP_PORT`` (native default 8011)."""

from __future__ import annotations

import uvicorn

from ..core.settings import Settings


def main() -> None:
    settings = Settings()
    settings.require_secrets("ingest")
    uvicorn.run(
        "sibyl_control.ingest.app:build_app",
        factory=True,
        host="0.0.0.0",  # noqa: S104  (container entrypoint; Caddy fronts it)
        port=settings.port_for("ingest"),
        server_header=False,
        proxy_headers=True,
        timeout_graceful_shutdown=15,
    )


if __name__ == "__main__":
    main()
