"""``python -m sibyl_control.api``: serve the api on ``SIBYL_HTTP_PORT`` (native default 8010)."""

from __future__ import annotations

import uvicorn

from ..core.settings import Settings


def main() -> None:
    settings = Settings()
    uvicorn.run(
        "sibyl_control.api.app:build_app",
        factory=True,
        host="0.0.0.0",  # noqa: S104  (container entrypoint; Caddy fronts it)
        port=settings.port_for("api"),
        server_header=False,
        # X-Forwarded-For is resolved by RequestContextMiddleware against SIBYL_TRUSTED_PROXIES;
        # uvicorn must not rewrite the peer address first (security M4).
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
