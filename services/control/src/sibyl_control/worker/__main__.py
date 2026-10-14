"""``python -m sibyl_control.worker``: loops + ``/healthz`` on ``SIBYL_HTTP_PORT`` (native 8012)."""

from .main import main

if __name__ == "__main__":
    main()
