"""Generator for the frozen Sibyl control-plane contract ``openapi/sibyl-api.v1.yaml``.

The route table (``routes_*.py``) mirrors API.md §5 row by row; ``build.py`` renders it into
OpenAPI 3.1 with the ``x-sibyl-*`` extensions. The YAML is the contract; this package is tooling.
Regenerate with ``uv run python openapi/build.py`` and check drift with ``--check``.
"""
