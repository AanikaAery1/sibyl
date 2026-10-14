"""Ingest service (lane I): OTLP/HTTP traces and logs plus ``sibyl-event/1`` batches.

``app.create_app()`` serves ``POST /v1/otlp/traces``, ``POST /v1/otlp/logs`` and
``POST /v1/events`` (API.md §4); ``python -m sibyl_control.ingest`` runs it on
``SIBYL_HTTP_PORT`` (native default 8011). Decoding lives in ``otlp``, the normaliser in
``normalise``, payload sealing in ``payloads``, the transactional write path in ``store`` and
``service``.
"""
