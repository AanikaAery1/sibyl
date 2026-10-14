"""Control-plane kernel shared by every API module and worker loop (W0-KER, steward-owned).

Modules: ``db`` (tenant transactions), ``authz`` (scope catalogue, ``authorize``), ``apikeys``,
``problems`` (RFC 9457), ``idempotency``, ``etag``, ``paging``, ``ratelimit``, ``audit``,
``outbox``, ``canonical`` (JCS), ``crypto`` (envelope encryption, Ed25519), ``blob`` (BlobStore),
``risk`` (frozen RiskDocument), ``settings``. Changes go through the contract steward at a gate.
"""
