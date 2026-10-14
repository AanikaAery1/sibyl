"""sibyl-schemas: the frozen Sibyl wire contract (`contracts-v1.1.0`).

Modules:
    values      frozen value sets, scope catalogue, problem/gateway error codes, topics
    jsonschema  JSON Schema 2020-12 documents with a registry-backed validator API
    models      pydantic v2 models that accept/reject exactly what the schemas do
    canonical   RFC 8785 JSON canonicalisation (hash chains, snapshot signatures)
    scrub       unconditional secrets scrubber (`secrets_only`, detectors/v1)
    pii         the `pii_standard` detector registry (redacted capture mode)
    golden      the golden fixture corpus shared by producers and consumers
"""

__version__ = "1.1.0"
CONTRACT_TAG = "contracts-v1.1.0"

DOCUMENT_SCHEMAS = (
    "sibyl-event/1",
    "sibyl-event-wire/1",
    "sibyl-health/1",
    "sibyl-handoff/1",
    "sibyl-checkpoint/1",
    "sibyl.policy_snapshot/1",
    "sibyl-ingest-response/1",
    "sibyl-feature-snapshot/1",
    "sibyl-label/1",
    "sibyl-action-policy/1",
)
