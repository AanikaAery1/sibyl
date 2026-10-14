"""Ingest limits and constants (API.md §4.2, api/ai-engineer.md §1.3-§1.4)."""

from __future__ import annotations

from dataclasses import dataclass

MiB = 1024 * 1024

NORMALISER_VERSION = "normaliser/1.0"
SEMCONV_VERSION = "1.37.0"
EVENT_SCHEMA = "sibyl-event/1"
RESPONSE_SCHEMA = "sibyl-ingest-response/1"

BATCH_ID_HEADER = "x-sibyl-batch-id"
SCHEMA_HEADER = "x-sibyl-schema"
AGENT_HEADER = "x-sibyl-agent"
CAPTURE_OWNER_HEADER = "x-sibyl-capture-owner"
BACKPRESSURE_HEADER = "X-Sibyl-Backpressure"
REPLAYED_HEADER = "X-Sibyl-Replayed"


@dataclass(frozen=True)
class IngestConfig:
    max_body_bytes: int = 4 * MiB  # on the wire, compressed or not
    max_decoded_bytes: int = 16 * MiB
    max_spans: int = 2000
    max_log_records: int = 1000
    max_events: int = 1000
    max_content_bytes: int = 4 * MiB  # per item, after scrubbing; tail-first truncation above
    inline_state_max_bytes: int = 65536
    attrs_budget_bytes: int = 4096  # jsonb upper bound; the DB CHECK is pg_column_size <= 4096
    ingest_block_budget_bytes: int = 1024  # the DB CHECK is pg_column_size <= 1024
    contribution_budget_bytes: int = 16384  # call_merge.*_contribution CHECK
    max_inflight: int = 64
    request_timeout_s: float = 10.0
    statement_timeout_ms: int = 9_000
    tenant_retry_after_max_s: int = 30
    erasing_retry_after_s: int = 3600
    db_retry_after_s: int = 5
    key_batches_per_s: int = 20
    dek_cache_ttl_s: float = 60.0
    batch_replay_window_h: int = 24
    call_merge_flush_after_s: float = 5.0
    flush_interval_s: float = 1.0
    flush_batch_rows: int = 1000
    max_rejection_detail: int = 500
    otlp_error_entries: int = 100
    max_warnings: int = 100
