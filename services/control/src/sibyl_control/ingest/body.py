"""Request body intake with streaming caps (T5 OTLP amplification).

The wire body is capped at 4 MiB whatever its encoding; a gzip body is inflated with a
streaming decompressor that stops at 16 MiB, so a decompression bomb costs at most the cap.
Anything over a cap is 413 ``payload_too_large`` and nothing is stored.
"""

from __future__ import annotations

import zlib
from collections.abc import AsyncIterator

from ..core.problems import ProblemError
from .config import IngestConfig

_GZIP_WBITS = 16 + zlib.MAX_WBITS
_CHUNK = 64 * 1024


def _too_large(what: str, limit: int) -> ProblemError:
    return ProblemError("payload_too_large", f"{what} exceeds {limit // (1024 * 1024)} MiB")


async def read_capped(stream: AsyncIterator[bytes], limit: int) -> bytes:
    buf = bytearray()
    async for chunk in stream:
        buf += chunk
        if len(buf) > limit:
            raise _too_large("request body", limit)
    return bytes(buf)


def inflate(body: bytes, encoding: str | None, cfg: IngestConfig) -> bytes:
    """Decode ``Content-Encoding`` (identity or gzip) under the decompressed cap."""
    enc = (encoding or "identity").strip().lower()
    if enc in ("", "identity"):
        return body
    if enc != "gzip":
        raise ProblemError("unsupported_media_type", "Content-Encoding must be gzip or identity")
    inflater = zlib.decompressobj(_GZIP_WBITS)
    out = bytearray()
    view = memoryview(body)
    try:
        for start in range(0, len(view), _CHUNK):
            out += inflater.decompress(
                view[start : start + _CHUNK], cfg.max_decoded_bytes + 1 - len(out)
            )
            if len(out) > cfg.max_decoded_bytes or inflater.unconsumed_tail:
                raise _too_large("decompressed body", cfg.max_decoded_bytes)
        out += inflater.flush()
    except zlib.error:
        raise ProblemError("validation_failed", "body is not valid gzip") from None
    if len(out) > cfg.max_decoded_bytes:
        raise _too_large("decompressed body", cfg.max_decoded_bytes)
    if not inflater.eof or inflater.unused_data:
        raise ProblemError("validation_failed", "gzip body is truncated or has trailing data")
    return bytes(out)


def check_declared_length(value: str | None, cfg: IngestConfig) -> None:
    if value is None:
        return
    try:
        declared = int(value)
    except ValueError:
        raise ProblemError("validation_failed", "Content-Length is not an integer") from None
    if declared > cfg.max_body_bytes:
        raise _too_large("request body", cfg.max_body_bytes)
