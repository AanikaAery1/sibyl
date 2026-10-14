"""Unconditional secrets scrubber (`secrets_only` profile, detector registry `detectors/v1`).

    from sibyl_schemas.scrub import SecretsScrubber, ScrubField
    scrubber = SecretsScrubber(salt=os.environb[b"SIBYL_SCRUB_SALT"])
    result = scrubber.scrub(text, field=ScrubField.TOOL_ARGS)
    result.text, result.rules_fired, result.secrets_scrubbed

The same registry runs in the SDK, gateway, ingest and api (API §10.3); it cannot be
disabled or reordered, and tenant redaction profiles must be supersets of it.
`PROFILE_HASH` is `sha256(JCS({detectors, pipeline, replacement_format}))`,
tenant-independent, and is what `redaction_profile.profile_hash` records for the baseline.
`pipeline` pins the decoded views, base64 handling, windowing and size cap so every
implementation scrubs the same text the same way.
"""

from __future__ import annotations

from typing import Any, Final

from sibyl_schemas.canonical import canonical_sha256
from sibyl_schemas.scrub._detectors import (
    DETECTORS,
    ENTROPY_THRESHOLD,
    REPLACEMENT_FORMAT,
    REPLACEMENT_PATTERN,
    STRUCTURED_FIELDS,
    VALIDATORS,
    Detector,
    DetectorPattern,
    ScrubField,
    SecretKind,
    shannon_entropy,
)
from sibyl_schemas.scrub._scrubber import (
    BASE64_MAX_CHARS,
    BASE64_MAX_DEPTH,
    BASE64_MIN_CHARS,
    KEY_COLLISION_SEPARATOR,
    MAX_SCRUB_CHARS,
    WINDOW_CHARS,
    WINDOW_OVERLAP_CHARS,
    Finding,
    ScrubInputTooLarge,
    ScrubResult,
    SecretsScrubber,
)
from sibyl_schemas.scrub._views import VIEW_CHAINS

__all__ = [
    "BASE64_MAX_CHARS",
    "BASE64_MAX_DEPTH",
    "BASE64_MIN_CHARS",
    "DETECTORS",
    "ENTROPY_THRESHOLD",
    "KEY_COLLISION_SEPARATOR",
    "MAX_SCRUB_CHARS",
    "PROFILE_HASH",
    "PROFILE_ID",
    "PROFILE_VERSION",
    "REGISTRY_VERSION",
    "REPLACEMENT_FORMAT",
    "REPLACEMENT_PATTERN",
    "STRUCTURED_FIELDS",
    "VALIDATORS",
    "VIEW_CHAINS",
    "WINDOW_CHARS",
    "WINDOW_OVERLAP_CHARS",
    "Detector",
    "DetectorPattern",
    "Finding",
    "ScrubField",
    "ScrubInputTooLarge",
    "ScrubResult",
    "SecretKind",
    "SecretsScrubber",
    "export_registry",
    "pipeline_document",
    "profile_document",
    "shannon_entropy",
]

REGISTRY_VERSION: Final = "detectors/v1"
PROFILE_ID: Final = "secrets_only"
PROFILE_VERSION: Final = 1


def _detector_document(detector: Detector) -> dict[str, Any]:
    return {
        "id": detector.id,
        "kind": detector.kind.value,
        "patterns": [
            {"regex": p.regex, "flags": p.flags, "group": p.group} for p in detector.patterns
        ],
        "validator": detector.validator,
        "requires": detector.requires,
        "fields": sorted(f.value for f in detector.fields) if detector.fields else None,
    }


def pipeline_document() -> dict[str, Any]:
    """How text reaches the detectors; part of the profile hash (G0 fix pass)."""
    return {
        "max_chars": MAX_SCRUB_CHARS,
        "window_chars": WINDOW_CHARS,
        "window_overlap_chars": WINDOW_OVERLAP_CHARS,
        "views": [list(chain) for chain in VIEW_CHAINS],
        "decoders": {
            "json": 'JSON string escapes \\" \\\\ \\/ \\b \\f \\n \\r \\t \\uXXXX',
            "percent": "runs of %XX decoded as UTF-8 (undecodable bytes match nothing); "
            "'+' is left alone",
            "format": "strip Unicode Cf format characters (zero-width, bidi, BOM, soft hyphen); "
            "fold fullwidth U+FF01-U+FF5E to ASCII",
        },
        "base64": {
            "min_chars": BASE64_MIN_CHARS,
            "max_chars": BASE64_MAX_CHARS,
            "views": "every view except those ending in the format decoder",
            "max_depth": BASE64_MAX_DEPTH,
            "printable_ratio": 0.9,
            "replace": "whole run, labelled with the highest-priority inner detector",
        },
        "overlap": "higher priority first, then longer match",
        "existing_tokens": "never rescanned; a candidate starting inside one is dropped, one "
        "starting before one keeps token-free pieces of >= 4 chars containing [A-Za-z0-9]",
        "token_hash_input": "the secret as decoded in the view that found it",
    }


def profile_document() -> dict[str, Any]:
    """The JCS input of the profile content hash: detectors ‖ pipeline ‖ replacement format."""
    return {
        "detectors": [_detector_document(d) for d in DETECTORS],
        "pipeline": pipeline_document(),
        "replacement_format": REPLACEMENT_FORMAT,
    }


PROFILE_HASH: Final = canonical_sha256(profile_document())


def export_registry() -> dict[str, Any]:
    """Contents of `detectors.v1.json`, shared with the TypeScript SDK."""
    return {
        "registry": REGISTRY_VERSION,
        "profile": PROFILE_ID,
        "version": PROFILE_VERSION,
        "content_hash": PROFILE_HASH,
        "replacement_format": REPLACEMENT_FORMAT,
        "hash": "first 8 hex of sha256(SIBYL_SCRUB_SALT || match)",
        "entropy_threshold_bits_per_char": ENTROPY_THRESHOLD,
        "validators": sorted(VALIDATORS),
        "pipeline": pipeline_document(),
        "detectors": profile_document()["detectors"],
    }
