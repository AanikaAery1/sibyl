"""Model drift value sets (D51, wave 3 lane DRIFT): baselines, verdicts, features, statistics.

`sibyl.drift_baseline` and `sibyl.drift_report` CHECK constraints enumerate exactly these
(drift-tested). Detection is deterministic: PSI over binned numeric features, Jensen-Shannon
divergence over categorical ones, plus model-identity checks; no LLM is involved.
"""

from __future__ import annotations

from enum import StrEnum


class DriftBaselineState(StrEnum):
    """`collecting -> frozen -> superseded` (a reset supersedes a collecting baseline too)."""

    COLLECTING = "collecting"
    FROZEN = "frozen"
    SUPERSEDED = "superseded"


class DriftVerdict(StrEnum):
    """Behavioural verdict of one evaluation; ordered by severity."""

    NONE = "none"
    WATCH = "watch"
    DRIFT = "drift"


class DriftFeature(StrEnum):
    """The behavioural features compared against the frozen baseline."""

    OUTPUT_TOKENS = "output_tokens"
    INPUT_TOKENS = "input_tokens"
    LATENCY_MS = "latency_ms"
    REFUSAL = "refusal"
    TRUNCATION = "truncation"
    TOOL_CALL = "tool_call"
    SCHEMA_FAIL = "schema_fail"
    ERROR_CLASS = "error_class"
    TOOL_BIGRAM = "tool_bigram"


class DriftStatistic(StrEnum):
    """`psi`: population stability index over baseline-decile bins (numeric features);
    `js`: Jensen-Shannon divergence, base 2, in [0, 1] (categorical features)."""

    PSI = "psi"
    JS = "js"


class DriftIdentityChange(StrEnum):
    """Model identity drift: what the provider served differs from what was asked for or from
    what the baseline saw."""

    SERVED_MODEL_MISMATCH = "served_model_mismatch"
    NEW_SERVED_MODEL = "new_served_model"
    NEW_FINGERPRINT = "new_fingerprint"
