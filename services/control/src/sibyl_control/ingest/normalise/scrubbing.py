"""Step 5 (unconditional secrets scrub, then the tenant profile) and step 6 (capture mode).

Ingest scrubs again whatever the emitter did (D12): every string leaf **and key** of the
envelope and ``attrs`` (decoded views, schemas 1.1.0), and every payload body before it is
sealed. ``ScrubInputTooLarge`` turns into a rejection, never a pass-through. JSON bodies are
parsed strictly, scrubbed per part (the ``ScrubField`` follows the part, so ``high_entropy``
only runs on structured parts), then re-serialised; other bodies are scrubbed as UTF-8 bytes.

``pii_standard`` redaction (``capture_mode = redacted``, API.md §10.3) uses the shared
``sibyl_schemas.pii`` registry, so the SDK, gateway and ingest detect identically; ingest only
adds its salted, non-reversible replacement token (``PiiRedactor``).

``rule_ids`` turns the rules fired into what ``events.scrub_rules_fired`` accepts (0007 CHECK).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Final

from sibyl_schemas.canonical import CanonicalizationError, parse_json_strict
from sibyl_schemas.pii import PII_DETECTORS, redact_pii
from sibyl_schemas.scrub import ScrubField, ScrubInputTooLarge, SecretsScrubber

from .candidate import Content
from .fields import dumps

PART_FIELDS: dict[str, ScrubField] = {
    "input_messages": ScrubField.INPUT_MESSAGES,
    "output_messages": ScrubField.OUTPUT_MESSAGES,
    "system_instructions": ScrubField.SYSTEM_INSTRUCTIONS,
    "tool_definitions": ScrubField.TOOL_DEFINITIONS,
    "tool_args": ScrubField.TOOL_ARGS,
    "tool_result": ScrubField.TOOL_RESULT,
    "state": ScrubField.STATE,
    "comment": ScrubField.COMMENT,
    "original_input": ScrubField.INPUT_MESSAGES,
    "raw_span": ScrubField.STATE,
}
TYPE_FIELDS: dict[str, ScrubField] = {
    "gen_ai.request": ScrubField.INPUT_MESSAGES,
    "tool.call": ScrubField.TOOL_ARGS,
    "checkpoint": ScrubField.STATE,
    "handoff.requested": ScrubField.STATE,
    "handoff.completed": ScrubField.COMMENT,
    "handoff.returned": ScrubField.COMMENT,
    "feedback": ScrubField.COMMENT,
}
ENVELOPE_FIELD = ScrubField.STATE
MODE_RANK = {"metadata": 0, "redacted": 1, "full": 2}


# ``events.scrub_rules_fired`` (0007): at most 64 ids, each ``[A-Za-z0-9_.:-]{1,64}``.
MAX_RULE_IDS: Final = 64
_RULE_ID: Final = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
RULE_ID_INVALID: Final = "ingest.rule_id_invalid"
RULES_TRUNCATED: Final = "ingest.rules_truncated"


def rule_ids(raw: Iterable[Any] | None) -> list[str]:
    """Deduped, sorted rule ids that satisfy the DB CHECK. A non-conforming id (it may carry
    whatever text an emitter put there) is never kept: one ``RULE_ID_INVALID`` marker stands in
    for all of them. Over 64 ids, the sorted list is cut and ``RULES_TRUNCATED`` added.
    Idempotent, so a merge may apply it again."""
    valid: set[str] = set()
    markers: set[str] = set()
    for item in raw or ():
        if isinstance(item, str) and _RULE_ID.fullmatch(item):
            (markers if item in (RULE_ID_INVALID, RULES_TRUNCATED) else valid).add(item)
        else:
            markers.add(RULE_ID_INVALID)
    ordered = sorted(valid)
    if len(ordered) + len(markers) > MAX_RULE_IDS:
        markers.add(RULES_TRUNCATED)
        ordered = ordered[: MAX_RULE_IDS - len(markers)]
    return sorted([*ordered, *markers])


class PiiRedactor:
    """``pii_standard`` over the shared ``sibyl_schemas.pii`` detectors with ingest's salted
    token ``[PII_<DETECTOR>:<8 hex of sha256(salt + value)>]``."""

    def __init__(self, salt: bytes, detector_ids: tuple[str, ...]) -> None:
        self._salt = salt
        self._detectors = tuple(d for d in detector_ids if d in PII_DETECTORS)
        self.unimplemented: tuple[str, ...] = ()  # every pii_standard detector is implemented

    def _token(self, rule: str, value: str) -> str:
        return f"[PII_{rule.upper()}:{hashlib.sha256(self._salt + value.encode()).hexdigest()[:8]}]"

    def redact(self, text: str) -> tuple[str, set[str]]:
        if not self._detectors:
            return text, set()
        return redact_pii(text, self._detectors, self._token)

    def redact_json(self, value: Any) -> tuple[Any, set[str]]:
        fired: set[str] = set()

        def walk(node: Any) -> Any:
            if isinstance(node, str):
                out, hits = self.redact(node)
                fired.update(hits)
                return out
            if isinstance(node, dict):
                return {k: walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v) for v in node]
            return node

        return walk(value), fired


class ScrubRefused(ValueError):
    """The input cannot be scrubbed (over the scrubber's size cap): reject the event."""


def strictest(*modes: str | None) -> str:
    present = [m for m in modes if m in MODE_RANK]
    return min(present, key=MODE_RANK.__getitem__) if present else "metadata"


def is_json(content_type: str) -> bool:
    base = content_type.split(";", 1)[0].strip().lower()
    return base == "application/json" or base.endswith("+json")


@dataclass
class ScrubTally:
    secrets: int = 0
    rules: set[str] = field(default_factory=set)

    def add(self, findings: list[Any]) -> None:
        self.secrets += len(findings)
        self.rules.update(f"secrets.{f.detector_id}" for f in findings)


class Scrubber:
    def __init__(self, secrets: SecretsScrubber, salt: bytes) -> None:
        self._secrets = secrets
        self._salt = salt

    def pii(self, detector_ids: tuple[str, ...]) -> PiiRedactor:
        return PiiRedactor(self._salt, detector_ids)

    def scrub_value(self, value: Any, scrub_field: ScrubField, tally: ScrubTally) -> Any:
        try:
            clean, findings = self._secrets.scrub_json(value, scrub_field)
        except ScrubInputTooLarge as exc:
            raise ScrubRefused(str(exc)) from None
        tally.add(findings)
        return clean

    def scrub_text(self, text: str, scrub_field: ScrubField, tally: ScrubTally) -> str:
        try:
            result = self._secrets.scrub(text, scrub_field)
        except ScrubInputTooLarge as exc:
            raise ScrubRefused(str(exc)) from None
        tally.add(list(result.findings))
        return result.text

    def scrub_document(self, doc: Any, text_field: ScrubField, tally: ScrubTally) -> Any:
        """Scrub the serialised document as one text first, so context-gated detectors
        (``aws_secret_key``, ``gcp_sa_key``) still see the key next to the value, then parse
        it back. A replacement that breaks the JSON structure refuses the document."""
        text = dumps(doc).decode("utf-8", errors="surrogatepass")
        cleaned = self.scrub_text(text, text_field, tally)
        if cleaned == text:
            return doc
        try:
            return parse_json_strict(cleaned, max_bytes=len(cleaned.encode()) + 1, max_depth=128)
        except CanonicalizationError:
            raise ScrubRefused("a secret spans JSON structure; refusing to store it") from None

    def scrub_event(self, event: dict[str, Any], tally: ScrubTally) -> dict[str, Any]:
        """One pass over the serialised envelope + ``attrs`` (keys included) as a structured
        field, so ``high_entropy`` also runs; equivalent to scrubbing every leaf and key, with
        the surrounding context that leaf-wise scrubbing loses."""
        cleaned: dict[str, Any] = self.scrub_document(event, ENVELOPE_FIELD, tally)
        return cleaned

    def scrub_content(
        self, content: Content, event_type: str, tally: ScrubTally, pii: PiiRedactor | None
    ) -> tuple[Content, Any | None]:
        """Return the scrubbed body and, for JSON bodies, the scrubbed document."""
        default = TYPE_FIELDS.get(event_type, ScrubField.STATE)
        if is_json(content.content_type):
            try:
                doc = parse_json_strict(
                    content.data, max_bytes=len(content.data) + 1, max_depth=128
                )
            except CanonicalizationError:
                doc = None
            if doc is not None:
                try:
                    if isinstance(doc, dict) and doc and set(doc) <= set(PART_FIELDS):
                        doc = {
                            k: self.scrub_document(v, PART_FIELDS[k], tally) for k, v in doc.items()
                        }
                    else:
                        doc = self.scrub_document(doc, default, tally)
                except ScrubRefused:
                    doc = None
            if doc is not None:
                if pii is not None:
                    doc, fired = pii.redact_json(doc)
                    tally.rules.update(fired)
                return Content(dumps(doc), content.content_type, content.parts), doc
        try:
            text = content.data.decode("utf-8", errors="surrogateescape")
            result = self._secrets.scrub(text, default)
        except ScrubInputTooLarge as exc:
            raise ScrubRefused(str(exc)) from None
        tally.add(list(result.findings))
        cleaned = result.text
        if pii is not None:
            cleaned, fired = pii.redact(cleaned)
            tally.rules.update(fired)
        return Content(
            cleaned.encode("utf-8", errors="surrogateescape"), content.content_type, content.parts
        ), None
