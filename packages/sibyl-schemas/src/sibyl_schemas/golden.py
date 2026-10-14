"""Golden fixture corpus shared by producers and consumers (seam tests, ROADMAP §4.8).

Each area directory holds `valid/*.json`, `invalid/*.json` and a `manifest.json` listing
every file with its schema, optional sub-schema pointer, expected verdict and, for
negatives, the JSON Pointer the violation must be reported at. Consumers iterate
`golden_cases()` and assert their own parser agrees with the verdict.

The corpus lives at `packages/sibyl-schemas/fixtures/` in the repository and is bundled
as `sibyl_schemas/_fixtures/` in the wheel.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Final

__all__ = [
    "AREAS",
    "BENIGN_TRANSFORMS",
    "SECRET_TRANSFORMS",
    "GoldenCase",
    "fixtures_root",
    "golden_cases",
    "load_fixture",
    "scrub_corpus",
]

AREAS: Final = ("ingest", "health", "handoff", "checkpoint", "snapshot", "action_gate")


@dataclass(frozen=True, slots=True)
class GoldenCase:
    area: str
    file: str
    schema: str
    valid: bool
    pointer: str | None = None
    error_pointer: str | None = None
    why: str | None = None

    @property
    def id(self) -> str:
        return f"{self.area}/{self.file}"

    def load(self) -> Any:
        return load_fixture(self.area, self.file)


@cache
def fixtures_root() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here / "_fixtures", here.parents[1] / "fixtures"):
        if (candidate / "ingest" / "manifest.json").is_file():
            return candidate
    raise FileNotFoundError("sibyl-schemas golden fixtures not found")


def load_fixture(area: str, relative: str) -> Any:
    path = fixtures_root() / area / relative
    return json.loads(path.read_text("utf-8"))


def golden_cases(*areas: str) -> list[GoldenCase]:
    selected = areas or AREAS
    cases: list[GoldenCase] = []
    for area in selected:
        if area not in AREAS:
            raise KeyError(f"unknown fixture area {area!r}")
        manifest = load_fixture(area, "manifest.json")
        cases.extend(
            GoldenCase(
                area=area,
                file=entry["file"],
                schema=entry["schema"],
                valid=entry["valid"],
                pointer=entry.get("pointer"),
                error_pointer=entry.get("error_pointer"),
                why=entry.get("why"),
            )
            for entry in manifest["cases"]
        )
    return cases


# --- secrets-scrub corpus (fixtures/scrub) ----------------------------------------------

STRUCTURED_SCRUB_FIELDS: Final = frozenset({"header", "tool_args", "state"})


def _json_escaped(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def _json_inner(text: str) -> str:
    return _json_escaped(text)[1:-1]


def _double_json(text: str) -> str:
    """A JSON document carried as a JSON string (OpenAI tool-call `arguments`)."""
    return json.dumps(json.dumps({"v": text}, ensure_ascii=False), ensure_ascii=False)


def _url_encoded(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def _crlf_prose(text: str) -> str:
    body = text.replace("\n", "\r\n")
    return f"FYI, pasted from the incident channel:\r\n{body}\r\nPlease rotate it today."


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


_Transform = tuple[Callable[[str], str], Callable[[str, str], str]]
"""(text transform, secret form): how the whole text and the secret inside it appear."""

SECRET_TRANSFORMS: Final[dict[str, _Transform]] = {
    "json_escaped": (_json_escaped, lambda secret, _text: _json_inner(secret)),
    "double_json": (_double_json, lambda secret, _text: _json_inner(_json_inner(secret))),
    "url_encoded": (_url_encoded, lambda secret, _text: _url_encoded(secret)),
    "base64_wrapped": (
        lambda text: f"payload={_b64(text)}",
        lambda _secret, text: _b64(text),
    ),
    "crlf_prose": (_crlf_prose, lambda secret, _text: secret.replace("\n", "\r\n")),
}
"""Metamorphic variants every scrubber implementation must still catch (G0 tests F7)."""

BENIGN_TRANSFORMS: Final = ("json_escaped", "double_json", "url_encoded", "crlf_prose")
"""Variants of the false-positive corpus that must stay untouched. `base64_wrapped` applies
only outside structured fields, where `high_entropy` (correctly) flags opaque blobs."""


def _jsonl(name: str) -> list[dict[str, Any]]:
    lines = (fixtures_root() / "scrub" / name).read_text("utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def scrub_corpus(kind: str, *, variants: bool = False) -> list[dict[str, Any]]:
    """Rows of `fixtures/scrub/{secrets,false_positives}.jsonl`, optionally with every
    deterministic transformed variant (`id` = `<base id>~<transform>`, `transform` set).

    A secret row's `secret` is the secret as it appears in that row's `text`.
    """
    if kind not in ("secrets", "false_positives"):
        raise KeyError(f"unknown scrub corpus {kind!r}")
    rows = _jsonl(f"{kind}.jsonl")
    if not variants:
        return rows
    out = list(rows)
    for row in rows:
        for name, (transform, secret_form) in SECRET_TRANSFORMS.items():
            if kind == "false_positives" and (
                name not in BENIGN_TRANSFORMS
                and (row["field"] in STRUCTURED_SCRUB_FIELDS or name != "base64_wrapped")
            ):
                continue
            variant = {**row, "id": f"{row['id']}~{name}", "transform": name}
            variant["text"] = transform(row["text"])
            if kind == "secrets":
                variant["secret"] = secret_form(row["secret"], row["text"])
            out.append(variant)
    return out
