"""Refusals a provider reports only in prose (ML.md §8.2 S-08, R37).

Some models refuse with an HTTP 200, ``finish_reason: stop`` and a sentence such as "I'm sorry,
but I can't help with that." Only the content tells such a refusal from an answer, so the
gateway, which sees every response body whatever the capture mode, recognises it here and
telemetry records the normalised finish reason ``refusal`` (the R6 refusal share counts it).
Nothing leaves the gateway but that flag.

Conservative by design: only a short, tool-free assistant text whose *opening* is a first-person
refusal qualifies; a long answer, or one that merely mentions an inability later on, does not.
"""

from __future__ import annotations

import re
from typing import Final

MAX_REFUSAL_CHARS: Final = 600
_APOSTROPHES: Final = str.maketrans({"\u2019": "'", "\u2018": "'", "\u02bc": "'"})
_OPENING: Final = re.compile(
    r"""^\W*
    (?:(?:i'm|i\ am|we're|we\ are)\s+(?:so\s+|very\s+|really\s+|truly\s+)?sorry
       |sorry|i\ apologi[sz]e|apologies|unfortunately)?
    [\s,.!:;-]*(?:but\s+)?
    (?:i|we)\s*
    (?:can't|cannot|can\ not|won't|will\ not|must\ decline\ to
       |(?:'m|'re|\ am|\ are)\s+(?:unable|not\ able|not\ allowed|not\ permitted)\ to)\s+
    (?:help|assist|comply|provide|do|fulfil|fulfill|answer|support|complete|share|process
       |continue|respond|engage|generate|create|write|give)\b""",
    re.IGNORECASE | re.VERBOSE,
)


def is_refusal_text(text: str) -> bool:
    """True when ``text`` (a whole assistant turn) is a prose refusal."""
    stripped = text.strip()
    if not stripped or len(stripped) > MAX_REFUSAL_CHARS:
        return False
    return _OPENING.match(stripped.translate(_APOSTROPHES)) is not None
