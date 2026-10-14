"""Detector registry `detectors/v1` for the `secrets_only` baseline profile.

Twenty-three detectors (security-auditor §5.2 plus the G0 fix-pass additions), in priority
order: when two matches overlap, the earlier detector wins (so `sk-ant-…` is an Anthropic
key, not an OpenAI one). Patterns are written in the common subset of Python `re` and
ECMAScript regex (flags are separate, no inline `(?i)`), because the TypeScript SDK loads
`detectors.v1.json`.

Linear time (security H4). ECMAScript has no possessive or atomic groups, so every pattern
is linear by construction instead:
- every run that is followed by more pattern is bounded (`{0,N}`) or uses a class that
  excludes the next delimiter, so a failed attempt costs O(N) at most;
- run starts are anchored by a lookbehind on the run's own class, so a long run is tried
  from its first character only, never from every character inside it;
- URL userinfo cannot cross `://`, so attempts from consecutive schemes never overlap;
- PEM bodies cannot contain `-----`, so an attempt stops at the next marker.
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class SecretKind(StrEnum):
    SECRET = "SECRET"  # noqa: S105 (a kind label, not a credential)
    TOKEN = "TOKEN"  # noqa: S105
    PRIVATE_KEY = "PRIVATE_KEY"
    ENTROPY = "ENTROPY"


class ScrubField(StrEnum):
    """Where a string came from; `high_entropy` runs only on structured fields."""

    INPUT_MESSAGES = "input_messages"
    OUTPUT_MESSAGES = "output_messages"
    SYSTEM_INSTRUCTIONS = "system_instructions"
    TOOL_DEFINITIONS = "tool_definitions"
    TOOL_ARGS = "tool_args"
    TOOL_RESULT = "tool_result"
    STATE = "state"
    COMMENT = "comment"
    HEADER = "header"
    AUDIT_TEXT = "audit_text"


STRUCTURED_FIELDS: Final = frozenset({ScrubField.HEADER, ScrubField.TOOL_ARGS, ScrubField.STATE})

REPLACEMENT_FORMAT: Final = "[{kind}:{hash8}]"
REPLACEMENT_PATTERN: Final = re.compile(r"\[(?:SECRET|TOKEN|PRIVATE_KEY|ENTROPY):[0-9a-f]{8}\]")
ENTROPY_THRESHOLD: Final = 4.5
ENTROPY_MIN_LENGTH: Final = 32


@dataclass(frozen=True, slots=True)
class DetectorPattern:
    regex: str
    flags: str = ""
    group: int = 0
    """Capture group replaced (0 = whole match); value-only detectors keep the key name."""

    def compile(self) -> re.Pattern[str]:
        flags = re.NOFLAG
        if "i" in self.flags:
            flags |= re.IGNORECASE
        if "s" in self.flags:
            flags |= re.DOTALL
        return re.compile(self.regex, flags)


@dataclass(frozen=True, slots=True)
class Detector:
    id: str
    kind: SecretKind
    patterns: tuple[DetectorPattern, ...]
    validator: str | None = None
    """Name of a post-match check in `VALIDATORS` (portable by name to other SDKs)."""
    requires: str | None = None
    """Context regex that must occur somewhere in the text for the detector to run."""
    fields: frozenset[ScrubField] | None = None
    """None = every field."""


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


_PLACEHOLDER: Final = re.compile(
    r"^(?:\$\{|\{\{|<|%\(|%s|process\.env|os\.environ|os\.getenv|env\(|getenv\(|vault:|"
    r"\[(?:SECRET|TOKEN|PRIVATE_KEY|ENTROPY):)"
    r"|^[*xX•._-]+$",
)
_PROSE_WORD: Final = re.compile(r"^[a-z]+$")


def _high_entropy(match: str) -> bool:
    return len(match) >= ENTROPY_MIN_LENGTH and shannon_entropy(match) >= ENTROPY_THRESHOLD


def _mixed_alnum(match: str) -> bool:
    return any(c.isdigit() for c in match) and any(c.isalpha() for c in match)


def _not_placeholder(match: str) -> bool:
    return not _PLACEHOLDER.search(match)


def _not_prose_word(match: str) -> bool:
    return not _PROSE_WORD.match(match)


_PATH_LIKE: Final = re.compile(r"^(?:~?/|\.\.?/|[A-Za-z]:\\)")


def _kv_value(match: str) -> bool:
    """`not_placeholder`, and not a filesystem path (`PWD=/home/runner/work`)."""
    return _not_placeholder(match) and not _PATH_LIKE.match(match)


_BASIC_PRINTABLE: Final = re.compile(r"^[\x21-\x7e][\x20-\x7e]*$")


def _basic_credentials(match: str) -> bool:
    """`Basic <b64>` whose payload decodes to printable `user:password`."""
    try:
        decoded = base64.b64decode(match + "=" * (-len(match) % 4), validate=True)
        text = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    user, sep, password = text.partition(":")
    return bool(sep and user and password and _BASIC_PRINTABLE.match(text))


VALIDATORS: Final[dict[str, Callable[[str], bool]]] = {
    "high_entropy": _high_entropy,
    "mixed_alnum": _mixed_alnum,
    "not_placeholder": _not_placeholder,
    "not_prose_word": _not_prose_word,
    "kv_value": _kv_value,
    "basic_credentials": _basic_credentials,
}

_P = DetectorPattern
_DB_SCHEMES: Final = r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)"

# PEM. A complete block: header, a body that cannot contain "-----", footer. A truncated
# block (cut-off tool output): header, optional `Name: value` lines, then base64 lines.
_PEM_HEAD: Final = r"-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----"
_PEM_FOOT: Final = r"-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----"
_PEM_BODY: Final = r"(?:[A-Za-z0-9+/=:,. \t\r\n\\]|-(?!----)){0,8192}"
_NL: Final = r"(?:\r?\n|\\r?\\n)"
_WS: Final = r"(?:[ \t\r\n]|\\[rn])"
_PEM_TRUNCATED_BODY: Final = (
    _WS
    + r"{0,8}(?:[A-Za-z][A-Za-z-]{0,30}:[^\r\n\\]{0,128}"
    + _NL
    + r"){0,4}"
    + _WS
    + r"{0,8}(?:[A-Za-z0-9+/=]{16,128}"
    + _WS
    + r"{0,4}){1,256}"
)


def _pem(head: str, foot: str) -> tuple[DetectorPattern, DetectorPattern]:
    return _P(head + _PEM_BODY + foot), _P(head + _PEM_TRUNCATED_BODY)


# URL userinfo: user, then a password that may contain `/` and `@` (taken up to the last `@`
# that is followed by a host) but never `://`, and never just a port (`host:8080/x@y`).
# The DSN query form walks non-empty path segments, so `//` (the next `scheme://`) ends an
# attempt at once and attempts from consecutive schemes never overlap.
# Value classes that stop at quotes also stop at `\`, so a replacement never eats the
# backslash of an escaped quote (the decoded JSON views see escaped values whole).
_USER: Final = r"[^:/\s@\"'?#\\]{0,128}"
_USERINFO_VALUE: Final = (
    r"((?![0-9]{1,5}(?:[/?#\s\"']|$))(?:[^\s\"':\\]|:(?!//)){1,256})@(?=[A-Za-z0-9\[])"
)
_SCHEME_START: Final = r"(?<![A-Za-z0-9+.-])"
_KV_KEYS: Final = r"(?:api[_-]?key|client[_-]?secret|secret|password|passwd|pwd|passphrase|token)"
_KV_SEP: Final = r"[\"']?\s{0,16}[:=]\s{0,16}[\"']?"

DETECTORS: Final[tuple[Detector, ...]] = (
    Detector(
        "sibyl_key",
        SecretKind.SECRET,
        (
            _P(
                r"(?<![A-Za-z0-9])sbl_(?:live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}"
                r"(?![A-Za-z0-9_-])"
            ),
        ),
    ),
    Detector(
        "anthropic_key", SecretKind.SECRET, (_P(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}"),)
    ),
    Detector(
        "openai_key",
        SecretKind.SECRET,
        (_P(r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),),
        validator="mixed_alnum",
    ),
    Detector(
        "stripe_key",
        SecretKind.SECRET,
        (_P(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}"),),
    ),
    Detector(
        "github_token",
        SecretKind.SECRET,
        (
            _P(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,}"),
            _P(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{82}"),
        ),
    ),
    Detector(
        "gitlab_token",
        SecretKind.SECRET,
        (
            _P(
                r"(?<![A-Za-z0-9_-])gl(?:pat|dt|rt|ptt|cbt|soat|ft|imt|agent)-"
                r"[A-Za-z0-9_-]{20,}"
            ),
        ),
    ),
    Detector(
        "huggingface_token",
        SecretKind.SECRET,
        (_P(r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])"),),
    ),
    Detector(
        "slack_token", SecretKind.SECRET, (_P(r"(?<![A-Za-z0-9_-])xox[abprs]-[A-Za-z0-9-]{10,}"),)
    ),
    Detector(
        "slack_webhook",
        SecretKind.SECRET,
        (
            _P(
                r"\bhooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9_/+-]{20,256})",
                flags="i",
                group=1,
            ),
        ),
    ),
    Detector(
        "google_api_key",
        SecretKind.SECRET,
        (_P(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),),
    ),
    Detector(
        "aws_access_key",
        SecretKind.SECRET,
        (_P(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),),
    ),
    Detector(
        "aws_secret_key",
        SecretKind.SECRET,
        (
            _P(
                r"(?:aws_?secret(?:_?access)?_?key|secret_?access_?key)"
                + _KV_SEP
                + r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
                flags="i",
                group=1,
            ),
        ),
    ),
    Detector(
        "gcp_sa_key",
        SecretKind.SECRET,
        (
            _P(r"\"private_key_id\"\s{0,16}:\s{0,16}\"([0-9a-f]{40})\"", group=1),
            _P(
                r"\"private_key\"\s{0,16}:\s{0,16}\"("
                + _PEM_HEAD
                + r"(?:"
                + _PEM_BODY
                + _PEM_FOOT
                + r"(?:\\n)?|"
                + _PEM_TRUNCATED_BODY
                + r"))",
                group=1,
            ),
        ),
        requires=r"\"private_key_id\"",
    ),
    Detector(
        "azure_conn_string",
        SecretKind.SECRET,
        (
            _P(r"AccountKey=([A-Za-z0-9+/]{86,}={0,2})", group=1),
            _P(r"SharedAccessKey=([A-Za-z0-9+/]{42,}={0,2})", group=1),
            _P(r"SharedAccessSignature=([^;\s\"'\\]+)", group=1),
        ),
    ),
    Detector(
        "jwt",
        SecretKind.TOKEN,
        (
            _P(
                r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}"
                r"\.[A-Za-z0-9_-]{8,}"
            ),
        ),
    ),
    Detector(
        "ssh_key",
        SecretKind.PRIVATE_KEY,
        (
            *_pem(r"-----BEGIN OPENSSH PRIVATE KEY-----", r"-----END OPENSSH PRIVATE KEY-----"),
            _P(
                r"Private-Lines:[ \t]{0,8}\d{1,4}"
                + _NL
                + r"((?:[A-Za-z0-9+/=]{4,128}"
                + _NL
                + r"){1,256})",
                group=1,
            ),
        ),
    ),
    Detector("pem_block", SecretKind.PRIVATE_KEY, _pem(_PEM_HEAD, _PEM_FOOT)),
    Detector(
        "dsn",
        SecretKind.SECRET,
        (
            _P(
                _SCHEME_START + _DB_SCHEMES + r"://" + _USER + r":" + _USERINFO_VALUE,
                flags="i",
                group=1,
            ),
            _P(
                _SCHEME_START
                + _DB_SCHEMES
                + r"://[^\s\"'?#/]{0,256}(?:/[^\s\"'?#/]{1,256}){0,16}/?"
                r"\?(?:[^\s\"'&#]{0,256}&){0,32}(?:password|passwd|pwd)=([^&\s\"'#\\]{1,512})",
                flags="i",
                group=1,
            ),
        ),
    ),
    Detector(
        "basic_auth_url",
        SecretKind.SECRET,
        (
            _P(
                _SCHEME_START + r"[a-z][a-z0-9+.-]{0,31}://" + _USER + r":" + _USERINFO_VALUE,
                flags="i",
                group=1,
            ),
        ),
    ),
    Detector(
        "bearer_header",
        SecretKind.TOKEN,
        (_P(r"\bbearer\s{1,8}([A-Za-z0-9._~+/=-]{16,})", flags="i", group=1),),
        validator="not_prose_word",
    ),
    Detector(
        "basic_auth_header",
        SecretKind.SECRET,
        (
            _P(
                r"\bbasic\s{1,8}([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])",
                flags="i",
                group=1,
            ),
        ),
        validator="basic_credentials",
    ),
    Detector(
        "generic_secret_kv",
        SecretKind.SECRET,
        (_P(_KV_KEYS + _KV_SEP + r"([^\s\"'\\]{12,})", flags="i", group=1),),
        validator="kv_value",
    ),
    Detector(
        "high_entropy",
        SecretKind.ENTROPY,
        (
            _P(
                r"(?<![A-Za-z0-9+/=_%-])(?<!base64,)(?!sha(?:256|384|512)-)"
                r"[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9+/=_-])"
            ),
        ),
        validator="high_entropy",
        fields=STRUCTURED_FIELDS,
    ),
)
