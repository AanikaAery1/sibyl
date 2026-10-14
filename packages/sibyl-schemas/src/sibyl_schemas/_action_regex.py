"""Safe-regex admission for Action Gate `matches` predicates.

Python's `re` backtracks and cannot be interrupted, so a policy pattern is admitted only when
its worst case stays polynomial and small on a bounded subject (`MAX_MATCH_SUBJECT`):

* at most `MAX_PATTERN_LENGTH` characters, and it must compile;
* no backreferences, conditionals or lookaround (they defeat the bounds below);
* no nested quantifier (`(a+)+`, `(x+x+)+y`): a repeat may not contain another repeat;
* no alternation inside an unbounded repeat (`(a|a)*`): overlapping branches are exponential;
* at most `MAX_LARGE_REPEATS` repeats whose upper bound exceeds `LARGE_REPEAT` (`*`, `+`,
  `{n,}`, `{n,1000}`), so adjacent quantifiers stay at most quadratic in the subject length.

Matching is always anchored (`fullmatch`); the predicate never searches.
"""

from __future__ import annotations

import re
import re._constants as _c
import re._parser as _p
from functools import lru_cache
from typing import Any, Final

MAX_PATTERN_LENGTH: Final = 256
MAX_MATCH_SUBJECT: Final = 1024
MAX_LARGE_REPEATS: Final = 2
LARGE_REPEAT: Final = 64

_REPEATS: Final = frozenset(
    op
    for op in (
        getattr(_c, "MAX_REPEAT", None),
        getattr(_c, "MIN_REPEAT", None),
        getattr(_c, "POSSESSIVE_REPEAT", None),
    )
    if op is not None
)
_FORBIDDEN: Final = frozenset(
    op
    for op in (
        getattr(_c, "GROUPREF", None),
        getattr(_c, "GROUPREF_EXISTS", None),
        getattr(_c, "ASSERT", None),
        getattr(_c, "ASSERT_NOT", None),
    )
    if op is not None
)


class UnsafePattern(ValueError):
    pass


def _children(op: Any, av: Any) -> list[Any]:
    """Sub-patterns of one parsed node (repeat bodies are handled by the caller)."""
    if op is _c.SUBPATTERN:
        return [av[-1]]
    if op is _c.BRANCH:
        return list(av[1])
    if op is getattr(_c, "ATOMIC_GROUP", None):
        return [av]
    return []


def _walk(sub: Any, *, in_repeat: bool, in_large: bool, large: list[int]) -> None:
    for op, av in sub:
        if op in _FORBIDDEN:
            raise UnsafePattern("backreferences, conditionals and lookaround are not allowed")
        if op in _REPEATS:
            low, high, body = av
            del low
            if in_repeat:
                raise UnsafePattern("nested quantifiers are not allowed")
            is_large = high is _c.MAXREPEAT or high > LARGE_REPEAT
            if is_large:
                large[0] += 1
            _walk(body, in_repeat=high > 1, in_large=is_large, large=large)
            continue
        if op is _c.BRANCH and in_large:
            raise UnsafePattern("alternation inside an unbounded repeat is not allowed")
        for child in _children(op, av):
            _walk(child, in_repeat=in_repeat, in_large=in_large, large=large)


def check_pattern(pattern: str) -> str:
    """Return the pattern if it is admissible, else raise `UnsafePattern`."""
    if not 1 <= len(pattern) <= MAX_PATTERN_LENGTH:
        raise UnsafePattern(f"pattern length must be 1..{MAX_PATTERN_LENGTH}")
    try:
        parsed = _p.parse(pattern)
        re.compile(pattern)
    except (re.error, RecursionError, OverflowError) as exc:
        raise UnsafePattern(f"pattern does not compile: {exc}") from None
    large = [0]
    _walk(parsed, in_repeat=False, in_large=False, large=large)
    if large[0] > MAX_LARGE_REPEATS:
        raise UnsafePattern(f"at most {MAX_LARGE_REPEATS} unbounded quantifiers are allowed")
    return pattern


@lru_cache(maxsize=4096)
def compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(check_pattern(pattern))
