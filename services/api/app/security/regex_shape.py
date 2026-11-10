"""Shape checks for regular expressions that people supply.

Ported from KEEN's ``check_scan_pattern`` (app/security/regex.py); keep the
two aligned. Python's engine backtracks, so a pattern such as ``(a+)+$`` or
``(a|a)*$`` takes time exponential in the text it searches. Release-feed
ignore patterns are written by project editors and searched against text from
upstream feeds, so a pattern is refused when it is saved, and again before it
runs, unless its matching state and backtracking stay bounded.
"""

from __future__ import annotations

import re
from functools import lru_cache
from re import _parser  # type: ignore[attr-defined]  # CPython's parser has no stub

# A greedy or lazy repeat of anything wider than one character keeps
# backtracking state for every repetition. A possessive repeat keeps none, and
# a bounded one keeps at most its bound, multiplied by the bounds of the
# repeats around it.
REPEATS_HELD = 1024
# The longest pattern accepted.
MAX_PATTERN_CHARS = 256
_ONE_CHARACTER = {_parser.ANY, _parser.IN, _parser.LITERAL, _parser.NOT_LITERAL}
_REPEATS = (_parser.MAX_REPEAT, _parser.MIN_REPEAT, _parser.POSSESSIVE_REPEAT)
_HELD_REPEAT = (
    "repeat a group or alternatives possessively (*+, ++ or {m,n}+), "
    f"or at most {REPEATS_HELD} times in all: matching keeps state for every "
    "repetition"
)
_NESTED_REPEAT = (
    "make an unbounded repeat inside another repeat possessive: nested repeats "
    "backtrack exponentially"
)


def _one_character(items) -> bool:
    if len(items) != 1:
        return False
    op, value = items[0]
    if op == _parser.SUBPATTERN:
        return value[0] is None and _one_character(value[-1])
    return op in _ONE_CHARACTER


def check_pattern_shape(pattern: str, flags: int = 0) -> None:
    """Raise ValueError for a pattern whose matching can grow without bound."""
    if len(pattern) > MAX_PATTERN_CHARS:
        raise ValueError(f"patterns are at most {MAX_PATTERN_CHARS} characters")
    if flags & re.VERBOSE or re.search(r"\(\?[a-zA-Z]*x", pattern):
        raise ValueError("expanded mode (the x flag) is unsupported")
    try:
        parsed = _parser.parse(pattern, flags)
    except (re.error, RecursionError) as exc:
        raise ValueError(f"invalid regex pattern: {exc}") from exc

    def check(items, held, repeated):
        for op, value in items:
            if op in _REPEATS:
                high, body = value[1], value[2]
                if op == _parser.POSSESSIVE_REPEAT:
                    # Each repetition commits, so its state lasts one repetition.
                    check(body, 1, False)
                    continue
                unbounded = high == _parser.MAXREPEAT
                if unbounded and repeated:
                    raise ValueError(_NESTED_REPEAT)
                inner = held
                if not _one_character(body):
                    inner = REPEATS_HELD + 1 if unbounded else held * high
                    if inner > REPEATS_HELD:
                        raise ValueError(_HELD_REPEAT)
                check(body, inner, repeated or high > 1)
            elif op == _parser.SUBPATTERN:
                check(value[-1], held, repeated)
            elif op == _parser.ATOMIC_GROUP:
                check(value, held, repeated)
            elif op == _parser.BRANCH:
                for branch in value[1]:
                    check(branch, held, repeated)
            elif op in (_parser.ASSERT, _parser.ASSERT_NOT):
                check(value[1], held, repeated)
            elif op == _parser.GROUPREF_EXISTS:
                check(value[1], held, repeated)
                if value[2] is not None:
                    check(value[2], held, repeated)
            elif op == _parser.GROUPREF:
                raise ValueError("back-references are unsupported")

    check(parsed, 1, False)


@lru_cache(maxsize=256)
def compile_supplied_pattern(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Compile a supplied pattern once it passes the shape checks."""
    check_pattern_shape(pattern, flags)
    return re.compile(pattern, flags)
