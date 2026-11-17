"""Shape checks for regular expressions that people supply.

Ported from KEEN's ``check_scan_pattern`` (app/security/regex.py); keep the
two aligned. Python's engine backtracks, so a pattern such as ``(a+)+$`` or
``(a|a)*$`` takes time exponential in the text it searches. Release-feed
ignore patterns are written by project editors and searched against text from
upstream feeds, so a pattern is refused when it is saved, and again before it
runs, unless its matching state and backtracking stay bounded. The shape
check reasons about a pattern; ``search_within`` bounds the search itself, so
a shape the check does not recognise still cannot hold a worker.
"""

from __future__ import annotations

import re
import signal
import threading
from functools import lru_cache
from re import (  # type: ignore[attr-defined]  # CPython's parser has no stub
    _compiler,
    _parser,
)

# A greedy or lazy repeat of anything wider than one character keeps
# backtracking state for every repetition. A possessive repeat keeps none, and
# a bounded one keeps at most its bound, multiplied by the bounds of the
# repeats around it.
REPEATS_HELD = 1024
# The longest pattern accepted.
MAX_PATTERN_CHARS = 256
# The most ignore rules one project keeps: each is tried against every entry.
MAX_IGNORE_PATTERNS = 50
_ONE_CHARACTER = {_parser.ANY, _parser.IN, _parser.LITERAL, _parser.NOT_LITERAL}
_REPEATS = (_parser.MAX_REPEAT, _parser.MIN_REPEAT, _parser.POSSESSIVE_REPEAT)
_HELD_REPEAT = (
    "repeat a group or alternatives possessively (*+, ++ or {m,n}+), "
    f"or at most {REPEATS_HELD} times in all: matching keeps state for every "
    "repetition"
)
_NESTED_REPEAT = (
    "make a repeat inside another repeat possessive, or give it one fixed "
    "count, and give alternatives in a repeated group different first "
    "characters: nested repeats backtrack exponentially"
)
_ADJACENT_REPEATS = (
    "separate repeats that can match the same text with text neither can "
    "match, or make them possessive: each one multiplies the time by the "
    "length of the text"
)


def _one_character(items) -> bool:
    if len(items) != 1:
        return False
    op, value = items[0]
    if op == _parser.SUBPATTERN:
        return value[0] is None and _one_character(value[-1])
    return op in _ONE_CHARACTER


# Characters a one-character item is tried against to decide whether two items
# can match the same text: ASCII, Latin-1 and Latin Extended-A, then one
# character from each way the classes \d, \s and \w and their opposites meet
# beyond those (a digit, a space, a letter, and one that is none of them).
# check_pattern_shape adds every character and range end the pattern itself
# names, so two items that meet only beyond the sample are still seen to.
_SAMPLE = [chr(code) for code in range(0x180)] + [
    "\u0663",
    "\u2003",
    "\u4e2d",
    "\U0001f600",
]


def _named_characters(items) -> set[str]:
    """Every character a pattern names outside the sample: literals, and the
    ends of class ranges, each with its other-case forms."""
    found: set[str] = set()

    def note(code: int) -> None:
        ch = chr(code)
        found.update((ch, ch.lower(), ch.upper()))

    def walk(seq) -> None:
        for op, value in seq:
            if op in (_parser.LITERAL, _parser.NOT_LITERAL):
                note(value)
            elif op == _parser.RANGE:
                note(value[0])
                note(value[1])
            elif op == _parser.IN:
                walk(value)
            elif op in _REPEATS:
                walk(value[2])
            elif op == _parser.SUBPATTERN:
                walk(value[-1])
            elif op == _parser.ATOMIC_GROUP:
                walk(value)
            elif op == _parser.BRANCH:
                for branch in value[1]:
                    walk(branch)
            elif op in (_parser.ASSERT, _parser.ASSERT_NOT):
                walk(value[1])
            elif op == _parser.GROUPREF_EXISTS:
                walk(value[1])
                if value[2] is not None:
                    walk(value[2])

    walk(items)
    return {ch for ch in found if len(ch) == 1}


# Adjacent repeats that can match the same text split it between them in as
# many ways as its length allows, once per repeat: two is quadratic in the
# text, and each further one multiplies that by the text's length again.
ADJACENT_REPEATS = 2


def _characters(state, items) -> frozenset[str] | None:
    """The sample characters a one-character item matches, else None."""
    if not _one_character(items):
        return None
    one = _compiler.compile(_parser.SubPattern(state, list(items)))
    sample = getattr(state, "ospmae_sample", _SAMPLE)
    return frozenset(ch for ch in sample if one.fullmatch(ch))


def _first_characters(state, item) -> frozenset[str] | None:
    """The sample characters an item that consumes text can start with, where
    that is plain to see; None where it is not."""
    op, value = item
    if op in _ONE_CHARACTER:
        return _characters(state, [item])
    if op in _REPEATS and value[0] >= 1:
        return _characters(state, value[2])
    if op == _parser.SUBPATTERN and value[-1]:
        return _first_characters(state, value[-1][0])
    if op == _parser.BRANCH:
        found: set[str] = set()
        for branch in value[1]:
            first = _first_characters(state, branch[0]) if branch else None
            if first is None:
                return None
            found |= first
        return frozenset(found)
    return None


def _all_characters(state, items) -> frozenset[str] | None:
    """Every sample character a sequence of one-character items, and repeats
    of them, can match; None for anything else."""
    found: set[str] = set()
    for op, value in items:
        if op == _parser.SUBPATTERN:
            inner = _all_characters(state, value[-1])
        elif op in _REPEATS:
            inner = _all_characters(state, value[2])
        else:
            inner = _characters(state, [(op, value)])
        if inner is None:
            return None
        found |= inner
    return frozenset(found)


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
    state = parsed.state
    # The characters items are compared on: the fixed sample and whatever
    # this pattern names beyond it.
    setattr(  # noqa: B010 - the parser's state carries the sample to helpers
        state,
        "ospmae_sample",
        _SAMPLE + sorted(_named_characters(parsed) - set(_SAMPLE)),
    )

    def consumes(item) -> bool:
        return _parser.SubPattern(state, [item]).getwidth()[0] > 0

    def flat(items) -> list:
        """The sequence with its plain groups opened out in place."""
        out: list = []
        for item in items:
            if item[0] == _parser.SUBPATTERN:
                out.extend(flat(item[1][-1]))
            else:
                out.append(item)
        return out

    def varying(item) -> bool:
        return item[0] in _REPEATS[:2] and item[1][0] != item[1][1]

    def in_sequence(items, looking: bool = False) -> list:
        """The sequence as the matcher walks it: plain groups opened out, and
        each lookaround's body in place, marked. A lookaround's repeats run
        over the same text as the repeats around it; what else it holds
        moves the match nowhere."""
        out: list = []
        for item in items:
            if item[0] == _parser.SUBPATTERN:
                out.extend(in_sequence(item[1][-1], looking))
            elif item[0] in (_parser.ASSERT, _parser.ASSERT_NOT):
                out.extend(in_sequence(item[1][1], True))
            else:
                out.append((item, looking))
        return out

    def shared(items, limit: int, message: str) -> None:
        """Refuse `limit` or more repeats in a row that can match the same
        text with nothing between them that none of them can match."""
        # For each varying repeat met: the characters it can match, or None
        # where that is not plain to see.
        run: list[frozenset[str] | None] = []
        for item, looking in in_sequence(items):
            if varying(item):
                body = item[1][2]
                # A repeat shares text with an earlier one when what it can
                # start with is something the earlier one can match.
                first = (
                    _characters(state, body)
                    if _one_character(body)
                    else (_first_characters(state, body[0]) if body else None)
                )
                if (
                    any(
                        first is None or other is None or first & other for other in run
                    )
                    and len(run) + 1 >= limit
                ):
                    raise ValueError(message)
                run.append(_all_characters(state, body))
            elif run and not looking and consumes(item):
                # Text that must be here, and that no repeat before it can
                # match, ends what those repeats share with later ones.
                first = _first_characters(state, item)
                if first is not None and all(
                    other is not None and not (first & other) for other in run
                ):
                    run = []

    def overlapping_alternatives(body) -> None:
        """Alternatives in a repeated group that can start with the same
        text let each round be matched more than one way: (?:a|aa){1,512}."""
        for op, value in flat(body):
            if op != _parser.BRANCH:
                continue
            seen: set[str] = set()
            for branch in value[1]:
                first = _first_characters(state, branch[0]) if branch else None
                if first is None or first & seen:
                    raise ValueError(_NESTED_REPEAT)
                seen |= first

    def check(items, held, repeated):
        shared(items, ADJACENT_REPEATS + 1, _ADJACENT_REPEATS)
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
                    if high > 1:
                        # One repetition followed by the next: a repeat that
                        # can share text with its own next round, or with
                        # another in the body, splits the text between rounds
                        # in exponentially many ways, bounded or not.
                        shared(list(body) * 2, 2, _NESTED_REPEAT)
                        overlapping_alternatives(body)
                check(body, inner, repeated or high > 1)
            elif op == _parser.SUBPATTERN:
                check(value[-1], held, repeated)
            elif op == _parser.ATOMIC_GROUP:
                check(value, held, repeated)
            elif op == _parser.BRANCH:
                for branch in value[1]:
                    # Alternatives inside a repeat are tried round by round;
                    # a varying repeat in one is a nested repeat.
                    if repeated and any(varying(item) for item in flat(branch)):
                        raise ValueError(_NESTED_REPEAT)
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


class _SearchDeadline(Exception):
    """The search ran past its allowance."""


def _past_deadline(_signum, _frame) -> None:
    raise _SearchDeadline


# How long one search of one text may run. Most patterns that pass the shape
# check search a 1024-character window in well under a millisecond; the two
# adjacent repeats the check allows (".*rc.*") can take the square of the
# text's length on text built for it, and end here.
SEARCH_SECONDS = 0.25


def search_within(
    compiled: re.Pattern[str], text: str, seconds: float = SEARCH_SECONDS
) -> bool | None:
    """Whether the pattern matches the text; None when the search was stopped
    at its deadline.

    The deadline is an interval timer, which the matcher notices between
    steps. Timers belong to a process's main thread, where a worker runs its
    tasks; anywhere else the search runs unbounded, as it did before.
    """
    if threading.current_thread() is not threading.main_thread():
        return compiled.search(text) is not None
    previous = signal.signal(signal.SIGALRM, _past_deadline)
    try:
        try:
            signal.setitimer(signal.ITIMER_REAL, seconds)
            found = compiled.search(text) is not None
            # Disarmed while the deadline can still be caught here: a timer
            # that fires as the search returns ends in the same place.
            signal.setitimer(signal.ITIMER_REAL, 0)
            return found
        except _SearchDeadline:
            return None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
