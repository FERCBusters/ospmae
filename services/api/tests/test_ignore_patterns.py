"""Release-feed ignore patterns: the shape check that keeps supplied
regular expressions from backtracking without bound, the count and window
limits, and the time allowance each search runs under."""

from __future__ import annotations

import re

import pytest
from app.api.payloads import ReleaseFeedIgnorePatternPayload
from app.db.models import Project
from app.security.regex_shape import check_pattern_shape
from app.tasks.release_feed import _release_feed_entry_is_ignored
from pydantic import ValidationError


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"(a|a)*$",
        r"(.*a){20}",
        r"(\w+)\1",
        r"(?x)a b",
        r"(ab){2000}",
        "a" * 257,
        r"([a-z",
        # Bounded repeats nest exponentially too: each round of the outer
        # one can take the text in more than one way.
        r"(?:a{1,2}){1,512}!",
        r"(?:a{0,32}){0,32}!",
        r"(?:a|aa){1,512}!",
        r"(?:a?b?){1,40}c",
        r"(?:x\d*\d*){2,9}",
        r"(?:(?:a{1,3}|b)){1,300}!",
        r"(?:a*){2}!",
        r"(?:\d+\.?){1,9}x",
        # Repeats in a row over the same text multiply by its length each.
        r"a*a*a*!",
        r"a*a*a*a*a*a*!",
        r"a*aa*aa*a!",
        r".*.*.*=",
        r"\w*\d*[a-z]*x",
        r"(?:ab)*+a*(?:ab)?a*a*!",
        # The same shapes over characters far from ASCII: what two repeats
        # share is judged on the characters the pattern itself names.
        "(?:[^\\x00-\\u017f]{1,32}){1,32}$",
        "(?:\u044f{1,32}){1,32}$",
        "(?:[\u4e00-\u4e10]{1,9}){1,9}!",
        "[\u4e00-\u4e10]*[\u4e08-\u4e20]*\u4e09*!",
        "(?i)(?:\u03a9{1,9}[\u03c0-\u03cf]{1,9}){1,9}!",
        "(?:\\d{1,9}\u0663{1,9}){1,9}!",
        # A lookaround's repeats run over the same text as those around it.
        r"a*(?=a*a*x)a*$",
        r"a*(?=a*x)a*a*$",
        r"(?!a*b)a*(?<=a*)a*!",
    ],
)
def test_patterns_that_can_backtrack_without_bound_are_refused(pattern):
    with pytest.raises(ValueError):
        check_pattern_shape(pattern)
    with pytest.raises(ValidationError):
        ReleaseFeedIgnorePatternPayload.model_validate(
            {"match_type": "regex", "pattern": pattern}
        )


@pytest.mark.parametrize(
    "pattern",
    [
        r"^v?\d+\.\d+\.\d+-rc\d*$",
        r"(?:\.\d+)*+$",
        r"nightly|beta|alpha",
        r"(ab){10}",
        r"[^/]+/[^/]+",
        # Repeats kept apart by text neither can match, or two at most.
        r"^v?\d+\.\d+\.\d+-(?:rc|beta|alpha)\.?\d*$",
        r"\d+\.\d+(?:\.\d+)?(?:-\w+)?$",
        r"[a-z]+-[a-z]+-[a-z]+",
        r"a*b*c*",
        r"a*a*",
        r".*rc.*",
        r"\s*v\d+",
        # A fixed count inside a repeat, and rounds that cannot run together.
        r"(?:x{2}){1,5}",
        r"(?:\d{1,3}\.){2}\d+",
        r"(?:rc|beta){1,3}",
        # Possessive repeats commit, so they share nothing.
        r"a*+a*+a*+!",
        r"(?:a{1,2})++!",
        # Other scripts, kept apart as any repeats are.
        "\u044f+-\u044f+-\u044f+",
        "[\u0430-\u044f]+\\d+",
        "(?:[\u4e00-\u4e10]{1,9}-){1,9}!",
        # The usual way to say "not a pre-release".
        r"^(?!.*beta).*$",
        r"^v\d+(?=\.)",
    ],
)
def test_bounded_patterns_are_accepted(pattern):
    check_pattern_shape(pattern)
    payload = ReleaseFeedIgnorePatternPayload.model_validate(
        {"match_type": "regex", "pattern": pattern}
    )
    assert payload.pattern == pattern


def test_a_project_keeps_a_bounded_number_of_ignore_patterns():
    from app.api.payloads import ProjectUpdatePayload
    from app.security.regex_shape import MAX_IGNORE_PATTERNS
    from app.tasks import release_feed as rf

    rules = [{"match_type": "contains", "pattern": f"rc{n}"} for n in range(51)]
    kept = ProjectUpdatePayload.model_validate(
        {"release_rss_ignore_patterns": rules[:MAX_IGNORE_PATTERNS]}
    )
    assert len(kept.release_rss_ignore_patterns) == 50
    for too_many in (rules, "\n".join(f"rc{n}" for n in range(51))):
        with pytest.raises(ValidationError, match="at most 50 ignore patterns"):
            ProjectUpdatePayload.model_validate(
                {"release_rss_ignore_patterns": too_many}
            )
    # A longer list saved before the limit is read up to it.
    stored = Project(id=3, release_rss_ignore_patterns=[f"rc{n}" for n in range(80)])
    assert len(rf._normalised_release_ignore_patterns(stored)) == 50
    assert rf._release_feed_entry_is_ignored(stored, {"title": "v1-rc49"}, "v1") is True
    assert (
        rf._release_feed_entry_is_ignored(stored, {"title": "v1-rc50x"}, "v1") is True
    )
    assert rf._release_feed_entry_is_ignored(stored, {"title": "v1-rc7"}, "v1") is True
    assert rf._release_feed_entry_is_ignored(stored, {"title": "v1-rd"}, "v1") is False


def test_slow_rules_cost_a_project_a_fixed_budget_not_one_deadline_each(monkeypatch):
    """Rules that reach the deadline are counted: each is tried once in a
    run, and together they spend a budget after which no rule is tried."""
    import re

    from app.security import regex_shape
    from app.tasks import release_feed as rf

    searched: list[str] = []

    def timed_out(compiled, text, seconds=regex_shape.SEARCH_SECONDS):
        searched.append(compiled.pattern)
        return (
            None if compiled.pattern.startswith("slow") else bool(compiled.search(text))
        )

    monkeypatch.setattr(rf, "search_within", timed_out)
    monkeypatch.setattr(rf, "compile_supplied_pattern", lambda p, f: re.compile(p, f))
    monkeypatch.setattr(rf.log, "warning", lambda *a: None)
    rules = [{"match_type": "regex", "pattern": f"slow{n}"} for n in range(30)]
    rules.append({"match_type": "regex", "pattern": "nightly"})
    project = Project(id=9, release_rss_ignore_patterns=rules)
    budget = rf.MatchBudget(seconds=5 * regex_shape.SEARCH_SECONDS)

    entry = {"title": "v1.0.0-nightly", "link": "", "id": ""}
    # Five deadlines spend the budget; the rules after them, the good one
    # included, are not consulted, and the entry is taken.
    assert rf._release_feed_entry_is_ignored(project, entry, "v1.0.0", budget) is False
    assert searched == [f"slow{n}" for n in range(5)]
    assert budget.spent
    # Nothing more is searched for this project in this run.
    assert rf._release_feed_entry_is_ignored(project, entry, "v1.0.1", budget) is False
    assert len(searched) == 5

    # With room in the budget a slow rule is tried once, and the others
    # still decide.
    searched.clear()
    roomy = rf.MatchBudget()
    few = Project(id=9, release_rss_ignore_patterns=rules[:2] + rules[-1:])
    assert rf._release_feed_entry_is_ignored(few, entry, "v1.0.0", roomy) is True
    assert rf._release_feed_entry_is_ignored(few, entry, "v1.0.1", roomy) is True
    # Each slow rule once; the good rule against the label and then the
    # title of both entries.
    assert searched == ["slow0", "slow1"] + ["nightly"] * 4
    assert not roomy.spent


def test_a_deadline_that_fires_as_the_search_returns_is_still_a_stop():
    import re
    import signal

    from app.security import regex_shape

    class Slow:
        pattern = "x"

        def search(self, text):
            # The timer goes off after the search has its answer.
            signal.raise_signal(signal.SIGALRM)
            return re.match("x", "x")

    before = signal.getsignal(signal.SIGALRM)
    assert regex_shape.search_within(Slow(), "x") is None
    # The handler and the timer are as they were.
    assert signal.getsignal(signal.SIGALRM) is before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_a_stored_pattern_that_fails_the_checks_is_skipped_never_run():
    project = Project(id=1)
    project.release_rss_ignore_patterns = [
        {"match_type": "regex", "pattern": r"(a+)+$"},
        {"match_type": "regex", "pattern": r"-rc\d+$"},
    ]
    hostile = {"title": "a" * 40 + "!"}
    assert _release_feed_entry_is_ignored(project, hostile, "1.0.0") is False
    assert _release_feed_entry_is_ignored(project, {}, "1.0.0-rc1") is True


def test_ignore_patterns_read_a_bounded_window_of_feed_text():
    project = Project(id=1)
    project.release_rss_ignore_patterns = [{"match_type": "regex", "pattern": "tail$"}]
    entry = {"title": "x" * 2000 + "tail"}
    assert _release_feed_entry_is_ignored(project, entry, "") is False
    assert re.search("tail$", entry["title"])


def test_every_accepted_pattern_searches_a_full_window_quickly():
    """The claim the shape check makes, measured: the patterns it accepts
    search the longest text a feed can offer, built to suit each of them, in
    far less than one search's allowance."""
    import re
    import time

    from app.security.regex_shape import SEARCH_SECONDS, compile_supplied_pattern

    accepted = [
        r"^v?\d+\.\d+\.\d+-(?:rc|beta|alpha)\.?\d*$",
        r"\d+\.\d+(?:\.\d+)?(?:-\w+)?$",
        r"[a-z]+-[a-z]+-[a-z]+",
        r"a*b*c*",
        r"a*a*",
        r".*rc.*",
        r"(?:x{2}){1,5}",
        r"(?:\d{1,3}\.){2}\d+",
        r"(?:\.\d+)*+$",
        r"[^/]+/[^/]+",
    ]
    texts = [
        unit * (1024 // len(unit))
        for unit in ("a", "1", "a1", "1.", "-a", "x", "r", "/a")
    ]
    for pattern in accepted:
        compiled = compile_supplied_pattern(pattern, re.IGNORECASE)
        started = time.perf_counter()
        for text in texts:
            compiled.search(text)
            compiled.search(text + "!")
        assert time.perf_counter() - started < SEARCH_SECONDS, pattern


def test_a_search_stops_at_its_allowance_and_leaves_no_timer_behind():
    import re
    import signal
    import threading
    import time

    from app.security.regex_shape import search_within

    slow = re.compile("(?:a|aa){1,512}!")
    handler_before = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()
    assert search_within(slow, "a" * 200, seconds=0.1) is None
    assert time.monotonic() - started < 2
    # The previous handler is back and no timer is pending.
    assert signal.getsignal(signal.SIGALRM) is handler_before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    assert search_within(slow, "aaa!") is True
    assert search_within(slow, "bbb") is False

    # Off the main thread there is no timer to set: the search just runs.
    found: list[bool | None] = []
    worker = threading.Thread(
        target=lambda: found.append(search_within(re.compile("b+"), "abba"))
    )
    worker.start()
    worker.join()
    assert found == [True]
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
