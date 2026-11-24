"""Celery contract: every scheduled task must be registered with the worker.

A beat schedule entry whose task module is missing from ``include`` is
silently discarded by the worker ("Received unregistered task") and the
housekeeping it performs never runs. This test pins every scheduled task
name to the registry the worker builds after importing the include list.
"""

from __future__ import annotations

import pytest


def test_beat_schedule_tasks_are_registered() -> None:
    celery_app = pytest.importorskip("app.celery_app").celery_app
    # Importing the include modules is what a worker does at startup; go
    # through the configured list rather than importing by hand, so a new
    # task module that forgets to join the include list is caught here.
    for module in celery_app.conf.include:
        pytest.importorskip(module)

    registered = set(celery_app.tasks.keys())
    scheduled = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    missing = sorted(scheduled - registered)
    assert not missing, (
        "beat schedules tasks the worker would discard as unregistered; "
        f"missing from the app registry: {missing}"
    )


def test_requests_never_wait_long_on_the_broker():
    # Nothing reads task results, so a hand-off touches only the broker, and
    # for at most a few seconds; queued work waits for the beat dispatchers.
    from app.celery_app import celery_app

    assert celery_app.conf.task_ignore_result is True
    assert celery_app.conf.broker_connection_timeout <= 3


def test_no_task_runs_without_an_end():
    """Every task has a hard limit and, a minute before it, a soft one the
    task can answer; scans and feed tasks carry their own."""
    from app.celery_app import celery_app, task_limits
    from app.core.config import settings

    conf = celery_app.conf
    assert conf.task_time_limit == settings.task_time_limit_seconds == 900
    assert conf.task_soft_time_limit == 840
    celery_app.loader.import_default_modules()
    tasks = {
        name: task
        for name, task in celery_app.tasks.items()
        if name.startswith("app.tasks.")
    }
    assert len(tasks) >= 7
    longer = {
        "app.tasks.dependency_discovery.discover_project_version_dependencies": 1800,
        "app.tasks.release_feed.poll_release_feeds": 1800,
        "app.tasks.release_feed.discover_project_release_feed": 1800,
    }
    for name, task in tasks.items():
        hard = task.time_limit or conf.task_time_limit
        soft = task.soft_time_limit or conf.task_soft_time_limit
        assert hard == longer.get(name, 900), name
        assert soft == hard - 60, name
    assert task_limits(10) == {"soft_time_limit": 60, "time_limit": 120}


def test_a_scan_told_to_stop_records_that_as_its_error(db, monkeypatch):
    from app.db.models import ProjectVersion
    from app.tasks import dependency_discovery as dd
    from billiard.exceptions import SoftTimeLimitExceeded
    from mosp.core import task_deadline

    from tests.support import make_project, make_version, signed_in

    admin, _ = signed_in("admin")
    pid = make_project(admin, "alpha")["id"]
    vid = make_version(
        admin, pid, "1.0.0", link_to_source_code="https://github.com/example/repo"
    )["id"]

    def too_slow(*_args, **_kwargs):
        # As in the worker: the deadline has passed, so every further
        # statement raises the time limit again (mosp.core.task_deadline).
        task_deadline.start(0.5)
        assert task_deadline.passed()
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(dd, "clone_repo", too_slow)
    try:
        result = dd.discover_project_version_dependencies.run(vid)
    finally:
        task_deadline.finish()
    assert result["ok"] is False
    db.expire_all()
    version = db.get(ProjectVersion, vid)
    assert version.dependency_discovery_status == "error"
    assert version.dependency_discovery_error


def _broad_handlers_that_swallow_the_time_limit(source: str) -> list[int]:
    """Lines of `except Exception` (or BaseException) handlers that would
    carry on past the task's time limit: no earlier handler of the same try
    re-raises TIME_LIMITS, the handler does not re-raise, and it does not
    record the stop under task_deadline.grace()."""
    import ast

    def names(handler: ast.ExceptHandler) -> set[str]:
        kinds = handler.type
        items = kinds.elts if isinstance(kinds, ast.Tuple) else [kinds]
        return {
            item.id if isinstance(item, ast.Name) else getattr(item, "attr", "")
            for item in items
            if item is not None
        }

    def reraises(handler: ast.ExceptHandler) -> bool:
        return any(
            isinstance(node, ast.Raise) and node.exc is None for node in handler.body
        )

    def under_grace(handler: ast.ExceptHandler) -> bool:
        return "grace" in ast.unparse(handler)

    # What runs inside a task: a module-level try runs once, at import.
    tries = {
        node
        for function in ast.walk(ast.parse(source))
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for node in ast.walk(function)
        if isinstance(node, ast.Try)
    }
    found = []
    for node in sorted(tries, key=lambda item: item.lineno):
        guarded = False
        for handler in node.handlers:
            caught = names(handler)
            if "TIME_LIMITS" in caught:
                guarded = True
            elif caught & {"Exception", "BaseException"} and not (
                guarded or reraises(handler) or under_grace(handler)
            ):
                found.append(handler.lineno)
    return found


def test_no_task_carries_on_past_its_time_limit():
    """The worker's time limit ends a task's run. Every broad handler in the
    task and scan code lets it through (mosp.core.task_deadline), so a run
    stops where the limit falls instead of treating it as one input's failure
    and carrying on until the hard limit kills the process."""
    from pathlib import Path

    app = Path(__file__).resolve().parents[1] / "app"
    offenders = {
        str(path.relative_to(app)): lines
        for path in sorted([*app.glob("tasks/*.py"), *app.glob("depscan/*.py")])
        if (lines := _broad_handlers_that_swallow_the_time_limit(path.read_text()))
    }
    assert offenders == {}


def test_the_time_limit_check_finds_a_handler_that_swallows_it():
    import textwrap

    def task(handlers: str) -> str:
        body = "try:\n    work()\n" + textwrap.dedent(handlers)
        return "def task():\n" + textwrap.indent(body, "    ")

    swallowing = task("except Exception:\n    pass\n")
    assert _broad_handlers_that_swallow_the_time_limit(swallowing) == [4]
    # At module level it runs once, at import.
    assert (
        _broad_handlers_that_swallow_the_time_limit(
            textwrap.dedent(
                "try:\n    import yaml\nexcept Exception:\n    yaml = None\n"
            )
        )
        == []
    )
    for kept in (
        "except TIME_LIMITS:\n    raise\nexcept Exception:\n    pass\n",
        "except Exception:\n    tidy()\n    raise\n",
        "except Exception:\n    with task_deadline.grace():\n        record()\n",
    ):
        assert _broad_handlers_that_swallow_the_time_limit(task(kept)) == []
