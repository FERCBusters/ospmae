"""OSPMAE's mail outbox and maintenance sweep (no network).

The transport, redaction and notification hub are mosp's, and mosp's suite
covers them.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from app.db.models import AuditLog, Notification
from app.db.session import SessionLocal
from app.services import notifications
from app.tasks.maintenance import sweep_expired_rows
from mosp.core.datetime_utils import utc_now_naive

from tests.conftest import auth_client
from tests.conftest import db as db_fixture  # noqa: F401


def _mail_configured(monkeypatch):
    monkeypatch.setattr(notifications, "smtp_configured", lambda: True)


def test_each_project_notice_is_queued_on_one_line(monkeypatch, db):
    """OSPMAE's notices are queued in the caller's transaction; sending them
    is the worker's job (deliver_pending). A name that carries a line break
    never splits the subject."""
    from app.services import mailer

    monkeypatch.setattr(mailer, "smtp_configured", lambda: True)
    _mail_configured(monkeypatch)
    name = "proj\r\nBcc: x@evil"
    with SessionLocal() as s:
        mailer.send_project_version_published_email(
            db=s,
            to_email="u4@example.com",
            project_name=name,
            version="1.0",
            project_url="https://ospmae.example/p",
        )
        mailer.send_project_version_draft_email(
            db=s, to_email="u5@example.com", project_name=name, version="2.0"
        )
        mailer.send_manifest_shared_email(
            db=s, to_email="u6@example.com", manifest_name=name, shared_by_username="o"
        )
        mailer.send_project_question_created_email(
            db=s, to_email="u7@example.com", project_name=name, question_body="q?"
        )
        mailer.send_project_question_replied_email(
            db=s, to_email="u8@example.com", project_name=name, reply_body="r"
        )
        s.commit()
        rows = s.query(Notification).order_by(Notification.recipient).all()
    assert [row.recipient for row in rows] == [f"u{n}@example.com" for n in range(4, 9)]
    assert rows[0].subject == "OSPMAE: New release for proj Bcc: x@evil (1.0)"
    assert "View project: https://ospmae.example/p" in rows[0].body
    assert all("\n" not in row.subject and "\r" not in row.subject for row in rows)
    assert all(row.status == "pending" for row in rows)


def test_a_preview_is_bounded():
    from app.services.mailer import _preview_text

    assert _preview_text(None) == ""
    assert _preview_text("  a \n b  ") == "a b"
    preview = _preview_text("x" * 500)
    assert len(preview) == 240 and preview.endswith("…")


def test_nothing_is_queued_without_mail_settings(monkeypatch, db):
    monkeypatch.setattr(notifications, "smtp_configured", lambda: False)
    with SessionLocal() as s:
        assert (
            notifications.queue_email(
                s, user_id=None, recipient="to@example.com", subject="s", body="b"
            )
            is None
        )
        s.commit()
        assert s.query(Notification).count() == 0
    assert notifications.deliver_pending(limit=2) == 0


def test_outbox_delivers_pending_rows_and_records_failure(monkeypatch, db):
    _mail_configured(monkeypatch)
    with SessionLocal() as s:
        row = notifications.queue_email(
            s, user_id=None, recipient="to@example.com", subject="s", body="b"
        )
        s.commit()
        assert row is not None and row.status == "pending"
        row_id = row.id

    deliveries = []

    def fake_send_email(*, to_email, subject, body):
        deliveries.append(to_email)

    monkeypatch.setattr(notifications, "send_email", fake_send_email)
    assert notifications.deliver_pending(limit=2) == 1
    assert deliveries == ["to@example.com"]
    with SessionLocal() as s:
        spent = s.get(Notification, row_id)
        assert spent.status == "sent"
        assert spent.body == ""
        assert spent.sent_at is not None

    # A failing transport keeps the row pending with a backoff stamp (only the
    # exception class is recorded).
    with SessionLocal() as s:
        failure = notifications.queue_email(
            s, user_id=None, recipient="fail@example.com", subject="f", body="b"
        )
        s.commit()
        failure_id = failure.id

    def broken_send(*, to_email, subject, body):
        raise OSError("no network here")

    monkeypatch.setattr(notifications, "send_email", broken_send)
    assert notifications.deliver_pending(limit=2) == 0
    with SessionLocal() as s:
        failed_row = s.get(Notification, failure_id)
        assert failed_row.status == "pending"
        assert failed_row.attempts == 1
        assert failed_row.last_error == "OSError"
        assert failed_row.next_attempt_at > utc_now_naive()


def test_sweep_removes_expired_rows(client):
    auth_client(role="contributor")
    now = utc_now_naive()
    with SessionLocal() as s:
        s.add(
            AuditLog(
                ts=now - timedelta(days=400),
                method="GET",
                path="/v1/x",
                status_code=200,
                duration_ms=1,
            )
        )
        s.commit()
    result = sweep_expired_rows.run()
    assert result["audit_logs"] == 1
    with SessionLocal() as s:
        # The sign-in that made the contributor's session is recent and stays.
        assert all(row.ts > now - timedelta(days=1) for row in s.query(AuditLog))


@pytest.mark.parametrize(
    ("feature", "task", "args", "answer"),
    [
        (
            "dependency_scans",
            "app.tasks.dependency_queue:dispatch_queued_dependency_discoveries",
            (),
            {"ok": False, "reason": "dependency_scans feature disabled"},
        ),
        (
            "dependency_scans",
            "app.tasks.dependency_discovery:discover_project_version_dependencies",
            (1,),
            {"skipped": True, "reason": "dependency_scans feature disabled"},
        ),
    ],
)
def test_a_switched_off_feature_runs_no_work(monkeypatch, feature, task, args, answer):
    import importlib

    from app.core.config import settings

    module, name = task.split(":")
    monkeypatch.setattr(settings, f"feature_{feature}", False)
    assert getattr(importlib.import_module(module), name)(*args) == answer


def test_release_feeds_poll_nothing_while_switched_off(monkeypatch):
    import app.tasks.release_feed as rf
    from app.core.config import settings

    monkeypatch.setattr(settings, "feature_release_feed", False)
    assert rf.poll_release_feeds()["enabled"] is False
