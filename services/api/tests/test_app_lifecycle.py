"""Start-up, shut-down and the notification worker's hand-offs."""

from __future__ import annotations

import asyncio

import pytest
from app import main
from app.tasks import notifications as tasks


@pytest.mark.parametrize("failure", [None, "start", "stop"])
def test_the_listener_never_stops_the_application_starting_or_stopping(
    monkeypatch, failure
):
    seen = []

    async def start():
        seen.append("start")
        if failure == "start":
            raise ConnectionError("valkey unavailable")

    async def stop():
        seen.append("stop")
        if failure == "stop":
            raise ConnectionError("valkey unavailable")

    monkeypatch.setattr(main, "start_notification_listener", start)
    monkeypatch.setattr(main, "stop_notification_listener", stop)
    monkeypatch.setattr(main, "_bootstrap", lambda: seen.append("bootstrap"))

    async def run():
        async with main.app.router.lifespan_context(main.app):
            seen.append("serving")

    asyncio.run(run())
    assert seen == ["start", "bootstrap", "serving", "stop"]


def test_the_root_names_the_service(client):
    assert client.get("/").json() == {"ok": True, "service": "ospmae-api"}


def test_both_outboxes_drain_and_one_failing_leaves_the_other(monkeypatch):
    from mosp.services import security_notifications

    monkeypatch.setattr(tasks.notifications, "deliver_pending", lambda limit: 2)

    def broken(limit):
        raise OSError("smtp down")

    monkeypatch.setattr(security_notifications, "deliver_pending", broken)
    assert tasks.deliver_notifications.run(limit=5) == {"sent": 2}
    monkeypatch.setattr(security_notifications, "deliver_pending", lambda limit: 3)
    assert tasks.deliver_notifications.run(limit=5) == {"sent": 5}


def test_a_kick_needs_mail_and_tolerates_a_missing_broker(monkeypatch):
    kicks = []
    monkeypatch.setattr(
        tasks.deliver_notifications, "apply_async", lambda **kw: kicks.append(kw)
    )
    monkeypatch.setattr(tasks.notifications, "smtp_configured", lambda: False)
    tasks.kick_delivery()
    assert kicks == []

    monkeypatch.setattr(tasks.notifications, "smtp_configured", lambda: True)
    tasks.kick_delivery()
    assert kicks == [{"retry": False}]

    def unreachable(**_):
        raise ConnectionError("broker down")

    monkeypatch.setattr(tasks.deliver_notifications, "apply_async", unreachable)
    tasks.kick_delivery()


def test_mail_queued_after_a_change_is_committed_before_the_kick(monkeypatch):
    order = []

    class Session:
        def commit(self):
            order.append("commit")

    monkeypatch.setattr(tasks, "kick_delivery", lambda: order.append("kick"))
    tasks.commit_and_kick(Session())
    assert order == ["commit", "kick"]
