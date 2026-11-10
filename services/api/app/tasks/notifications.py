"""Notification outbox dispatch.

The beat schedule drains pending rows regularly; request paths kick an
immediate best-effort dispatch so interactive mail (a verification link) is
not left to the next beat. Failure is tolerated: a beat will retry.
"""

from __future__ import annotations

from celery.utils.log import get_task_logger

from app.celery_app import celery_app
from app.services import notifications

log = get_task_logger(__name__)


@celery_app.task(name="app.tasks.notifications.deliver_notifications")
def deliver_notifications(limit: int = 10) -> dict:
    try:
        sent = notifications.deliver_pending(limit=limit)
    except Exception:
        log.exception("Notification dispatch failed")
        return {"sent": 0, "error": "dispatch failed"}
    return {"sent": sent}


def kick_delivery() -> None:
    """Best-effort immediate dispatch; the outbox tolerates silence."""
    if not notifications.smtp_configured():
        return
    try:
        deliver_notifications.delay()
    except Exception:
        log.exception("Immediate notification dispatch failed; beat will retry")
