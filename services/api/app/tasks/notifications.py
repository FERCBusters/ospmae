"""Notification outbox dispatch: OSPMAE's mail and mosp's security notices.

The beat schedule drains pending rows regularly; request paths kick an
immediate best-effort dispatch so interactive mail (a verification link) is
not left to the next beat. Failure is tolerated: a beat will retry.
"""

from __future__ import annotations

from celery.utils.log import get_task_logger
from mosp.core.task_deadline import TIME_LIMITS
from sqlalchemy.orm import Session

from app.celery_app import celery_app
from app.services import notifications

log = get_task_logger(__name__)


@celery_app.task(name="app.tasks.notifications.deliver_notifications")
def deliver_notifications(limit: int = 10) -> dict:
    """Drain OSPMAE's outbox and mosp's security notices."""
    from mosp.services import security_notifications

    sent = 0
    for outbox in (notifications, security_notifications):
        try:
            sent += outbox.deliver_pending(limit=limit)
        except TIME_LIMITS:
            # The task's time limit ends the run; it is no outbox's failure.
            raise
        except Exception:
            log.exception("Notification dispatch failed")
    return {"sent": sent}


def kick_delivery() -> None:
    """Best-effort immediate dispatch; the outbox tolerates silence."""
    if not notifications.smtp_configured():
        return
    try:
        # One attempt, so a request never waits on broker reconnection; the
        # beat schedule delivers the outbox anyway.
        deliver_notifications.apply_async(retry=False)
    except TIME_LIMITS:
        raise
    except Exception:
        log.exception("Immediate notification dispatch failed; beat will retry")


def commit_and_kick(db: Session) -> None:
    """Commit mail queued after the change it reports, then kick delivery.

    A request's session discards whatever it has not committed when it
    closes, so a sender that queues mail after the request's last commit
    must commit again or the mail is silently lost.
    """
    db.commit()
    kick_delivery()
