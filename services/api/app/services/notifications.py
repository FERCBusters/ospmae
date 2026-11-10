"""Transactional e-mail outbox (KEEN's design, ported).

Senders queue a row inside their own transaction; the worker drains pending
rows with exponential backoff and records the outcome on the row, so a broken
SMTP configuration is visible rather than silently swallowed. A sent
message's body is cleared afterwards: verification links are one-time
secrets and never linger in the database.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Notification

log = logging.getLogger(__name__)

_MAX_ATTEMPTS = 8
# Bodies of delivered or permanently failed rows never outlive a month.
_RETENTION_DAYS = 30


def smtp_configured() -> bool:
    return bool((settings.smtp_host or "").strip()) and bool(
        (settings.smtp_from_email or "").strip()
    )


def _now() -> datetime:
    return datetime.utcnow()


def queue_email(
    db: Session,
    *,
    user_id: int | None,
    recipient: str,
    subject: str,
    body: str,
) -> Notification | None:
    """Queue an e-mail in the caller's transaction; the worker sends it."""
    if not smtp_configured():
        return None
    recipient = (recipient or "").strip()
    if not recipient:
        return None
    row = Notification(
        user_id=user_id,
        recipient=recipient,
        subject=(subject or "").strip()[:500],
        body=str(body or ""),
        status="pending",
        next_attempt_at=_now(),
    )
    db.add(row)
    return row


def deliver_pending(limit: int = 10) -> int:
    """Drain the outbox: one SMTP send per pending row, backoff on failure."""

    from app.db.session import SessionLocal
    from app.services.mailer import send_email

    if not smtp_configured():
        return 0
    sent = 0
    for _ in range(max(1, int(limit or 10))):
        with SessionLocal() as db:
            row = (
                db.query(Notification)
                .filter(
                    Notification.status == "pending",
                    Notification.next_attempt_at <= _now(),
                )
                .order_by(Notification.created_at)
                .with_for_update(skip_locked=True)
                .first()
            )
            if row is None:
                break
            row.attempts += 1
            try:
                send_email(to_email=row.recipient, subject=row.subject, body=row.body)
            except Exception as error:
                # Exception strings can carry SMTP credentials or addresses;
                # retain only the exception class name.
                row.last_error = type(error).__name__[:100]
                row.status = "failed" if row.attempts >= _MAX_ATTEMPTS else "pending"
                row.next_attempt_at = _now() + timedelta(
                    seconds=min(3600, 60 * 2 ** (row.attempts - 1))
                )
                log.warning(
                    "Notification %s delivery failed; attempt=%s status=%s",
                    row.id,
                    row.attempts,
                    row.status,
                )
            else:
                row.status = "sent"
                row.sent_at = _now()
                row.last_error = None
                row.body = ""
                sent += 1
            db.commit()
        if sent >= max(1, int(limit or 10)):
            break
    # Bound retention of spent rows regardless of outcome.
    with SessionLocal() as db:
        db.query(Notification).filter(
            Notification.status.in_(["sent", "failed"]),
            Notification.created_at < _now() - timedelta(days=_RETENTION_DAYS),
        ).delete(synchronize_session=False)
        db.commit()
    return sent


def notification_snapshot(
    db: Session, *, user_id: int, limit: int = 20
) -> list[dict[str, Any]]:
    """The user's own outbox history: what was mailed to them and when.

    Bodies are never returned; a queued row that has already been sent
    carries no body by design, and rows still pending keep their body only
    server-side.
    """
    rows = (
        db.query(Notification)
        .filter(Notification.user_id == user_id)
        .order_by(Notification.created_at.desc())
        .limit(max(1, int(limit or 20)))
        .all()
    )
    return [
        {
            "id": str(row.id),
            "subject": row.subject,
            "recipient": row.recipient,
            "status": row.status,
            "attempts": row.attempts,
            "last_error": row.last_error,
            "created_at": row.created_at,
            "sent_at": row.sent_at,
        }
        for row in rows
    ]
