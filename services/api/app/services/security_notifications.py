"""Security notices about an account's sign-ins.

Ported from KEEN: every completed sign-in records its client address against
the account, and the first sign-in from an address not seen before queues a
notice to the account's notification address through the e-mail outbox.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import User, UserLoginIP
from app.services.mailer import queue_email, smtp_configured
from app.services.notification_recipients import notification_email_for_user

UNFAMILIAR_ADDRESS = "Sign-in from an unfamiliar IP address"


def record_login(db: Session, user: User, *, ip: str | None) -> bool:
    """Record a completed sign-in's address in the caller's transaction.

    Returns True when a notice was queued: the address is new for the account
    and mail can be sent. The account/address key is unique, so parallel
    sign-ins from one new address queue a single notice.
    """

    address = (ip or "").strip()
    if not address:
        return False
    created = db.execute(
        insert(UserLoginIP)
        .values(user_id=user.id, address=address, first_seen_at=datetime.utcnow())
        .on_conflict_do_nothing()
        .returning(UserLoginIP.address)
    ).scalar_one_or_none()
    if created is None or not smtp_configured():
        return False
    recipient = notification_email_for_user(db, user=user)
    if not recipient:
        return False
    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
    installation = (settings.public_base_url or "").strip().rstrip("/")
    lines = [
        f"{UNFAMILIAR_ADDRESS}.",
        "",
        f"Account: {user.username}",
    ]
    if installation:
        lines.append(f"OSPMAE installation: {installation}")
    lines += [
        f"Time (UTC): {datetime.utcnow().isoformat(timespec='seconds')}Z",
        f"IP address: {address}",
        "",
        "This address has not previously been recorded for a successful "
        "sign-in to this account. A VPN, mobile connection or changing ISP "
        "address can cause this alert.",
        "",
        "If this was you, no action is needed. If you do not recognise this "
        "activity, open your known OSPMAE address directly and contact your "
        "OSPMAE administrator. Review your password and authenticators.",
    ]
    queue_email(
        db,
        user_id=user.id,
        recipient=recipient,
        subject=f"{from_name} security: {UNFAMILIAR_ADDRESS}",
        body="\n".join(lines) + "\n",
    )
    return True
