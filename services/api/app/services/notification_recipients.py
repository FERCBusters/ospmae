"""Where an account's e-mail goes, as KEEN sends it.

An account is mailed at its e-mail, which an administrator sets, and only
when that is exactly one mailbox. Addresses an account proves for single
sign-on linking (user_sso_emails) are never mailed.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.email_address import single_mailbox
from app.db.models import User


def notification_email_for_user(db: Session, *, user: User) -> str | None:
    """The account's e-mail when it is one mailbox, else None."""
    return single_mailbox(user.email)


def notification_emails_for_users(db: Session, *, users: list[User]) -> list[str]:
    """The distinct e-mail addresses of these accounts, sorted."""
    emails = {
        email
        for user in users
        if (email := notification_email_for_user(db, user=user)) is not None
    }
    return sorted(emails)
