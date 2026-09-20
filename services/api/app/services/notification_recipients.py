from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import User, UserEmail, UserIdentity


def notification_email_for_user(db: Session, *, user: User) -> str | None:
    """Return the canonical email address for user-facing notifications.

    ``user_emails`` is the source of truth for accounts that have been migrated
    to multi-provider SSO. In particular, an explicitly selected primary email
    must win over the legacy ``users.email`` and ``user_identities.email``
    columns, which can contain older addresses retained only for account linking.

    The legacy fallbacks are intentionally kept for pre-migration/incomplete
    accounts that do not yet have a primary ``UserEmail`` row.
    """

    primary = (
        db.query(UserEmail)
        .filter(UserEmail.user_id == user.id)
        .filter(UserEmail.is_primary.is_(True))
        .order_by(
            UserEmail.is_verified.desc(),
            UserEmail.updated_at.desc(),
            UserEmail.id.desc(),
        )
        .first()
    )
    if primary and str(primary.email or "").strip():
        return str(primary.email).strip()

    legacy_user_email = str(getattr(user, "email", "") or "").strip()
    if legacy_user_email:
        return legacy_user_email

    account_email = (
        db.query(UserEmail)
        .filter(UserEmail.user_id == user.id)
        .order_by(
            UserEmail.is_verified.desc(),
            UserEmail.updated_at.desc(),
            UserEmail.id.desc(),
        )
        .first()
    )
    if account_email and str(account_email.email or "").strip():
        return str(account_email.email).strip()

    identity = (
        db.query(UserIdentity.email)
        .filter(UserIdentity.user_id == user.id)
        .filter(UserIdentity.email.isnot(None))
        .order_by(UserIdentity.updated_at.desc(), UserIdentity.id.desc())
        .first()
    )
    if identity and identity[0] and str(identity[0]).strip():
        return str(identity[0]).strip()

    return None


def notification_emails_for_users(db: Session, *, users: list[User]) -> list[str]:
    """Resolve and de-duplicate canonical notification addresses for users."""

    emails = {
        email
        for user in users
        if (email := notification_email_for_user(db, user=user)) is not None
    }
    return sorted(emails)
