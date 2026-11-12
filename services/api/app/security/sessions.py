"""Database-backed browser sessions.

The browser holds the session identifier; the database holds only its
SHA-256 digest, as KEEN's session store does, so a copy of the table, a
backup or a database reader sees no identifier a browser could present.
Every lookup by a presented identifier goes through ``session_row``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Session as SessionRow
from app.db.models import User


def _now() -> datetime:
    return datetime.utcnow()


def stored_session_id(session_id: str) -> str:
    """The form in which a session identifier is stored: its SHA-256 digest."""

    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def csrf_token_for(session_id: str) -> str:
    """The CSRF token that belongs to a session.

    It is derived from the identifier the browser holds in its HttpOnly
    cookie, which the database never stores, so only that session's own
    responses can carry it: a cookie planted from a sibling subdomain, or
    another account's token, is not this one.
    """

    digest = hmac.new(
        session_id.encode("utf-8"), b"ospmae-csrf-token", hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def session_row(db: Session, session_id: str | None) -> SessionRow | None:
    """The stored row for an identifier a browser presented, whatever its age."""

    sid = (session_id or "").strip()
    if not sid:
        return None
    return (
        db.query(SessionRow)
        .filter(SessionRow.session_id == stored_session_id(sid))
        .one_or_none()
    )


def _absolute_cutoff(row: SessionRow) -> datetime:
    """Fixed end-of-life computed from the session's creation time."""

    ttl = int(getattr(settings, "session_absolute_ttl_seconds", 0) or 0)
    if ttl <= 0:
        return row.created_at + timedelta(seconds=60 * 60 * 24 * 30)
    return row.created_at + timedelta(seconds=ttl)


def create_session(
    db: Session,
    *,
    user_id: int,
    ttl_seconds: int,
    auth_method: str = "local",
    oidc_id_token: str | None = None,
    mfa_verified: bool = False,
    mfa_version: int = 0,
) -> str:
    sid = secrets.token_urlsafe(32)
    row = SessionRow(
        session_id=stored_session_id(sid),
        user_id=user_id,
        expires_at=_now() + timedelta(seconds=int(ttl_seconds)),
        auth_method=(auth_method or "local")[:20],
        oidc_id_token=oidc_id_token,
        # The second-factor state proven when this session was issued; the
        # account's later enrolment bumps are refused at resolution.
        mfa_verified=bool(mfa_verified),
        mfa_version=int(mfa_version),
    )
    db.add(row)
    db.commit()
    return sid


def get_session(db: Session, session_id: str) -> SessionRow | None:
    row = session_row(db, session_id)
    if not row:
        return None
    now = _now()
    if row.expires_at <= now:
        db.delete(row)
        db.commit()
        return None
    if row.created_at and now >= _absolute_cutoff(row):
        # A session also ends a fixed time after sign-in however recently it
        # was used.
        db.delete(row)
        db.commit()
        return None
    return row


def refresh_session(db: Session, row: SessionRow, ttl_seconds: int) -> None:
    new_expiry = _now() + timedelta(seconds=int(ttl_seconds))
    # Rolling expiry never pushes a session past its absolute lifetime.
    hard_end = _absolute_cutoff(row)
    if row.created_at and new_expiry > hard_end:
        new_expiry = hard_end
    row.expires_at = new_expiry
    db.add(row)
    db.commit()


def delete_session(db: Session, session_id: str) -> None:
    """End the session a browser presented."""

    row = session_row(db, session_id)
    if row:
        db.delete(row)
        db.commit()


def end_all_sessions(db: Session, user: User) -> None:
    """End every session of the account, in the caller's transaction.

    The enrolment version moves on too, so a second-factor ceremony or an
    address proof started under the old state ends with them (KEEN advances
    its session and second-factor versions the same way).
    """
    db.query(SessionRow).filter(SessionRow.user_id == user.id).delete(
        synchronize_session=False
    )
    user.mfa_version = User.mfa_version + 1


def delete_all_sessions_for_user(db: Session, user_id: int) -> int:
    deleted = (
        db.query(SessionRow)
        .filter(SessionRow.user_id == user_id)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted
