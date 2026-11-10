from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Session as SessionRow


def _now() -> datetime:
    return datetime.utcnow()


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
) -> str:
    sid = secrets.token_urlsafe(32)
    row = SessionRow(
        session_id=sid,
        user_id=user_id,
        expires_at=_now() + timedelta(seconds=int(ttl_seconds)),
        auth_method=(auth_method or "local")[:20],
        oidc_id_token=oidc_id_token,
    )
    db.add(row)
    db.commit()
    return sid


def get_session(db: Session, session_id: str) -> SessionRow | None:
    sid = (session_id or "").strip()
    if not sid:
        return None
    row = db.query(SessionRow).filter(SessionRow.session_id == sid).one_or_none()
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


def refresh_session(db: Session, session_row: SessionRow, ttl_seconds: int) -> None:
    new_expiry = _now() + timedelta(seconds=int(ttl_seconds))
    # Rolling expiry never pushes a session past its absolute lifetime.
    hard_end = _absolute_cutoff(session_row)
    if session_row.created_at and new_expiry > hard_end:
        new_expiry = hard_end
    session_row.expires_at = new_expiry
    db.add(session_row)
    db.commit()


def delete_session(db: Session, session_id: str) -> None:
    sid = (session_id or "").strip()
    if not sid:
        return
    row = db.query(SessionRow).filter(SessionRow.session_id == sid).one_or_none()
    if row:
        db.delete(row)
        db.commit()


def delete_all_sessions_for_user(db: Session, user_id: int) -> int:
    deleted = (
        db.query(SessionRow)
        .filter(SessionRow.user_id == user_id)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted
