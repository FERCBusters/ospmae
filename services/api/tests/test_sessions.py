"""Session lifetimes and the absolute ceiling."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from app.core.config import settings
from app.db.models import Session as SessionRow
from app.db.models import User
from app.security.sessions import (
    create_session,
    delete_all_sessions_for_user,
    delete_session,
    get_session,
    refresh_session,
)


def _user(db, name: str = "SessU") -> User:
    from app.security.auth import create_user

    u = create_user(db, username=name, password="Password1!", role="viewer")
    db.close()
    return u


def test_session_round_trip(db):
    u = _user(db)
    sid = create_session(db, user_id=int(u.id), ttl_seconds=600)
    row = get_session(db, sid)
    assert row is not None and row.user_id == int(u.id)


def test_expired_session_is_deleted_on_read(db):
    u = _user(db)
    sid = create_session(db, user_id=int(u.id), ttl_seconds=-1)
    assert get_session(db, sid) is None
    assert db.query(SessionRow).filter(SessionRow.session_id == sid).count() == 0


def test_absolute_ttl_rolls_well_past_the_rolling_window(db, monkeypatch):
    u = _user(db)
    monkeypatch.setattr(settings, "session_absolute_ttl_seconds", 60)
    sid = create_session(db, user_id=int(u.id), ttl_seconds=600)
    row = get_session(db, sid)
    assert row is not None
    # Age past the absolute ceiling; a rolling refresh cannot resurrect it.
    row.created_at = datetime.utcnow() - timedelta(seconds=300)
    row.expires_at = datetime.utcnow() + timedelta(seconds=600)
    db.add(row)
    db.commit()
    refresh_session(db, row, 600)
    row = get_session(db, sid)
    assert row is None, "rolling refresh must never exceed the absolute lifetime"


def test_delete_session_and_bulk_revoke(db):
    u = _user(db)
    sid = create_session(db, user_id=int(u.id), ttl_seconds=600)
    create_session(db, user_id=int(u.id), ttl_seconds=600)
    delete_session(db, sid)
    assert get_session(db, sid) is None
    deleted = delete_all_sessions_for_user(db, int(u.id))
    assert deleted == 1


def test_get_session_refuses_blank_and_strips(db):
    assert get_session(db, "") is None
    assert get_session(db, secrets.token_urlsafe(32)) is None


def test_session_rows_carry_creation_time_for_the_ceiling(db):
    u = _user(db)
    sid = create_session(db, user_id=int(u.id), ttl_seconds=600)
    row = db.query(SessionRow).filter(SessionRow.session_id == sid).one()
    assert row.created_at <= datetime.utcnow() + timedelta(seconds=5)
