"""A sign-in issues its session, or starts its second-factor ceremony, only
for the account as its password check proved it.

Checking a password takes long enough for another request to commit
meanwhile: a password change or reset, a second-factor change, or a
deactivation. Each ends the account's sessions, so it must end a sign-in
proved against the account as it was before.
"""

from __future__ import annotations

import pytest
from app.api.routes import auth as auth_routes
from app.db.models import MfaChallenge, User
from app.db.models import Session as SessionRow
from app.db.session import SessionLocal
from app.security import auth, passwords

from tests.test_password_rules import (
    PASSWORD,
    fresh_browser,
    legacy_hash,
    login,
    make_user,
    store_hash,
    stored_hash,
)

NEW_PASSWORD = "Crimson thimble softly orbits 82"


def _commit(user_id: int, change) -> None:
    # Another request, in its own transaction.
    with SessionLocal() as other:
        change(other.get(User, user_id))
        other.commit()


def _change_password(row: User) -> None:
    # As a self-service change or an administrator's reset commits it.
    row.password_hash = passwords.hash_password(NEW_PASSWORD)
    row.mfa_version += 1


def _change_factors(row: User) -> None:
    row.mfa_version += 1


def _deactivate(row: User) -> None:
    row.is_active = False


CHANGES = pytest.mark.parametrize(
    "change",
    [_change_password, _change_factors, _deactivate],
    ids=["password", "second-factor", "deactivation"],
)
STORED = pytest.mark.parametrize("stored", ["current", "older"], ids=["hash", "rehash"])


def _during_the_check(monkeypatch, user_id: int, change) -> None:
    check = auth.verify_password
    changed = []

    def slow_check(password, stored_hash):
        proven = check(password, stored_hash)
        if not changed:
            changed.append(True)
            _commit(user_id, change)
        return proven

    monkeypatch.setattr(auth, "verify_password", slow_check)


def _sessions(user_id: int) -> int:
    with SessionLocal() as db:
        return db.query(SessionRow).filter(SessionRow.user_id == user_id).count()


@CHANGES
@STORED
def test_a_change_committed_while_the_password_is_checked_issues_no_session(
    monkeypatch, change, stored
):
    user = make_user("racing-" + change.__name__.strip("_"), PASSWORD, role="viewer")
    if stored == "older":
        store_hash(user.id, legacy_hash(PASSWORD))
    _during_the_check(monkeypatch, user.id, change)
    client = fresh_browser()

    refused = login(client, user.username, PASSWORD, peer="7.7.8.1")

    assert (refused.status_code, refused.json()["detail"]) == (
        401,
        "Invalid username or password",
    )
    assert _sessions(user.id) == 0
    assert client.get("/v1/me").status_code == 401
    if change is _change_password:
        # The changed password stands; the older one was not raised over it.
        assert passwords.verify_password(NEW_PASSWORD, stored_hash(user.id))


@CHANGES
@STORED
def test_a_change_committed_while_the_password_is_checked_starts_no_ceremony(
    monkeypatch, change, stored
):
    from app.core.config import settings
    from cryptography.fernet import Fernet

    monkeypatch.setattr(settings, "public_base_url", "https://testserver")
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "mfa_policy", "all")
    user = make_user("ceremony-" + change.__name__.strip("_"), PASSWORD, role="viewer")
    if stored == "older":
        store_hash(user.id, legacy_hash(PASSWORD))
    _during_the_check(monkeypatch, user.id, change)
    client = fresh_browser()
    client.headers["Origin"] = "https://testserver"

    refused = login(client, user.username, PASSWORD, peer="7.7.8.2")

    assert (refused.status_code, refused.json()["detail"]) == (
        401,
        "Account changed; sign in again",
    )
    with SessionLocal() as db:
        assert db.query(MfaChallenge).filter_by(user_id=user.id).count() == 0


def test_a_change_committed_once_the_account_is_checked_ends_the_new_session(
    monkeypatch,
):
    # Ending the account's earlier sessions commits, which ends the row lock
    # the check held; a change committed after it still ends the session,
    # which carries the version the sign-in proved.
    user = make_user("racing-late", PASSWORD, role="viewer")
    end_earlier = auth_routes.delete_all_sessions_for_user

    def then_changed(db, user_id):
        ended = end_earlier(db, user_id)
        _commit(user.id, _change_password)
        return ended

    monkeypatch.setattr(auth_routes, "delete_all_sessions_for_user", then_changed)
    client = fresh_browser()

    signed_in = login(client, user.username, PASSWORD, peer="7.7.8.3")

    assert signed_in.status_code == 200
    assert client.get("/v1/me").status_code == 401


def test_an_unchanged_account_signs_in():
    user = make_user("unchanged", PASSWORD, role="viewer")
    client = fresh_browser()
    assert login(client, user.username, PASSWORD, peer="7.7.8.4").status_code == 200
    assert client.get("/v1/me").json()["username"] == "unchanged"
