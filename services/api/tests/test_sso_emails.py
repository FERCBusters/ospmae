"""SSO email addresses, ported from KEEN.

An account proves an address by opening a mailed link while signed in; only
proved addresses link a provider's identity. Managing them needs a sign-in
within the last five minutes, the link lasts 30 minutes and works once, and a
change to the password or second factors ends it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from app.core.config import settings
from app.db.models import Session as SessionRow
from app.db.models import SsoEmailChallenge, User, UserSsoEmail
from app.db.session import SessionLocal

from tests.conftest import auth_client, make_user

ADDED = "OSPMAE security: An SSO email address was verified for your OSPMAE account"
REMOVED = "OSPMAE security: An SSO email address was removed from your OSPMAE account"


@pytest.fixture(autouse=True)
def _named_sender(monkeypatch):
    monkeypatch.setattr(settings, "smtp_from_name", "OSPMAE")


def _csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("ospmae_csrf") or ""}


def _account(email: str = "owner@x.test"):
    client, user = auth_client(role="viewer")
    with SessionLocal() as s:
        s.get(User, user.id).email = email
        s.commit()
    return client, user


def _request(client, email: str):
    return client.post(
        "/v1/me/sso-emails/request", json={"email": email}, headers=_csrf(client)
    )


def _link(outbox, address: str) -> str:
    [mail] = [m for m in outbox.messages() if m.recipient == address]
    assert mail.subject == "Verify your OSPMAE SSO email address"
    return mail.body.split("sso-email.html#token=")[1].split()[0]


def _confirm(client, token: str):
    return client.post(
        "/v1/me/sso-emails/confirm", json={"token": token}, headers=_csrf(client)
    )


def _addresses(user_id: int) -> list[str]:
    with SessionLocal() as s:
        return sorted(
            e for (e,) in s.query(UserSsoEmail.email).filter_by(user_id=user_id)
        )


def test_a_mailed_link_proves_the_address(outbox):
    client, user = _account()

    assert _request(client, "Work@X.test").json() == {"ok": True}
    token = _link(outbox, "work@x.test")
    confirmed = _confirm(client, token)
    assert confirmed.json() == {"ok": True, "email": "work@x.test"}
    assert _addresses(user.id) == ["work@x.test"]

    # The owner hears of it at the account's own email.
    [notice] = [m for m in outbox.messages() if m.subject == ADDED]
    assert notice.recipient == "owner@x.test"
    assert "IP address: 8.8.8.8\n" in notice.body
    # The link works once.
    assert _confirm(client, token).status_code == 400

    listing = client.get("/v1/me/sso-emails").json()
    assert listing["primary_email"] == "owner@x.test"
    assert listing["smtp_configured"] is True
    assert [a["email"] for a in listing["addresses"]] == ["work@x.test"]
    assert _request(client, "work@x.test").json() == {
        "ok": True,
        "already_verified": True,
    }


def test_requests_need_mail_and_an_https_address(outbox, monkeypatch):
    client, _user = _account()
    monkeypatch.setattr(settings, "public_base_url", "http://ospmae.example.com")
    assert _request(client, "work@x.test").status_code == 503
    monkeypatch.setattr(settings, "smtp_host", "")
    response = _request(client, "work@x.test")
    assert response.status_code == 503
    assert response.json()["detail"].startswith("SMTP must be configured")


def test_managing_addresses_needs_a_recent_sign_in(outbox):
    client, user = _account()
    with SessionLocal() as s:
        s.query(SessionRow).filter_by(user_id=user.id).update(
            {"created_at": datetime.utcnow() - timedelta(minutes=6)}
        )
        s.commit()

    for response in (
        _request(client, "work@x.test"),
        client.post(
            "/v1/me/sso-emails/remove",
            json={"email": "work@x.test"},
            headers=_csrf(client),
        ),
    ):
        assert response.status_code == 403
        assert "within five minutes" in response.json()["detail"]
    assert outbox.messages() == []


def test_requests_are_limited_per_account(outbox):
    client, _user = _account()
    for n in range(5):
        assert _request(client, f"a{n}@x.test").status_code == 200
    assert _request(client, "a5@x.test").status_code == 429


def test_an_account_keeps_at_most_ten_addresses(outbox):
    client, user = _account()
    with SessionLocal() as s:
        s.add_all(
            UserSsoEmail(email=f"n{n}@x.test", user_id=user.id) for n in range(10)
        )
        s.commit()
    response = _request(client, "eleven@x.test")
    assert response.status_code == 400


def test_another_accounts_address_gets_the_same_answer_and_no_mail(outbox):
    make_user("holder", "Holder-pass-1!", role="viewer", email="taken@x.test")
    client, user = _account()

    assert _request(client, "taken@x.test").json() == {"ok": True}
    # Nothing is mailed to an address another account uses.
    assert [m for m in outbox.messages() if m.recipient == "taken@x.test"] == []
    with SessionLocal() as s:
        assert s.query(SsoEmailChallenge).filter_by(user_id=user.id).count() == 1


def test_a_new_request_replaces_the_outstanding_link(outbox):
    client, user = _account()
    _request(client, "first@x.test")
    first = _link(outbox, "first@x.test")
    _request(client, "second@x.test")

    assert _confirm(client, first).status_code == 400
    assert _confirm(client, _link(outbox, "second@x.test")).status_code == 200
    assert _addresses(user.id) == ["second@x.test"]


def test_a_password_change_ends_an_outstanding_link(outbox):
    client, user = _account()
    _request(client, "work@x.test")
    token = _link(outbox, "work@x.test")
    with SessionLocal() as s:
        s.get(User, user.id).password_hash = "changed"
        s.commit()

    response = _confirm(client, token)
    assert response.status_code == 400
    assert response.json()["detail"] == "Verification link is invalid or expired"


def test_a_link_only_works_for_the_account_that_asked(outbox):
    client, _user = _account()
    _request(client, "work@x.test")
    token = _link(outbox, "work@x.test")

    other, _other_user = auth_client(role="viewer")
    assert _confirm(other, token).status_code == 400


def test_an_expired_link_is_refused(outbox):
    client, user = _account()
    _request(client, "work@x.test")
    token = _link(outbox, "work@x.test")
    with SessionLocal() as s:
        s.query(SsoEmailChallenge).filter_by(user_id=user.id).update(
            {"expires_at": datetime.utcnow() - timedelta(seconds=1)}
        )
        s.commit()
    assert _confirm(client, token).status_code == 400


def test_an_address_claimed_meanwhile_is_refused(outbox):
    client, user = _account()
    _request(client, "work@x.test")
    token = _link(outbox, "work@x.test")
    make_user("late", "Late-pass-123!", role="viewer", email="work@x.test")

    response = _confirm(client, token)
    assert response.status_code == 409
    assert _addresses(user.id) == []


def test_removing_an_address_mails_the_owner(outbox):
    client, user = _account()
    with SessionLocal() as s:
        s.add(UserSsoEmail(email="work@x.test", user_id=user.id))
        s.commit()

    response = client.post(
        "/v1/me/sso-emails/remove",
        json={"email": "WORK@x.test"},
        headers=_csrf(client),
    )
    assert response.json() == {"ok": True}
    assert _addresses(user.id) == []
    assert [m.recipient for m in outbox.messages() if m.subject == REMOVED] == [
        "owner@x.test"
    ]

    # Removing an address the account does not hold says nothing.
    client.post(
        "/v1/me/sso-emails/remove",
        json={"email": "work@x.test"},
        headers=_csrf(client),
    )
    assert len([m for m in outbox.messages() if m.subject == REMOVED]) == 1


def test_an_address_is_one_mailbox(outbox):
    client, _user = _account()
    for bad in ("a@x.test, b@x.test", "Name <a@x.test>", "a@@x.test"):
        assert _request(client, bad).status_code == 400, bad


def test_account_mail_goes_to_the_account_email_only(outbox, db):
    """Proved linking addresses are never mailed."""
    from app.services.notification_recipients import notification_email_for_user

    user = make_user("mailee", "Mailee-pass-1!", role="viewer")
    with SessionLocal() as s:
        s.add(UserSsoEmail(email="linked@x.test", user_id=user.id))
        s.commit()
        account = s.get(User, user.id)
        assert notification_email_for_user(s, user=account) is None
        account.email = "two@x.test, three@x.test"
        assert notification_email_for_user(s, user=account) is None
        account.email = "own@x.test"
        assert notification_email_for_user(s, user=account) == "own@x.test"
