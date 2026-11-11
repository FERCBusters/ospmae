"""Security notices for password and email-address changes, ported from KEEN.

Each notice reaches the address that received the account's notices before
the change, so a change of that address is reported to the one it replaced.
"""

from __future__ import annotations

import pytest
from app.core.config import settings

from tests.conftest import auth_client

PREFIX = "OSPMAE security: "


@pytest.fixture(autouse=True)
def _local_accounts(monkeypatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    monkeypatch.setattr(settings, "smtp_from_name", "OSPMAE")


def _csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("ospmae_csrf") or ""}


def _account(email: str = "owner@x.test"):
    password = "Owner-pass-123!"
    client, user = auth_client(password=password, role="viewer")
    from app.db.models import User
    from app.db.session import SessionLocal

    with SessionLocal() as s:
        s.get(User, user.id).email = email
        s.commit()
    return client, user, password


def _notices(outbox) -> list[tuple[str, str]]:
    """(recipient, title) of each security notice, oldest first."""
    return [
        (m.recipient, m.subject.removeprefix(PREFIX))
        for m in outbox.messages()
        if m.subject.startswith(PREFIX) and "unfamiliar IP" not in m.subject
    ]


def _body(outbox, title: str) -> str:
    [body] = [m.body for m in outbox.messages() if m.subject == PREFIX + title]
    return body


def test_changing_the_password_mails_the_owner(outbox):
    client, _user, password = _account()

    response = client.post(
        "/v1/auth/change-password",
        json={
            "current_password": password,
            "new_password": "Changed-pass-456!",
            "confirm_password": "Changed-pass-456!",
        },
        headers=_csrf(client),
    )
    assert response.status_code == 204, response.text
    assert _notices(outbox) == [("owner@x.test", "Your OSPMAE password was changed")]
    assert "IP address: 8.8.8.8\n" in _body(outbox, "Your OSPMAE password was changed")

    # A refused change reports nothing.
    client.post(
        "/v1/auth/change-password",
        json={
            "current_password": "not-the-password",
            "new_password": "Another-pass-789!",
            "confirm_password": "Another-pass-789!",
        },
        headers=_csrf(client),
    )
    assert len(_notices(outbox)) == 1


def test_resetting_the_password_by_link_mails_the_owner(outbox):
    client, user, _password = _account()
    requested = client.post(
        "/v1/auth/request-password-reset",
        json={"identifier": user.username},
        headers=_csrf(client),
    )
    assert requested.status_code == 204, requested.text
    [reset_mail] = [m for m in outbox.messages() if "Password reset" in m.subject]
    token = reset_mail.body.split("reset-password.html?token=")[1].split()[0]

    response = client.post(
        "/v1/auth/reset-password",
        json={
            "token": token,
            "new_password": "Reset-pass-456!",
            "confirm_password": "Reset-pass-456!",
        },
        headers=_csrf(client),
    )
    assert response.status_code == 204, response.text
    assert _notices(outbox) == [("owner@x.test", "Your OSPMAE password was changed")]


def _add_and_verify(client, outbox, address: str) -> int:
    added = client.post("/v1/me/emails", json={"email": address}, headers=_csrf(client))
    assert added.status_code == 200, added.text
    [link_mail] = [m for m in outbox.messages() if m.recipient == address]
    token = link_mail.body.split("verify_email=")[1].split()[0]
    verified = client.post(
        "/v1/me/emails/verify", json={"token": token}, headers=_csrf(client)
    )
    assert verified.status_code == 200, verified.text
    return added.json()["id"]


def test_a_verified_address_is_reported_to_the_current_one(outbox):
    client, _user, _password = _account()

    _add_and_verify(client, outbox, "second@x.test")

    title = "An email address was verified for your OSPMAE account"
    assert _notices(outbox) == [("owner@x.test", title)]
    assert "Address: second@x.test\n" in _body(outbox, title)


def test_a_new_notice_address_is_reported_to_the_old_one(outbox):
    client, _user, _password = _account()
    email_id = _add_and_verify(client, outbox, "second@x.test")

    response = client.post(f"/v1/me/emails/{email_id}/primary", headers=_csrf(client))
    assert response.status_code == 200, response.text

    title = "Notices for your OSPMAE account now go to a different email address"
    assert _notices(outbox)[-1] == ("owner@x.test", title)
    assert "New address: second@x.test\n" in _body(outbox, title)

    # Making the same address primary again changes nothing and says nothing.
    client.post(f"/v1/me/emails/{email_id}/primary", headers=_csrf(client))
    assert [t for _r, t in _notices(outbox)].count(title) == 1


def test_adding_an_address_as_primary_is_reported_to_the_old_one(outbox):
    client, _user, _password = _account()

    added = client.post(
        "/v1/me/emails",
        json={"email": "takeover@x.test", "is_primary": True},
        headers=_csrf(client),
    )
    assert added.status_code == 200, added.text

    title = "Notices for your OSPMAE account now go to a different email address"
    assert _notices(outbox) == [("owner@x.test", title)]
    assert "New address: takeover@x.test\n" in _body(outbox, title)


def test_a_removed_address_is_reported_where_notices_went_before(outbox):
    client, _user, _password = _account()
    second = _add_and_verify(client, outbox, "second@x.test")
    title = "An email address was removed from your OSPMAE account"

    response = client.delete(f"/v1/me/emails/{second}", headers=_csrf(client))
    assert response.status_code == 200, response.text
    assert _notices(outbox)[-1] == ("owner@x.test", title)
    assert "Address: second@x.test" in _body(outbox, title)

    # Removing the address that receives the notices tells that address.
    third = _add_and_verify(client, outbox, "third@x.test")
    client.post(f"/v1/me/emails/{third}/primary", headers=_csrf(client))
    response = client.delete(f"/v1/me/emails/{third}", headers=_csrf(client))
    assert response.status_code == 200, response.text
    assert _notices(outbox)[-1] == ("third@x.test", title)
