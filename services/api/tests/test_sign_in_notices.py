"""Unfamiliar-address sign-in notices, ported from KEEN.

A completed sign-in records its client address against the account; the
first sign-in from an address the account has not used before mails the
account a security notice through the outbox.
"""

from __future__ import annotations

import threading

import pytest
from app.core.config import settings
from app.db.models import User, UserLoginIP
from app.db.session import SessionLocal
from app.services import security_notifications
from fastapi.testclient import TestClient

from tests.conftest import login, make_user, peer_wrapper

PASSWORD = "Pass-notices-long1!"
SUBJECT = "OSPMAE security: Sign-in from an unfamiliar IP address"


@pytest.fixture(autouse=True)
def _local_sign_in(monkeypatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    monkeypatch.setattr(settings, "smtp_from_name", "OSPMAE")


def _client() -> TestClient:
    from app.main import app as application

    return TestClient(peer_wrapper(application), base_url="https://testserver")


def _known_addresses(user_id: int) -> set[str]:
    with SessionLocal() as s:
        return {
            address
            for (address,) in s.query(UserLoginIP.address).filter_by(user_id=user_id)
        }


def test_each_new_address_mails_the_account_once(outbox):
    user = make_user("roaming", PASSWORD, role="viewer", email="roam@example.com")

    assert login(_client(), "roaming", PASSWORD, peer="203.0.113.7").status_code == 200
    [notice] = outbox.messages()
    assert notice.recipient == "roam@example.com"
    assert notice.user_id == user.id
    assert notice.subject == SUBJECT
    assert "Account: roaming\n" in notice.body
    assert "OSPMAE installation: https://ospmae.example.com\n" in notice.body
    assert "IP address: 203.0.113.7\n" in notice.body
    assert "has not previously been recorded" in notice.body
    # The notice was handed to the mail worker straight after the commit.
    assert outbox.kicks == [{"retry": False}]

    # The same address again is known: no second notice.
    assert login(_client(), "roaming", PASSWORD, peer="203.0.113.7").status_code == 200
    assert len(outbox.messages()) == 1
    assert len(outbox.kicks) == 1

    # A different address is new again.
    assert login(_client(), "roaming", PASSWORD, peer="2001:db8::5").status_code == 200
    noticed = [
        m.body.split("IP address: ")[1].split("\n")[0] for m in outbox.messages()
    ]
    assert noticed == ["203.0.113.7", "2001:db8::5"]
    assert _known_addresses(user.id) == {"203.0.113.7", "2001:db8::5"}


def test_a_refused_sign_in_records_and_mails_nothing(outbox):
    user = make_user("guarded", PASSWORD, role="viewer", email="g@example.com")

    response = login(_client(), "guarded", "wrong-password", peer="198.51.100.9")
    assert response.status_code == 401
    assert _known_addresses(user.id) == set()
    assert outbox.messages() == []
    assert outbox.kicks == []


def test_without_mail_the_address_is_still_learned(monkeypatch):
    """With SMTP unset nothing is mailed, but the address is remembered, so
    configuring mail later does not alert on addresses already in use."""
    monkeypatch.setattr(settings, "smtp_host", "")
    user = make_user("quiet", PASSWORD, role="viewer", email="q@example.com")

    assert login(_client(), "quiet", PASSWORD, peer="192.0.2.44").status_code == 200
    assert _known_addresses(user.id) == {"192.0.2.44"}
    with SessionLocal() as s:
        from app.db.models import Notification

        assert s.query(Notification).count() == 0


def test_an_account_without_an_address_gets_no_notice(outbox):
    user = make_user("no-mailbox", PASSWORD, role="viewer")

    assert login(_client(), "no-mailbox", PASSWORD, peer="192.0.2.45").status_code == (
        200
    )
    assert _known_addresses(user.id) == {"192.0.2.45"}
    assert outbox.messages() == []
    assert outbox.kicks == []


def test_parallel_sign_ins_from_one_new_address_mail_once(outbox):
    """The account/address key is unique: a second sign-in racing the first
    waits for it and then finds the address known."""
    user = make_user("racer", PASSWORD, role="viewer", email="r@example.com")

    first = SessionLocal()
    try:
        account = first.get(User, user.id)
        assert security_notifications.record_login(first, account, ip="192.0.2.80")
        results: list[bool] = []

        def racing_sign_in() -> None:
            with SessionLocal() as second:
                results.append(
                    security_notifications.record_login(
                        second, second.get(User, user.id), ip="192.0.2.80"
                    )
                )
                second.commit()

        racer = threading.Thread(target=racing_sign_in)
        racer.start()
        # The second insert waits on the first transaction's key.
        racer.join(timeout=1)
        assert racer.is_alive()
        first.commit()
        racer.join(timeout=10)
        assert results == [False]
    finally:
        first.close()

    assert len(outbox.messages()) == 1


def test_a_missing_client_address_is_not_recorded(outbox):
    user = make_user("addressless", PASSWORD, role="viewer", email="a@example.com")
    with SessionLocal() as s:
        account = s.get(User, user.id)
        assert security_notifications.record_login(s, account, ip=None) is False
        assert security_notifications.record_login(s, account, ip="  ") is False
        s.commit()
    assert _known_addresses(user.id) == set()
    assert outbox.messages() == []


def test_sso_sign_in_mails_an_unfamiliar_address(outbox, monkeypatch):
    import app.api.routes.auth as auth_routes
    from app.security.oidc import get_sso_provider

    monkeypatch.setattr(settings, "oidc_sso_enabled", True)
    user = make_user("sso-roamer", PASSWORD, role="viewer", email="sso@example.com")
    provider = get_sso_provider("oidc")

    async def signed_in(request, db, *, provider_key):
        return db.get(User, user.id), "/projects.html", "id-token", provider

    monkeypatch.setattr(auth_routes, "handle_callback", signed_in)
    c = _client()
    c.headers["X-Test-Peer"] = "127.0.0.1"
    c.headers["X-Forwarded-For"] = "198.51.100.23"

    response = c.get(
        "/v1/auth/sso/oidc/callback?state=s&code=c", follow_redirects=False
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/projects.html"
    [notice] = outbox.messages()
    assert notice.recipient == "sso@example.com"
    assert "IP address: 198.51.100.23\n" in notice.body
    assert outbox.kicks == [{"retry": False}]

    # Signing in again from there is quiet.
    response = c.get(
        "/v1/auth/sso/oidc/callback?state=s&code=c", follow_redirects=False
    )
    assert response.status_code == 302
    assert len(outbox.messages()) == 1


def test_known_addresses_go_with_the_account(outbox):
    user = make_user("leaver", PASSWORD, role="viewer", email="l@example.com")
    assert login(_client(), "leaver", PASSWORD, peer="192.0.2.99").status_code == 200
    with SessionLocal() as s:
        s.delete(s.get(User, user.id))
        s.commit()
        assert s.query(UserLoginIP).count() == 0
