"""Edges of sign-in state: which origin a write may come from, how cookies
are named, what a sign-out link does, how wrong codes are remembered, and
what is kept about a session and a request."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from app import main as main_module
from app.core.config import settings
from app.db.models import Notification
from app.db.models import Session as SessionRow
from app.db.session import SessionLocal
from app.security import csrf, mfa, oidc
from app.services import notifications
from starlette.requests import Request

from tests.support import signed_in


def _request(**headers: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/x",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )


@pytest.mark.parametrize(
    "origin, host, secure, allowed",
    [
        # The page's own origin, with and without a port in Host.
        ("https://ospmae.example", "ospmae.example", True, True),
        ("https://ospmae.example:8443", "ospmae.example:8443", True, True),
        ("https://ospmae.example:443", "ospmae.example", True, True),
        # Another service on the same host name, on another port.
        ("https://ospmae.example:8443", "ospmae.example", True, False),
        ("https://ospmae.example", "ospmae.example:8443", True, False),
        ("https://ospmae.example:9000", "ospmae.example:8443", True, False),
        # The same name over plain HTTP, where cookies are Secure.
        ("http://ospmae.example", "ospmae.example", True, False),
        ("http://ospmae.example:80", "ospmae.example:80", True, False),
        # A plain-HTTP installation (development) accepts its own origin.
        ("http://localhost:8080", "localhost:8080", False, True),
        ("http://localhost", "localhost", False, True),
        ("http://localhost:8081", "localhost:8080", False, False),
        # Another host is refused whatever else matches.
        ("https://evil.example", "ospmae.example", True, False),
        ("https://ospmae.example", "", True, False),
        ("https://ospmae.example", "ospmae.example:port", True, False),
    ],
)
def test_without_a_configured_address_the_origin_is_the_one_addressed(
    monkeypatch, origin, host, secure, allowed
):
    monkeypatch.setattr(settings, "public_base_url", "")
    monkeypatch.setattr(settings, "cookie_secure", secure)
    headers = {"Origin": origin}
    if host:
        headers["Host"] = host
    assert csrf.request_origin_allowed(_request(**headers)) is allowed


@pytest.mark.parametrize(
    "secure, domain, prefixed",
    [(True, "", True), (False, "", False), (True, "example.org", False)],
)
def test_every_cookie_is_host_bound_by_the_same_rule(
    monkeypatch, secure, domain, prefixed
):
    monkeypatch.setattr(settings, "cookie_secure", secure)
    monkeypatch.setattr(settings, "cookie_domain", domain)
    # The address the installation is published at decides nothing here: a
    # prefix without the Secure attribute is a cookie browsers refuse.
    monkeypatch.setattr(settings, "public_base_url", "https://ospmae.example")
    names = [mfa.cookie_name(), oidc.sso_binding_cookie(), csrf.csrf_cookie_name()]
    assert [name.startswith("__Host-") for name in names] == [prefixed] * 3
    assert [name.removeprefix("__Host-") for name in names] == [
        "ospmae_mfa_pending",
        "ospmae_sso",
        "ospmae_csrf",
    ]


def test_a_sign_out_link_without_the_token_changes_nothing(client):
    from app.main import app
    from fastapi.testclient import TestClient

    from tests.conftest import peer_wrapper

    # No session: a browser holding only a ceremony cookie and a CSRF cookie.
    visitor = TestClient(peer_wrapper(app), base_url="https://testserver")
    visitor.headers["X-Test-Peer"] = "127.0.0.1"
    visitor.cookies.set(mfa.cookie_name(), "pending", domain="testserver.local")
    visitor.cookies.set(csrf.csrf_cookie_name(), "token", domain="testserver.local")
    for query in ({}, {"csrf": "wrong"}):
        left = visitor.get("/v1/auth/logout", params=query, follow_redirects=False)
        assert (left.status_code, left.headers["location"]) == (302, "/index.html")
        assert left.headers.get_list("set-cookie") == []

    # With the cookie's own token the sign-out goes ahead and clears them.
    done = visitor.get(
        "/v1/auth/logout", params={"csrf": "token"}, follow_redirects=False
    )
    assert done.headers["location"] == "/login.html"
    cleared = " ".join(done.headers.get_list("set-cookie"))
    assert mfa.cookie_name() in cleared and csrf.csrf_cookie_name() in cleared


def _account(failures: int = 0, since: datetime | None = None):
    return SimpleNamespace(mfa_code_failures=failures, mfa_code_failures_since=since)


def test_wrong_codes_are_remembered_for_a_day_and_refused_for_an_hour(monkeypatch):
    clock = [datetime(2026, 1, 1, 9, 0)]
    monkeypatch.setattr(mfa, "_now", lambda: clock[0])
    account = _account()

    # Four wrong codes an hour apart, as someone holding the password might
    # try them: under the old rule each hour began a fresh count.
    for _ in range(4):
        assert mfa.record_wrong_code(account) is False
        assert mfa.codes_refused(account) is False
        clock[0] += timedelta(hours=1, minutes=5)
    # The fifth spends the allowance, which is what mails the owner.
    assert mfa.record_wrong_code(account) is True
    assert mfa.codes_refused(account) is True
    clock[0] += timedelta(minutes=59)
    assert mfa.codes_refused(account) is True
    # A code tried during the refusal keeps it going.
    assert mfa.record_wrong_code(account) is True
    clock[0] += timedelta(minutes=59)
    assert mfa.codes_refused(account) is True
    clock[0] += timedelta(minutes=2)
    assert mfa.codes_refused(account) is False
    # Once a refusal has been served, the count starts again.
    assert mfa.record_wrong_code(account) is False
    assert account.mfa_code_failures == 1

    # A day without a wrong code, and the earlier ones are forgotten.
    account = _account()
    for _ in range(3):
        mfa.record_wrong_code(account)
    clock[0] += timedelta(hours=23, minutes=59)
    mfa.record_wrong_code(account)
    assert account.mfa_code_failures == 4
    clock[0] += timedelta(hours=24)
    assert mfa.record_wrong_code(account) is False
    assert account.mfa_code_failures == 1
    # A right code clears the count at once.
    mfa.clear_wrong_codes(account)
    assert (account.mfa_code_failures, account.mfa_code_failures_since) == (0, None)


def _enable_oidc(monkeypatch, **more):
    for name, value in {
        "oidc_sso_enabled": True,
        "oidc_client_id": "client",
        "oidc_client_secret": "secret",
        "oidc_authorization_endpoint": "https://idp.example/auth",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_redirect_uri": "https://testserver/v1/auth/sso/oidc/callback",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_issuer": "https://idp.example",
        **more,
    }.items():
        monkeypatch.setattr(settings, name, value)


def test_a_provider_session_lasts_only_while_the_provider_is_enabled(monkeypatch):
    _enable_oidc(monkeypatch)
    client, user_id = signed_in("viewer")
    with SessionLocal() as s:
        row = s.query(SessionRow).filter_by(user_id=user_id).one()
        row.auth_method = "oidc"
        s.commit()
    assert client.get("/v1/me").status_code == 200

    monkeypatch.setattr(settings, "oidc_sso_enabled", False)
    assert client.get("/v1/me").status_code == 401
    # Turning the provider back on does not bring the session back.
    monkeypatch.setattr(settings, "oidc_sso_enabled", True)
    assert client.get("/v1/me").status_code == 401
    with SessionLocal() as s:
        assert s.query(SessionRow).filter_by(user_id=user_id).count() == 0
    # A password session is untouched by any of it.
    other, _ = signed_in("viewer")
    monkeypatch.setattr(settings, "oidc_sso_enabled", False)
    assert other.get("/v1/me").status_code == 200


@pytest.mark.parametrize(
    "referer, kept",
    [
        (None, None),
        ("  ", None),
        ("https://ospmae.example/project.html", "https://ospmae.example/project.html"),
        (
            "https://ospmae.example/login.html?next=/x&token=abc123#frag",
            "https://ospmae.example/login.html?next=/x&token=%5BREDACTED%5D",
        ),
        ("https://[bad", None),
    ],
)
def test_the_page_a_request_came_from_is_kept_without_its_secrets(referer, kept):
    from app.security.redaction import redact_query_string

    stored = main_module._referer_for_audit(referer)
    if kept is not None and "token=" in kept:
        # Whatever the redactor writes for a secret, the secret is not there.
        assert "abc123" not in stored and "#" not in stored
        assert stored == "https://ospmae.example/login.html?" + redact_query_string(
            "next=/x&token=abc123"
        )
    else:
        assert stored == kept


def test_a_mail_that_will_never_be_sent_keeps_no_body(db, monkeypatch):
    from app.services import mailer

    monkeypatch.setattr(notifications, "smtp_configured", lambda: True)

    def refuse(**_):
        raise OSError("smtp down: password=hunter2")

    monkeypatch.setattr(mailer, "send_email", refuse)
    with SessionLocal() as s:
        row = Notification(
            recipient="a@x.test",
            subject="Confirm your address",
            body="https://ospmae.example/confirm?token=one-time-secret",
            status="pending",
            attempts=notifications._MAX_ATTEMPTS - 2,
            next_attempt_at=datetime.utcnow() - timedelta(minutes=1),
        )
        s.add(row)
        s.commit()
        row_id = row.id

    assert notifications.deliver_pending(limit=1) == 0
    with SessionLocal() as s:
        row = s.get(Notification, row_id)
        # Still to be retried: the body is what the retry sends.
        assert (row.status, row.attempts) == (
            "pending",
            notifications._MAX_ATTEMPTS - 1,
        )
        assert "one-time-secret" in row.body
        row.next_attempt_at = datetime.utcnow() - timedelta(minutes=1)
        s.commit()
    assert notifications.deliver_pending(limit=1) == 0
    with SessionLocal() as s:
        row = s.get(Notification, row_id)
        assert (row.status, row.body) == ("failed", "")
        assert row.last_error == "OSError"
