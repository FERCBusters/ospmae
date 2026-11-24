"""OSPMAE's names on mosp's sign-in surface: its cookies, the check
header nginx reads, and the methods it advertises.

mosp's suite covers signing in and out, CSRF and the providers."""

from __future__ import annotations

from tests.conftest import auth_client, login, make_user


def test_login_sets_secure_session_and_csrf_cookies(client):
    make_user("CookieU", "Test-passphrase-1!", role="viewer")
    c = client
    r = login(c, "CookieU", "Test-passphrase-1!")
    assert r.status_code == 200
    assert c.cookies.get("__Host-ospmae_session")
    assert c.cookies.get("__Host-ospmae_csrf")


def test_cookie_authenticates_and_check_names_the_account(client):
    c, user = auth_client("CheckU")
    r = c.get("/v1/auth/check")
    assert r.status_code == 204
    assert r.headers["X-Ospmae-User"] == "CheckU"
    r = c.get("/v1/auth/check-admin")
    assert r.status_code == 204


def test_unauthenticated_check_is_401(client):
    r = client.get("/v1/auth/check")
    assert r.status_code == 401


def test_no_password_reset_is_advertised(client):
    # As in KEEN, an administrator resets passwords: sign-in offers no reset.
    r = client.get("/v1/auth/methods")
    assert "password_reset_enabled" not in r.json()
    assert "password_reset" not in r.json()
