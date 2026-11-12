"""Cookies, CSRF, logout and the methods/check surfaces."""

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
    assert r.headers["X-Project-User"] == "CheckU"
    r = c.get("/v1/auth/check-admin")
    assert r.status_code == 204


def test_unauthenticated_check_is_401(client):
    r = client.get("/v1/auth/check")
    assert r.status_code == 401


def test_unsafe_write_without_csrf_token_is_refused(client):
    c, _user = auth_client("CsrfU")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.post(
        "/v1/auth/change-password",
        json={
            "current_password": "x",
            "new_password": "y",
            "confirm_password": "y",
        },
    )
    assert r.status_code == 403, "cookie-authenticated write must carry CSRF"
    del csrf


def test_logout_get_without_proof_keeps_the_session(client):
    c, user = auth_client("LogoutU")
    r = c.get("/v1/auth/logout", follow_redirects=False)
    assert r.status_code == 302
    assert c.get("/v1/auth/check").status_code == 204


def test_logout_get_with_csrf_proof_destroys_the_session(client):
    c, user = auth_client("LogoutV")
    token = c.cookies.get("__Host-ospmae_csrf")
    r = c.get(f"/v1/auth/logout?csrf={token}", follow_redirects=False)
    assert r.status_code == 302
    assert c.get("/v1/auth/check").status_code == 401


def test_logout_post_destroys_the_session_and_all_others(client, db):
    from app.db.models import Session as SessionRow

    c, user = auth_client("LogoutW")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    # A second device holds another session of the same account.
    from app.security.sessions import create_session

    s = db
    create_session(s, user_id=int(user.id), ttl_seconds=600)
    r = c.post("/v1/auth/logout", headers={"X-CSRF-Token": csrf or ""})
    assert r.status_code == 204
    assert c.get("/v1/auth/check").status_code == 401
    remaining = s.query(SessionRow).filter(SessionRow.user_id == int(user.id)).count()
    assert remaining == 0


def test_login_exemption_is_exactly_login(client, db):
    """POST logout must still require the CSRF proof only login is exempt."""
    make_user("ExemptU", "Test-passphrase-1!", role="viewer")
    r = login(client, "ExemptU", "Test-passphrase-1!")
    assert r.status_code == 200
    # No CSRF header: the middleware refuses the unsafe write.
    r = client.post("/v1/auth/logout")
    assert r.status_code == 403


def test_auth_methods_lists_enabled_providers(client, monkeypatch):
    from app.core.config import settings

    saved = {
        "local": settings.local_auth_enabled,
        "sso": settings.oidc_sso_enabled,
    }
    settings.oidc_sso_enabled = True
    settings.oidc_client_id = "client"
    settings.oidc_client_secret = "secret"
    settings.oidc_authorization_endpoint = "https://idp.example.com/auth"
    settings.oidc_token_endpoint = "https://idp.example.com/token"
    settings.oidc_redirect_uri = "https://ospmae.example.com/v1/auth/sso/oidc/callback"
    settings.oidc_jwks_uri = "https://idp.example.com/.well-known/jwks.json"
    settings.oidc_issuer = "https://idp.example.com"
    try:
        r = client.get("/v1/auth/methods")
        assert r.status_code == 200
        body = r.json()
        assert body["local_enabled"] is True
        assert body["sso_providers"][0]["key"] == "oidc"
    finally:
        settings.local_auth_enabled = saved["local"]
        settings.oidc_sso_enabled = saved["sso"]


def test_no_password_reset_is_advertised(client):
    # As in KEEN, an administrator resets passwords: sign-in offers no reset.
    r = client.get("/v1/auth/methods")
    assert "password_reset_enabled" not in r.json()
    assert "password_reset" not in r.json()
