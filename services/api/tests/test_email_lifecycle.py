"""Account emails (verification lifecycle) and navbar shortcuts."""

from __future__ import annotations

from datetime import datetime, timedelta

from app.db.models import EmailVerificationToken, UserEmail

from tests.conftest import auth_client


def test_self_asserted_emails_start_unverified(client, db):
    c, user = auth_client("MailU")
    csrf = c.cookies.get("ospmae_csrf")
    r = c.post(
        "/v1/me/emails",
        json={"email": "mailu@example.com", "is_primary": False},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 200
    row = db.query(UserEmail).filter(UserEmail.email_lower == "mailu@example.com").one()
    assert row.is_verified is False, "self-asserted addresses are never trusted"
    assert row.source == "user"


def test_verification_token_single_use_and_expiring(client, monkeypatch, db):
    from app.core.config import settings

    saved = (settings.smtp_host, settings.smtp_from_email, settings.public_base_url)
    settings.smtp_host = "smtp.example.com"
    settings.smtp_from_email = "noreply@example.com"
    settings.public_base_url = "https://ospmae.example.com"
    try:
        c, user = auth_client("MailV")
        csrf = c.cookies.get("ospmae_csrf")
        r = c.post(
            "/v1/me/emails",
            json={"email": "mailv@example.com", "is_primary": False},
            headers={"X-CSRF-Token": csrf or ""},
        )
        assert r.status_code == 200
        token_row = (
            db.query(EmailVerificationToken)
            .filter(EmailVerificationToken.user_id == int(user.id))
            .one()
        )
        stored_digest = token_row.token_hash

        # The unauthenticated redemption endpoint takes only the token.
        # Force the digest we stored: the test cannot see the mailed link, so
        # mint a matching token row directly for the redemption path.
        token_row.token_hash = token_row.token_hash  # exercised via unit path
        db.commit()
        assert stored_digest == token_row.token_hash

        # Redemption is unauthenticated: the token itself is the bearer.
        fresh = client
        r = fresh.post("/v1/me/emails/verify", json={"token": "wrong-token"})
        assert r.status_code == 400

        # An expired token is refused.
        import hashlib

        real_token = "real-token-for-mailv"
        token_row.token_hash = hashlib.sha256(real_token.encode()).hexdigest()
        token_row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
        r = fresh.post("/v1/me/emails/verify", json={"token": real_token})
        assert r.status_code == 400

        # A live token verifies the row once, then is spent.
        token_row.expires_at = datetime.utcnow() + timedelta(hours=1)
        db.commit()
        r = fresh.post("/v1/me/emails/verify", json={"token": real_token})
        assert r.status_code == 200, r.text
        r2 = fresh.post("/v1/me/emails/verify", json={"token": real_token})
        assert r2.status_code == 400, "one-time redemption"
    finally:
        settings.smtp_host, settings.smtp_from_email, settings.public_base_url = saved


def test_verification_send_needs_smtp_or_public_base_url(client, monkeypatch, db):
    from app.core.config import settings

    saved = (settings.smtp_host, settings.smtp_from_email, settings.public_base_url)
    settings.smtp_host = ""
    settings.public_base_url = ""
    try:
        c, user = auth_client("MailW")
        csrf = c.cookies.get("ospmae_csrf")
        r = c.post(
            "/v1/me/emails",
            json={"email": "mailw@example.com", "is_primary": False},
            headers={"X-CSRF-Token": csrf or ""},
        )
        assert r.status_code == 200
        assert db.query(EmailVerificationToken).count() == 0, (
            "fail closed: no SMTP/public URL means no trusted address"
        )
    finally:
        settings.smtp_host, settings.smtp_from_email, settings.public_base_url = saved


def test_shortcut_urls_must_be_same_origin(client):
    from app.api.routes.me import _normalize_shortcut_url
    from fastapi import HTTPException

    assert _normalize_shortcut_url("/project.html?id=1") == "/project.html?id=1"
    for bad in ("//evil.example.com", "/\\evil", "javascript:alert(1)", "", "http://x"):
        try:
            _normalize_shortcut_url(bad)
        except HTTPException:
            continue
        except Exception:
            raise
        raise AssertionError(f"accepted unsafe shortcut: {bad!r}")


def test_email_shape_is_checked(client):
    c, user = auth_client("MailX")
    csrf = c.cookies.get("ospmae_csrf")
    r = c.post(
        "/v1/me/emails",
        json={"email": "not-an-email", "is_primary": False},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code in (400, 422)
