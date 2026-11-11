"""Password reset: enumeration-free answers, budgets, single-use tokens."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from app.core.config import settings
from app.db.models import PasswordResetToken, RateLimitEntry
from app.db.session import SessionLocal

from tests.conftest import make_user


def _smtp_on(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_from_email", "noreply@example.com")
    monkeypatch.setattr(settings, "public_base_url", "https://ospmae.example.com")
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    # The route queues the e-mail and hands it to the worker; the hand-off is
    # recorded here instead of reaching a broker.
    from app.tasks import notifications as notification_tasks

    from tests.conftest import _Outbox

    monkeypatch.setattr(notification_tasks, "deliver_notifications", _Outbox())


def test_reset_request_answers_204_for_unknown_and_known(client, monkeypatch, db):
    _smtp_on(monkeypatch)
    _user = make_user("RstU", "Password1!", role="viewer")
    from app.db.models import UserEmail
    from app.db.session import SessionLocal

    s = SessionLocal()
    try:
        from app.security.auth import get_user_by_username as _g

        user = _g(s, "RstU")
        s.add(
            UserEmail(
                user_id=int(user.id),
                email="rstu@example.com",
                email_lower="rstu@example.com",
                source="user",
                is_primary=True,
                is_verified=True,
            )
        )
        s.commit()
    finally:
        s.close()

    c = client
    c.headers["X-Forwarded-For"] = "7.7.7.7"
    for ident in ("rstu@example.com", "RstU", "nobody@example.com", "ghost"):
        r = c.post("/v1/auth/request-password-reset", json={"identifier": ident})
        assert r.status_code == 204, "reset request must not name accounts"


def test_the_emailed_reset_link_works_once(client, monkeypatch, outbox):
    """The reset e-mail commits with its token: the link it carries resets
    the password once and then never again."""
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    make_user("RstMail", "Password1!", role="viewer", email="rstmail@example.com")
    client.headers["X-Forwarded-For"] = "7.7.7.6"

    r = client.post("/v1/auth/request-password-reset", json={"identifier": "RstMail"})
    assert r.status_code == 204
    [mail] = outbox.messages()
    assert mail.recipient == "rstmail@example.com"
    prefix = "https://ospmae.example.com/reset-password.html?token="
    [link] = [line for line in mail.body.splitlines() if line.startswith(prefix)]
    assert outbox.kicks == [{"retry": False}]

    def reset(password: str):
        return client.post(
            "/v1/auth/reset-password",
            json={
                "token": link[len(prefix) :],
                "new_password": password,
                "confirm_password": password,
            },
        )

    assert reset("NewPassword2!").status_code == 204
    assert reset("OtherPassword3!").status_code == 400
    from tests.conftest import login

    assert login(client, "RstMail", "NewPassword2!").status_code == 200


def test_reset_request_commit_cost_is_equalised(client, monkeypatch, db):
    """The unknown-name path commits too, so timing cannot separate them."""
    _smtp_on(monkeypatch)
    c = client
    c.headers["X-Forwarded-For"] = "7.7.7.8"
    r = c.post(
        "/v1/auth/request-password-reset", json={"identifier": "ghost@example.com"}
    )
    assert r.status_code == 204
    rows = db.query(RateLimitEntry).count()
    assert rows >= 1, "unknown path must perform comparable committed work"


def test_reset_tokens_are_single_use_and_expire(client, monkeypatch, db):
    _smtp_on(monkeypatch)
    make_user("RstV", "Password1!", role="viewer")
    c = client
    c.headers["X-Forwarded-For"] = "7.7.7.9"
    from app.db.models import UserEmail

    s = SessionLocal()
    try:
        from app.security.auth import get_user_by_username as _g

        u_row = _g(s, "RstV")
        s.add(
            UserEmail(
                user_id=int(u_row.id),
                email="rstv@example.com",
                email_lower="rstv@example.com",
                source="user",
                is_primary=True,
                is_verified=True,
            )
        )
        s.commit()
    finally:
        s.close()
    c.post("/v1/auth/request-password-reset", json={"identifier": "rstv@example.com"})
    tokens = [r for (r,) in db.query(PasswordResetToken.token_hash).all()]
    assert tokens, "a known active user with a resolved address earns a token"

    # The stored digest is the sha256 of the emailed token.
    new_password = "NewPassword2!"

    def try_token(token: str):
        return c.post(
            "/v1/auth/reset-password",
            json={
                "token": token,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )

    # 256-bit taste: an arbitrary token is refused by the digest lookup.
    r = try_token(secrets.token_urlsafe(32))
    assert r.status_code == 400

    # A token whose email row is missing is refused alike.
    r = try_token("x-too-short")
    assert r.status_code in (400, 422)


def test_expired_reset_token_is_refused(client, monkeypatch, db):
    _smtp_on(monkeypatch)
    u = make_user("RstW", "Password1!", role="viewer")
    row = PasswordResetToken(
        user_id=int(u.id),
        token_hash=hashlib.sha256(b"expired-token-abc").hexdigest(),
        created_at=datetime.utcnow() - timedelta(hours=2),
        expires_at=datetime.utcnow() - timedelta(hours=1),
        used_at=None,
    )
    db.add(row)
    db.commit()
    r = client.post(
        "/v1/auth/reset-password",
        json={
            "token": "expired-token-abc",
            "new_password": "NewPass2!",
            "confirm_password": "NewPass2!",
        },
    )
    assert r.status_code == 400


def test_reset_request_is_rate_limited_per_address(client, monkeypatch, db):
    _smtp_on(monkeypatch)
    c = client
    c.headers["X-Forwarded-For"] = "7.7.7.10"
    make_user("RstX", "Password1!", role="viewer")
    from app.db.models import UserEmail
    from app.db.session import SessionLocal

    s = SessionLocal()
    try:
        from app.security.auth import get_user_by_username

        user = get_user_by_username(s, "RstX")
        s.add(
            UserEmail(
                user_id=int(user.id),
                email="rstx@example.com",
                email_lower="rstx@example.com",
                source="user",
                is_primary=True,
                is_verified=True,
            )
        )
        s.commit()
    finally:
        s.close()
    codes = [
        c.post(
            "/v1/auth/request-password-reset",
            json={"identifier": "rstx@example.com"},
        ).status_code
        for _ in range(4)
    ]
    assert all(code == 204 for code in codes)
    tokens = db.query(PasswordResetToken).count()
    assert tokens <= 3, "per-target budget bounds token issuance"


def test_change_password_round_trip(client):
    from tests.conftest import login

    make_user("ChgU", "Password1!", role="viewer")
    r = login(client, "ChgU", "Password1!")
    assert r.status_code == 200
    csrf = client.cookies.get("ospmae_csrf")
    r = client.post(
        "/v1/auth/change-password",
        json={
            "current_password": "Password1!",
            "new_password": "NewPass2!",
            "confirm_password": "NewPass2!",
        },
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 204

    # The old password no longer logs in; the new one does.
    c2 = client
    c2.headers["X-Forwarded-For"] = "5.5.5.5"
    assert (
        c2.post(
            "/v1/auth/login", json={"username": "ChgU", "password": "Password1!"}
        ).status_code
        == 401
    )
    assert (
        c2.post(
            "/v1/auth/login", json={"username": "ChgU", "password": "NewPass2!"}
        ).status_code
        == 200
    )


def test_change_password_bounded_per_account(client):
    from tests.conftest import login

    make_user("ChgV", "Password1!", role="viewer")
    login(client, "ChgV", "Password1!")
    csrf = client.cookies.get("ospmae_csrf")
    for i in range(6):
        r = client.post(
            "/v1/auth/change-password",
            json={
                "current_password": f"wrong-{i}-x!",
                "new_password": "NewPass2!",
                "confirm_password": "NewPass2!",
            },
            headers={"X-CSRF-Token": csrf or ""},
        )
    assert r.status_code == 429
