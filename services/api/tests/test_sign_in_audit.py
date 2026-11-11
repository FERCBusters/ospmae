"""Sign-in audit rows: one per attempt, naming the account it reached."""

from __future__ import annotations

from urllib.parse import parse_qs

from app.db.models import AuditLog, User
from app.db.session import SessionLocal
from app.security import sign_in_throttle as throttle

from tests.conftest import login, make_user

PASSWORD = "Audit-Pass-123!"


def _sign_in_rows():
    with SessionLocal() as db:
        return [
            (row.username, parse_qs(row.query_string or ""), row.client_ip)
            for row in db.query(AuditLog)
            .filter_by(path="/action/sign-in")
            .order_by(AuditLog.ts, AuditLog.id)
        ]


def _outcome(method, outcome):
    return {"method": [method], "outcome": [outcome]}


def test_each_attempt_names_the_account_it_reached(client):
    make_user("audited", PASSWORD, role="viewer")
    assert (
        login(client, "audited", "wrong-password", peer="203.0.113.10").status_code
        == 401
    )
    assert (
        login(client, "nobody", "wrong-password", peer="203.0.113.10").status_code
        == 401
    )
    assert login(client, "audited", PASSWORD, peer="203.0.113.10").status_code == 200
    assert _sign_in_rows() == [
        ("audited", _outcome("local", "failed"), "203.0.113.10"),
        # A name that matches no account is never stored.
        (None, _outcome("local", "failed"), "203.0.113.10"),
        ("audited", _outcome("local", "success"), "203.0.113.10"),
    ]


def test_refusals_by_the_limits_add_no_sign_in_row(client):
    make_user("limited", PASSWORD, role="viewer")
    for _ in range(throttle.FREE_FAILURES + 1):
        client.cookies.clear()
        assert login(client, "limited", "wrong-password").status_code == 401
    client.cookies.clear()
    assert login(client, "limited", PASSWORD).status_code == 429
    rows = _sign_in_rows()
    assert len(rows) == throttle.FREE_FAILURES + 1
    assert {outcome["outcome"][0] for _, outcome, _ in rows} == {"failed"}


def test_a_password_alone_does_not_count_as_signing_in(client, monkeypatch):
    from app.core.config import settings
    from cryptography.fernet import Fernet

    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "public_base_url", "https://testserver")
    make_user("second-factor", PASSWORD, role="viewer")
    with SessionLocal() as db:
        user = db.query(User).filter_by(username="second-factor").one()
        user.mfa_enabled = True
        db.commit()
    client.headers["Origin"] = "https://testserver"
    response = login(client, "second-factor", PASSWORD)
    assert response.status_code == 200
    assert response.json() == {"mfa_required": True, "next": "/mfa.html"}
    with SessionLocal() as db:
        assert (
            db.query(User).filter_by(username="second-factor").one().last_login_at
            is None
        )
    assert _sign_in_rows() == []
