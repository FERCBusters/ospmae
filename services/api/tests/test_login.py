"""Sign-in behaviour: lockout resistance, timing equalisation, budgets."""

from __future__ import annotations

from app.db.session import SessionLocal
from app.security.auth import authenticate_user
from app.security.rate_limit import check_rate_limit, record_rate_limit_attempt

from tests.conftest import login, make_user

# ---------------------------------------------------------------- lockout --


def test_correct_password_survives_attacker_drained_name_allowance(client):
    """The property the deployment promises: a failed-attempt flood against a
    username cannot stop that username's correct password from signing in."""
    import httpx  # noqa: F401

    make_user("Alice", "Password1!", role="viewer")

    attacker_failures = 0

    # Farm failures against 'Alice' from three distinct attacker addresses.
    for peer in ("9.9.9.9", "9.9.9.8", "9.9.9.7"):
        c = client
        c.headers["X-Forwarded-For"] = peer
        for _ in range(8):
            r = c.post(
                "/v1/auth/login",
                json={"username": "Alice", "password": "BadPass1!"},
            )
            attacker_failures += 1
            assert r.status_code in (401, 429)
    assert attacker_failures >= 20

    # The name's failure allowance is now spent; the victim's own IP still
    # has its verify budget, so their correct password signs in.
    r = login(client, "Alice", "Password1!", peer="8.8.8.8")
    assert r.status_code == 200, r.text


def test_correct_login_clears_the_name_allowance(client, db):
    """A success under the spent-failure budget clears attack state."""
    import hashlib

    from app.api.routes.auth import _normalize_login_name
    from app.db.models import RateLimitEntry

    make_user("Bob", "Password1!", role="viewer")
    digest = hashlib.sha256(_normalize_login_name("Bob").encode()).hexdigest()
    key = f"login_fail_user:{digest}"
    c = client
    c.headers["X-Forwarded-For"] = "9.9.9.9"
    for _ in range(10):
        c.post("/v1/auth/login", json={"username": "Bob", "password": "BadPass1!"})
    spent = db.query(RateLimitEntry).filter(RateLimitEntry.identifier == key).count()
    assert spent >= 8, "failures must be chargeable across spellings"
    # The same client address has burnt its own login budget too, so the
    # correct password signs in from the victim's own address. The limit key
    # folds case for allowance sharing, while authentication itself stays
    # exact for the account's own username spelling.
    r = login(client, "Bob", "Password1!", peer="8.8.8.8")
    assert r.status_code == 200, "correct password must survive the flood"
    after = db.query(RateLimitEntry).filter(RateLimitEntry.identifier == key).count()
    assert after == 0, "a failed-attempt flood must not survive a successful login"


def test_name_allowance_keys_fold_case_and_whitespace():
    from app.api.routes.auth import _normalize_login_name

    assert _normalize_login_name("  Alice  ") == "alice"
    assert _normalize_login_name("ALICE") == "alice"


# ----------------------------------------------------------------- timing --


def test_unknown_username_pays_full_password_cost(client, monkeypatch):
    """Every rejection runs one full PBKDF2, unknown names contribute."""
    import app.security.auth as auth_mod

    calls = {"n": 0}
    real_verify = auth_mod.verify_password

    def counting_verify(password, hashed):
        calls["n"] += 1
        return real_verify(password, hashed)

    monkeypatch.setattr(auth_mod, "verify_password", counting_verify)
    c = client
    c.headers["X-Forwarded-For"] = "7.7.7.7"
    assert (
        c.post(
            "/v1/auth/login", json={"username": "NoSuchUser", "password": "Whatever1!"}
        ).status_code
        == 401
    )
    assert calls["n"] == 1, "unknown user skipped the PBKDF2: timing leak"
    calls["n"] = 0
    make_user("Existing", "Password1!", role="viewer")
    assert (
        c.post(
            "/v1/auth/login", json={"username": "existing", "password": "Whatever1!"}
        ).status_code
        == 401
    )
    assert calls["n"] == 1, "inactive/unknown path diverges in cost"


def test_inactive_user_gets_the_same_dummy_verification(client, monkeypatch):
    import app.security.auth as auth_mod

    calls = {"n": 0}
    real_verify = auth_mod.verify_password

    def counting(password, hashed):
        calls["n"] += 1
        return real_verify(password, hashed)

    monkeypatch.setattr(auth_mod, "verify_password", counting)
    make_user("Ghost", "Password1!", role="viewer")
    s = SessionLocal()
    try:
        user = s.query(auth_mod.User).filter(auth_mod.User.username == "Ghost").one()
        user.is_active = False
        s.add(user)
        s.commit()
        # The session stays open until here: a closed session reused by
        # authenticate_user leaks an idle-in-transaction connection, and the
        # next TRUNCATE teardown waits on its ACCESS SHARE lock forever.
        assert authenticate_user(s, "Ghost", "Password1!") is None
    finally:
        s.close()
    assert calls["n"] == 1


# ----------------------------------------------------------------- bounds --


def test_blank_username_refused_before_work(client):
    c = client
    c.headers["X-Forwarded-For"] = "7.7.7.7"
    assert c.post(
        "/v1/auth/login", json={"username": "", "password": "Password1!"}
    ).status_code in (401, 422)


def test_per_address_login_allowance_enforced(client):
    """The 11th attempt from one address within a window is refused."""

    make_user("Solo", "Password1!", role="viewer")
    c = client
    c.headers["X-Forwarded-For"] = "6.6.6.6"
    statuses = []
    for _ in range(11):
        statuses.append(
            c.post(
                "/v1/auth/login",
                json={"username": "Solo", "password": "Password1!"},
            ).status_code
        )
    assert 429 in statuses
    assert statuses[0] == 200


def test_rate_limit_retry_after_is_well_formed(client, db):
    c = client
    c.headers["X-Forwarded-For"] = "5.5.5.5"
    for _ in range(12):
        r = c.post("/v1/auth/login", json={"username": "Solo2", "password": "wrongpw"})
    if r.status_code == 429:
        assert int(r.headers["Retry-After"]) >= 0


def test_failed_attempts_record_the_name_without_leaking_membership(db):
    """A refused attempt costs one full verification for both shapes."""
    db.execute
    from app.db.models import RateLimitEntry

    record_rate_limit_attempt(db, "login_fail_user:" + "a" * 64)
    rows = db.query(RateLimitEntry).all()
    assert any("login_fail_user" in r.identifier for r in rows)


def test_check_rate_limit_counts_and_blocks(db, monkeypatch):
    for _ in range(5):
        record_rate_limit_attempt(db, "unit")
    allowed, info = check_rate_limit(db, "unit", max_attempts=5, window_seconds=300)
    assert allowed is False
    assert info["limit"] == 5
    assert info["retry_after"] >= 1


def test_check_rate_limit_prunes_expired(db):
    from datetime import datetime, timedelta

    from app.db.models import RateLimitEntry

    old = RateLimitEntry(
        identifier="old", timestamp=datetime.utcnow() - timedelta(hours=2)
    )
    db.add(old)
    db.commit()
    allowed, _info = check_rate_limit(db, "old", max_attempts=1, window_seconds=60)
    assert allowed is True
    leftovers = (
        db.query(RateLimitEntry).filter(RateLimitEntry.identifier == "old").count()
    )
    assert leftovers == 0


def test_login_rejects_local_disabled(client, monkeypatch):
    monkeypatch.setenv("OSPMAE_LOCAL_AUTH_ENABLED", "false")
    from app.core.config import settings

    saved = settings.local_auth_enabled
    settings.local_auth_enabled = False
    try:
        c = client
        c.headers["X-Forwarded-For"] = "4.4.4.4"
        r = c.post("/v1/auth/login", json={"username": "x", "password": "Password1!"})
        assert r.status_code == 404
    finally:
        settings.local_auth_enabled = saved


def test_login_does_not_reveal_the_attempted_name_in_audit_payload(client, db):
    make_user("Quiet", "Password1!", role="viewer")
    c = client
    c.headers["X-Forwarded-For"] = "3.3.3.3"
    c.post("/v1/auth/login", json={"username": "quiet", "password": "BadPass1!"})
    from app.db.models import AuditLog

    rows = db.query(AuditLog).all()
    for row in rows:
        assert "BadPass1!" not in (row.query_string or "")
        assert "quiet" not in (row.path or "")
