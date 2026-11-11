"""Password sign-in: the shared throttling policy, equal-cost refusals, budgets.

Policy (app/security/sign_in_throttle.py, identical in KEEN): a browser that
has proved an account's password is heard whatever an attacker does from
elsewhere; every other browser shares the account's growing waits, and a
refused attempt never reaches password verification.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

import pytest
from app.db.models import LoginDevice, LoginThrottle, RateLimitEntry, User
from app.db.models import Session as SessionRow
from app.db.session import SessionLocal
from app.security import sign_in_throttle as throttle
from app.security.auth import authenticate_user
from app.security.rate_limit import check_rate_limit, record_rate_limit_attempt
from fastapi.testclient import TestClient

from tests.conftest import auth_client, make_user, peer_wrapper

PASSWORD = "Password1!"
WRONG = "BadPass1!"


def browser(peer: str = "8.8.8.8") -> TestClient:
    """A separate browser (its own cookie jar) behind the trusted proxy."""

    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    c.headers["X-Test-Peer"] = "127.0.0.1"
    c.headers["X-Forwarded-For"] = peer
    return c


def attempt(c: TestClient, username: str, password: str):
    return c.post("/v1/auth/login", json={"username": username, "password": password})


@pytest.fixture()
def verifications(monkeypatch):
    import app.security.auth as auth_mod

    seen: list[str] = []
    real = auth_mod.verify_password

    def counting(password, hashed):
        seen.append(password)
        return real(password, hashed)

    monkeypatch.setattr(auth_mod, "verify_password", counting)
    return seen


def user_id(name: str) -> int:
    with SessionLocal() as s:
        return s.query(User.id).filter(User.username == name).scalar()


def _throttle_row(name: str) -> LoginThrottle | None:
    with SessionLocal() as s:
        return s.get(LoginThrottle, throttle.name_key(name))


# ------------------------------------------------- the owner keeps signing in --


def test_recognised_browser_signs_in_while_the_account_is_under_attack(
    client, verifications
):
    make_user("Alice", PASSWORD, role="viewer")
    owner = browser("8.8.8.8")
    assert attempt(owner, "Alice", PASSWORD).status_code == 200
    assert owner.cookies.get(throttle.device_cookie_name())

    # An attacker spreads guesses over many addresses until the account's
    # unrecognised-browser throttle closes.
    for n in range(throttle.FREE_FAILURES + 1):
        refused = attempt(browser(f"9.9.9.{n}"), "Alice", WRONG)
        assert refused.status_code == 401
    held = attempt(browser("9.9.9.200"), "Alice", PASSWORD)
    assert held.status_code == 429
    assert held.json()["detail"] == throttle.LIMITED
    # The first gated wait is 30 seconds, less whatever has elapsed since.
    assert 1 <= held.json()["retry_after"] <= 30
    assert held.headers["Retry-After"] == str(held.json()["retry_after"])
    assert "set-cookie" not in held.headers

    # The owner's browser is heard throughout, and its success ends the count.
    verified = len(verifications)
    signed_in = attempt(owner, "Alice", PASSWORD)
    assert signed_in.status_code == 200, signed_in.text
    assert len(verifications) == verified + 1
    assert _throttle_row("Alice") is None


def test_refused_attempts_never_reach_password_verification(client, verifications):
    make_user("Bob", PASSWORD, role="viewer")
    for n in range(throttle.FREE_FAILURES + 1):
        assert attempt(browser(f"9.8.0.{n}"), "Bob", WRONG).status_code == 401
    verified = len(verifications)
    for password in (WRONG, PASSWORD):
        assert attempt(browser("9.8.1.1"), "Bob", password).status_code == 429
    assert len(verifications) == verified


def test_unknown_and_existing_names_are_throttled_alike(client):
    make_user("Carol", PASSWORD, role="viewer")
    answers = {}
    for name in ("Carol", "nobody-here"):
        seq = []
        for n in range(throttle.FREE_FAILURES + 2):
            r = attempt(browser(f"9.7.{len(answers)}.{n}"), name, WRONG)
            seq.append((r.status_code, r.json()))
        answers[name] = seq
    assert answers["Carol"] == answers["nobody-here"]
    assert [s for s, _ in answers["Carol"]] == [401] * 6 + [429]


def test_spellings_of_a_name_share_one_throttle(client):
    make_user("dave", PASSWORD, role="viewer")
    spellings = [
        "DAVE",
        " dave ",
        "ｄａｖｅ",  # fullwidth
        "da​ve",  # zero-width space
        "d­ave",  # soft hyphen
        "dave",
    ]
    for n, name in enumerate(spellings):
        assert attempt(browser(f"9.6.0.{n}"), name, WRONG).status_code == 401
    assert attempt(browser("9.6.1.1"), "dave", PASSWORD).status_code == 429
    assert throttle.login_name("  Ｄａｖｅ​  ") == "dave"


def test_a_device_cookie_speaks_only_for_its_own_username(client):
    make_user("Erin", PASSWORD, role="viewer")
    make_user("Frank", PASSWORD, role="viewer")
    shared = browser("8.8.4.4")
    assert attempt(shared, "Erin", PASSWORD).status_code == 200
    for n in range(throttle.FREE_FAILURES + 1):
        attempt(browser(f"9.5.0.{n}"), "Frank", WRONG)
    # Erin's recognition does not open Frank's throttle.
    assert attempt(shared, "Frank", PASSWORD).status_code == 429


def test_a_recognised_browser_loses_recognition_after_five_wrong_passwords(client):
    make_user("Gina", PASSWORD, role="viewer")
    owner = browser("8.8.8.8")
    assert attempt(owner, "Gina", PASSWORD).status_code == 200
    for _ in range(throttle.DEVICE_FAILURES):
        assert attempt(owner, "Gina", WRONG).status_code == 401
    with SessionLocal() as s:
        assert s.query(LoginDevice).count() == 0
        # The account's own count was untouched by the recognised browser.
        assert s.get(LoginThrottle, throttle.name_key("Gina")) is None
    # The browser now counts as unrecognised, and draws on the account.
    assert attempt(owner, "Gina", WRONG).status_code == 401
    assert _throttle_row("Gina").failures == 1


def test_device_cookie_shape_and_rotation(client):
    make_user("Hal", PASSWORD, role="viewer")
    owner = browser("8.8.8.8")
    first = attempt(owner, "Hal", PASSWORD)
    cookie = next(
        c
        for c in first.headers.get_list("set-cookie")
        if c.startswith(throttle.device_cookie_name() + "=")
    )
    assert throttle.device_cookie_name() == "__Host-ospmae_device"
    for part in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert part.lower() in cookie.lower()
    assert "domain=" not in cookie.lower()
    old_token = owner.cookies.get(throttle.device_cookie_name())

    assert attempt(owner, "Hal", PASSWORD).status_code == 200
    new_token = owner.cookies.get(throttle.device_cookie_name())
    assert new_token != old_token
    with SessionLocal() as s:
        stored = [d.token_hash for d in s.query(LoginDevice).all()]
    # Only a digest of the newest token is kept.
    assert stored == [throttle._token_hash(new_token)]
    assert old_token not in stored and new_token not in stored


def test_an_account_keeps_its_newest_recognised_browsers_only(client, db):
    make_user("Ivy", PASSWORD, role="viewer")
    now = datetime.utcnow()
    for n in range(throttle.DEVICES_PER_ACCOUNT + 3):
        throttle.issue_device(
            db,
            user_id=user_id("Ivy"),
            key=throttle.name_key("Ivy"),
            now=now + timedelta(seconds=n),
        )
        db.commit()
    assert db.query(LoginDevice).count() == throttle.DEVICES_PER_ACCOUNT
    oldest = db.query(LoginDevice).order_by(LoginDevice.created_at).first()
    assert oldest.created_at == now + timedelta(seconds=3)


def test_expired_or_oversized_device_tokens_are_not_recognised(db):
    make_user("Jay", PASSWORD, role="viewer")
    key = throttle.name_key("Jay")
    now = datetime.utcnow()
    token = throttle.issue_device(db, user_id=user_id("Jay"), key=key, now=now)
    db.commit()
    assert throttle.recognised_device(db, token, key, now) is not None
    assert throttle.recognised_device(db, token, key, now + timedelta(days=91)) is None
    assert throttle.recognised_device(db, token, throttle.name_key("x"), now) is None
    assert throttle.recognised_device(db, "x" * 129, key, now) is None
    assert throttle.recognised_device(db, None, key, now) is None


# ------------------------------------------------------- the waiting schedule --


def test_unrecognised_waits_grow_to_an_hour_and_stop_at_the_ceiling(db):
    key = throttle.name_key("schedule")
    t0 = datetime(2026, 1, 1)
    for n in range(throttle.FREE_FAILURES):
        assert throttle.reserve_unrecognised_attempt(db, key, t0) == (True, 0)

    now = t0
    expected_waits = [30, 60, 120, 240, 480, 960, 1920, 3600, 3600]
    for wait in expected_waits:
        assert throttle.reserve_unrecognised_attempt(db, key, now) == (True, 0)
        # Within the wait every attempt is refused with the time remaining.
        assert throttle.reserve_unrecognised_attempt(
            db, key, now + timedelta(seconds=wait - 1)
        ) == (False, 1)
        now += timedelta(seconds=wait)

    row = db.get(LoginThrottle, key)
    db.refresh(row)
    assert row.failures == throttle.FREE_FAILURES + len(expected_waits)

    # At the ceiling no wait is long enough; recovery has to end it.
    row.failures = throttle.FAILURE_CEILING
    row.gate_until = None
    db.commit()
    later = now + timedelta(days=29)
    assert throttle.reserve_unrecognised_attempt(db, key, later) == (
        False,
        throttle.MAX_WAIT_SECONDS,
    )
    # Thirty days after the last failure the count is forgotten.
    forgotten = row.last_failure_at + timedelta(days=30, seconds=1)
    assert throttle.reserve_unrecognised_attempt(db, key, forgotten) == (True, 0)
    db.refresh(row)
    assert row.failures == 1


def test_wait_schedule_values():
    assert [throttle.wait_seconds(n) for n in range(5)] == [0] * 5
    assert throttle.wait_seconds(5) == 30
    assert throttle.wait_seconds(11) == 1920
    assert throttle.wait_seconds(12) == 3600
    assert throttle.wait_seconds(99) == 3600


def test_concurrent_attempts_cannot_share_one_opening():
    """Two attempts racing for the first gated slot: exactly one is heard."""

    key = throttle.name_key("racer")
    now = datetime.utcnow()
    with SessionLocal() as s:
        s.add(
            LoginThrottle(
                name_key=key,
                failures=throttle.FREE_FAILURES,
                gate_until=None,
                last_failure_at=now,
            )
        )
        s.commit()

    barrier = threading.Barrier(2)
    results: list[tuple[bool, int]] = []

    def race():
        with SessionLocal() as s:
            barrier.wait()
            results.append(throttle.reserve_unrecognised_attempt(s, key, now))

    threads = [threading.Thread(target=race) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sorted(results) == [(False, 30), (True, 0)]


# --------------------------------------------------------------- recoveries --


def test_an_administrators_reset_clears_the_throttle_and_ends_sessions_and_devices(
    client, db
):
    make_user("Kim", PASSWORD, role="viewer")
    kim = user_id("Kim")
    owner = browser("8.8.8.8")
    assert attempt(owner, "Kim", PASSWORD).status_code == 200
    for n in range(throttle.FREE_FAILURES + 1):
        attempt(browser(f"9.4.0.{n}"), "Kim", WRONG)
    assert attempt(browser("9.4.1.1"), "Kim", PASSWORD).status_code == 429

    admin, _ = auth_client("kim-admin", PASSWORD, role="admin")
    reset = admin.post(
        f"/v1/admin/users/{kim}/password",
        json={"new_password": "NewPassword2!"},
        headers={"X-CSRF-Token": admin.cookies.get("ospmae_csrf")},
    )
    assert reset.status_code == 200, reset.text
    assert owner.get("/v1/auth/check").status_code == 401
    with SessionLocal() as s:
        assert s.query(LoginDevice).filter_by(user_id=kim).count() == 0
    assert _throttle_row("Kim") is None
    # Any browser now signs in with the new password straight away.
    assert attempt(browser("9.4.1.2"), "Kim", "NewPassword2!").status_code == 200


def test_password_change_ends_every_session_and_every_recognition(client):
    make_user("Lee", PASSWORD, role="viewer")
    here = browser("8.8.8.8")
    elsewhere = browser("8.8.8.7")
    assert attempt(elsewhere, "Lee", PASSWORD).status_code == 200
    # Sign-in is single-session per account, so sign in here last and give
    # the other browser a session again directly.
    assert attempt(here, "Lee", PASSWORD).status_code == 200
    from app.security.sessions import create_session

    lee = user_id("Lee")
    with SessionLocal() as s:
        other_sid = create_session(s, user_id=lee, ttl_seconds=600)
    elsewhere.cookies.set("ospmae_session", other_sid, domain="testserver.local")
    assert elsewhere.get("/v1/auth/check").status_code == 204
    changed = here.post(
        "/v1/auth/change-password",
        json={
            "current_password": PASSWORD,
            "new_password": "NewPassword2!",
            "confirm_password": "NewPassword2!",
        },
        headers={"X-CSRF-Token": here.cookies.get("ospmae_csrf")},
    )
    assert changed.status_code == 204, changed.text
    with SessionLocal() as s:
        devices = s.query(LoginDevice).filter_by(user_id=lee).all()
    assert devices == []
    # As in KEEN, this browser signs in again too.
    assert here.get("/v1/auth/check").status_code == 401
    assert elsewhere.get("/v1/auth/check").status_code == 401


def test_a_password_without_its_second_factor_signs_no_one_out(client, db, monkeypatch):
    """Earlier sessions end only when sign-in completes, factor included."""

    from app.core.config import settings

    monkeypatch.setattr(
        settings, "mfa_encryption_key", "kw0nbN6bJuWBIBG2F91GoVvw1bLXCT7Fz8i9CSaj-e0="
    )
    monkeypatch.setattr(settings, "public_base_url", "https://testserver")

    make_user("Mo", PASSWORD, role="viewer")
    owner = browser("8.8.8.8")
    assert attempt(owner, "Mo", PASSWORD).status_code == 200
    with SessionLocal() as s:
        user = s.query(User).filter_by(username="Mo").one()
        user.mfa_enabled = True
        s.commit()
    saved = settings.mfa_policy
    try:
        intruder = browser("9.3.0.1").post(
            "/v1/auth/login",
            json={"username": "Mo", "password": PASSWORD},
            headers={"Origin": "https://testserver"},
        )
    finally:
        settings.mfa_policy = saved
    assert intruder.status_code == 200
    assert intruder.json().get("mfa_required") is True
    # The owner's session row is untouched by a ceremony that never finished.
    with SessionLocal() as s:
        assert s.query(SessionRow).filter_by(user_id=user_id("Mo")).count() == 1


# ----------------------------------------------------- per-address allowance --


def test_one_address_cannot_spray_many_usernames(client):
    spray = browser("6.6.6.6")
    statuses = [
        attempt(spray, f"guess-{n}", WRONG).status_code
        for n in range(throttle.ADDRESS_ATTEMPTS + 1)
    ]
    assert statuses == [401] * throttle.ADDRESS_ATTEMPTS + [429]


def test_recognised_browsers_skip_their_address_allowance(client):
    make_user("Ned", PASSWORD, role="viewer")
    owner = browser("6.6.6.7")
    assert attempt(owner, "Ned", PASSWORD).status_code == 200
    # A neighbour on the same address spends its whole allowance.
    neighbour = browser("6.6.6.7")
    for n in range(throttle.ADDRESS_ATTEMPTS):
        attempt(neighbour, f"guess-{n}", WRONG)
    assert attempt(neighbour, "guess-x", WRONG).status_code == 429
    assert attempt(owner, "Ned", PASSWORD).status_code == 200


def test_ipv6_addresses_in_one_slash64_share_an_allowance(client):
    statuses = [
        attempt(browser(f"2001:db8::{n:x}"), f"v6-{n}", WRONG).status_code
        for n in range(throttle.ADDRESS_ATTEMPTS + 1)
    ]
    assert statuses[-1] == 429
    assert attempt(browser("2001:db8:1::1"), "v6-other", WRONG).status_code == 401


# ---------------------------------------------------------------- timing ----


def test_unknown_username_pays_full_password_cost(client, verifications):
    """Every rejection runs one full PBKDF2, unknown names included."""

    assert attempt(browser("7.7.7.7"), "NoSuchUser", "Whatever1!").status_code == 401
    assert len(verifications) == 1
    make_user("Existing", PASSWORD, role="viewer")
    assert attempt(browser("7.7.7.8"), "existing", "Whatever1!").status_code == 401
    assert len(verifications) == 2


def test_inactive_user_gets_the_same_dummy_verification(client, verifications):
    make_user("Ghost", PASSWORD, role="viewer")
    s = SessionLocal()
    try:
        user = s.query(User).filter(User.username == "Ghost").one()
        user.is_active = False
        s.commit()
        assert authenticate_user(s, "Ghost", PASSWORD) is None
    finally:
        s.close()
    assert verifications == [PASSWORD]


@pytest.mark.parametrize(
    ("name", "status"), [("", 422), ("   ", 401), ("\u200b\u200b", 401)]
)
def test_blank_usernames_are_refused_before_any_work(
    client, verifications, name, status
):
    r = attempt(browser("7.7.7.9"), name, PASSWORD)
    assert r.status_code == status
    if status == 401:
        assert r.json() == {"detail": "Invalid username or password"}
    assert verifications == []
    with SessionLocal() as s:
        assert s.query(LoginThrottle).count() == 0
        assert s.query(RateLimitEntry).count() == 0


def test_login_rejects_local_disabled(client, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "local_auth_enabled", False)
    r = attempt(browser("4.4.4.4"), "x", PASSWORD)
    assert (r.status_code, r.json()) == (404, {"detail": "Local auth disabled"})


def test_the_ledger_stores_digests_never_names_or_passwords(client, db):
    attempt(browser("3.3.3.3"), "secret-name", "secret-password")
    stored = " ".join(
        [r.identifier for r in db.query(RateLimitEntry).all()]
        + [r.name_key for r in db.query(LoginThrottle).all()]
    )
    assert "secret" not in stored
    assert throttle.name_key("secret-name") in stored


# ------------------------------------------------------------ rate limiter --


def test_check_rate_limit_counts_and_blocks(db):
    for _ in range(5):
        record_rate_limit_attempt(db, "unit")
    allowed, info = check_rate_limit(db, "unit", max_attempts=5, window_seconds=300)
    assert allowed is False
    assert info["limit"] == 5
    assert 1 <= info["retry_after"] <= 300_000


def test_check_rate_limit_prunes_expired(db):
    db.add(
        RateLimitEntry(
            identifier="old", timestamp=datetime.utcnow() - timedelta(hours=2)
        )
    )
    db.commit()
    allowed, _info = check_rate_limit(db, "old", max_attempts=1, window_seconds=60)
    assert allowed is True
    assert db.query(RateLimitEntry).filter_by(identifier="old").count() == 0
