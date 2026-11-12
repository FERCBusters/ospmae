"""The rules a new password meets, and the work a stored one costs to check.

A new password needs the length NIST SP 800-63B-4 asks of a single factor and
is compared with passwords that are commonly used or expected here. Stored
hashes use OWASP's PBKDF2 work factor; one stored with fewer iterations costs
the same to refuse, and is replaced when its account next signs in. The rules
and the work factor are KEEN's.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from app.core.config import Settings, settings
from app.db.models import User
from app.db.session import SessionLocal
from app.security import auth, passwords
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tests.conftest import auth_client, login, make_user, peer_wrapper
from tests.support import csrf

PASSWORD = "Test-passphrase-1!"
LEGACY_ITERATIONS = 260_000


def legacy_hash(password, iterations=LEGACY_ITERATIONS):
    """A hash as OSPMAE stored it before the work factor rose."""
    salt = b"sixteen-byte-salt"
    digest = passwords._pbkdf2_sha256(password, salt, iterations)
    return "$".join(
        [
            "pbkdf2_sha256",
            str(iterations),
            passwords._b64u_encode(salt),
            passwords._b64u_encode(digest),
        ]
    )


def fresh_browser() -> TestClient:
    """A browser that has never signed in, behind the trusted proxy."""
    from app.main import app

    return TestClient(peer_wrapper(app), base_url="https://testserver")


def stored_hash(user_id: int) -> str:
    with SessionLocal() as db:
        return db.get(User, user_id).password_hash


def store_hash(user_id: int, value: str) -> None:
    with SessionLocal() as db:
        db.get(User, user_id).password_hash = value
        db.commit()


# -- the rules ------------------------------------------------------------------


@pytest.mark.parametrize(
    "password,problem",
    [
        ("fourteen-chars", "Password must be at least 15 characters"),
        ("x" * 1025, "Password must be at most 1024 characters"),
        (" " * 15, "Password repeats too few characters; choose a longer phrase"),
        ("a" * 16, "Password repeats too few characters; choose a longer phrase"),
        ("ab12" * 4, "Password repeats too few characters; choose a longer phrase"),
        ("π" * 15, "Password repeats too few characters; choose a longer phrase"),
        (
            "123456789012345",
            "Password is a keyboard or counting sequence; choose a phrase",
        ),
        (
            "987654321098765",
            "Password is a keyboard or counting sequence; choose a phrase",
        ),
        (
            "ABCDEFGHIJKLMNOPQ",
            "Password is a keyboard or counting sequence; choose a phrase",
        ),
        (
            "qwertyuiopasdfghj",
            "Password is a keyboard or counting sequence; choose a phrase",
        ),
        (
            "passwordpassword",
            "Password is too common; choose a phrase of several unrelated words",
        ),
        (
            "Password123456!",
            "Password is too common; choose a phrase of several unrelated words",
        ),
        (
            "P@ssw0rd-2026-11",
            "Password is too common; choose a phrase of several unrelated words",
        ),
        (
            "admin admin admin",
            "Password is too common; choose a phrase of several unrelated words",
        ),
        (
            "Correct Horse Battery Staple",
            "Password is too common; choose a phrase of several unrelated words",
        ),
        (
            "<<<changeme>>>!!",
            "Password is too common; choose a phrase of several unrelated words",
        ),
        (
            # The example an earlier README printed in its account-creation command.
            "SomethingStrongHere!",
            "Password is too common; choose a phrase of several unrelated words",
        ),
        (
            "Ospmae-Admin-2026!",
            "Password is too common; choose a phrase of several unrelated words",
        ),
    ],
)
def test_a_guessable_new_password_is_refused_with_its_reason(password, problem):
    assert passwords.new_password_problem(password) == problem
    with pytest.raises(ValueError) as refused:
        passwords.hash_password(password)
    assert str(refused.value) == problem


@pytest.mark.parametrize(
    "password",
    [
        "unique π password",
        "ünïcödé-påsswörd",  # sixteen code points, more as bytes
        "synthetic-password-for-tests",
        "tide-lantern-oak-91",
        "x7Qp-2mLw-9zRk-4T",
    ],
)
def test_a_long_unremarkable_password_is_accepted_whatever_its_characters(password):
    assert passwords.new_password_problem(password) is None
    assert passwords.verify_password(password, passwords.hash_password(password))


def test_a_password_may_not_contain_its_accounts_username():
    problem = "Password must not contain the username"
    assert (
        passwords.new_password_problem("riley-walks-at-dawn", username=" Riley ")
        == problem
    )
    with pytest.raises(ValueError, match="^" + problem + "$"):
        passwords.hash_password("RILEY-walks-at-dawn", username="riley")
    # A name too short to be told from ordinary text is not looked for.
    assert passwords.new_password_problem("new-walks-at-dawn-91", username="new") is (
        None
    )
    assert passwords.new_password_problem("riley-walks-at-dawn") is None


def test_the_minimum_length_follows_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "password_min_length", 8)
    assert passwords.new_password_problem("tide-oak") is None
    assert passwords.new_password_problem("tide-oa") == (
        "Password must be at least 8 characters"
    )


@pytest.mark.parametrize(
    "values,accepted",
    [
        ({}, True),
        ({"password_min_length": 15, "mfa_policy": "optional"}, True),
        ({"password_min_length": 8, "mfa_policy": "all"}, True),
        ({"password_min_length": 14, "mfa_policy": "optional"}, False),
        ({"password_min_length": 8, "mfa_policy": "admins"}, False),
        ({"password_min_length": 7, "mfa_policy": "all"}, False),
    ],
)
def test_a_shorter_minimum_needs_a_second_factor_on_every_account(values, accepted):
    if accepted:
        assert Settings(**values).password_min_length == values.get(
            "password_min_length", 15
        )
        return
    with pytest.raises(ValidationError):
        Settings(**values)


def test_setting_a_password_applies_the_rules_through_the_api(monkeypatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    admin, _ = auth_client(role="admin")
    common = "Password is too common; choose a phrase of several unrelated words"
    named = "Password must not contain the username"

    created = admin.post(
        "/v1/admin/users",
        headers=csrf(admin),
        json={
            "username": "morgan",
            "password": "morgan-walks-at-dawn",
            "role": "viewer",
        },
    )
    assert (created.status_code, created.json()) == (400, {"detail": named})
    with SessionLocal() as db:
        assert db.query(User).filter_by(username="morgan").count() == 0

    owner, target = auth_client(username="riley", password=PASSWORD, role="viewer")
    before = stored_hash(target.id)
    for new_password, detail in [
        ("passwordpassword", common),
        ("riley-walks-at-dawn", named),
        ("fourteen-chars", "Password must be at least 15 characters"),
    ]:
        reset = admin.post(
            f"/v1/admin/users/{target.id}/password",
            headers=csrf(admin),
            json={"new_password": new_password},
        )
        assert (reset.status_code, reset.json()) == (400, {"detail": detail})

    for new_password, detail in [
        ("Password123456!", common),
        ("RILEY-walks-at-dawn", named),
        ("ospmae ospmae ospmae", common),
    ]:
        changed = owner.post(
            "/v1/auth/change-password",
            headers=csrf(owner),
            json={
                "current_password": PASSWORD,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )
        assert (changed.status_code, changed.json()) == (400, {"detail": detail})
    # Every refusal left the password, the session and the account as they were.
    assert stored_hash(target.id) == before
    assert owner.get("/v1/me").status_code == 200

    # A password longer than the sign-in form accepts is refused as invalid.
    too_long = owner.post(
        "/v1/auth/change-password",
        headers=csrf(owner),
        json={
            "current_password": PASSWORD,
            "new_password": "x" * 1025,
            "confirm_password": "x" * 1025,
        },
    )
    assert too_long.status_code == 422
    assert stored_hash(target.id) == before


def test_the_longest_password_that_can_be_set_can_be_typed():
    """The sign-in form accepts every length a new password may have."""
    longest = "tide lantern oak " * 60 + "abcd"
    assert len(longest) == passwords.MAX_PASSWORD_LENGTH
    user = make_user("longhand", longest, role="viewer")
    client = fresh_browser()
    assert login(client, user.username, longest, peer="7.7.7.7").status_code == 200
    assert (
        login(client, user.username, longest + "c", peer="7.7.7.7").status_code == 422
    )


# -- the work factor --------------------------------------------------------------


def test_new_hashes_use_the_current_work_factor():
    assert passwords._DEFAULT_ITERS == 600_000
    stored = passwords.derive_password_hash("x")
    assert stored.split("$")[:2] == ["pbkdf2_sha256", "600000"]
    assert passwords.needs_rehash(stored) is False
    assert passwords.needs_rehash(legacy_hash("x")) is True
    assert passwords.needs_rehash("not-a-hash") is False
    with pytest.raises(ValueError, match="^Password is required$"):
        passwords.derive_password_hash("")


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "not-a-hash",
        "pbkdf2_sha256$600000$only-three-parts",
        "bcrypt$600000$c2FsdA$ZGlnZXN0",
        "pbkdf2_sha256$many$c2FsdA$ZGlnZXN0",
        "pbkdf2_sha256$0$c2FsdA$ZGlnZXN0",
        "pbkdf2_sha256$-5$c2FsdA$ZGlnZXN0",
        "pbkdf2_sha256$600000$$ZGlnZXN0",
        "pbkdf2_sha256$600000$c2FsdA$",
        "pbkdf2_sha256$600000$c2FsdA$Zm9v\u00e9",
    ],
)
def test_a_stored_value_that_is_no_hash_verifies_nothing(stored):
    """Whatever a password column holds, only a well-formed hash can match."""
    assert passwords.verify_password("any-password-at-all", stored) is False
    assert passwords.needs_rehash(stored) is False


def test_no_password_matches_without_being_given():
    stored = passwords.derive_password_hash("the-right-password")
    assert passwords.verify_password("", stored) is False
    assert passwords.verify_password("the-right-password", stored) is True


@pytest.mark.parametrize("password", ["a-wrong-password", "the-right-password"])
def test_an_older_hash_costs_the_current_work_to_check(monkeypatch, password):
    stored = legacy_hash("the-right-password")
    derive = Mock(wraps=passwords._pbkdf2_sha256)
    monkeypatch.setattr(passwords, "_pbkdf2_sha256", derive)

    matched = passwords.verify_password(password, stored)

    assert matched is (password == "the-right-password")
    spent = [call.args[2] for call in derive.call_args_list]
    assert spent == [LEGACY_ITERATIONS, passwords._DEFAULT_ITERS - LEGACY_ITERATIONS]
    # The original defect this guards: without the second derivation, a refused
    # attempt on an older account would cost less than one on an unknown name.
    assert sum(spent) == passwords._DEFAULT_ITERS


def test_a_correct_password_replaces_an_older_hash_once():
    user = make_user("legacy", PASSWORD, role="viewer")
    old = legacy_hash(PASSWORD)
    store_hash(user.id, old)
    client = fresh_browser()

    refused = login(client, "legacy", "not-the-password", peer="7.7.7.1")
    assert refused.status_code == 401
    assert stored_hash(user.id) == old

    assert login(client, "legacy", PASSWORD, peer="7.7.7.1").status_code == 200
    replaced = stored_hash(user.id)
    assert replaced != old and passwords.needs_rehash(replaced) is False
    assert passwords.verify_password(PASSWORD, replaced) is True
    # The session made with the rehash keeps working.
    assert client.get("/v1/me").json()["username"] == "legacy"

    assert login(client, "legacy", PASSWORD, peer="7.7.7.1").status_code == 200
    assert stored_hash(user.id) == replaced


def test_a_rehash_never_undoes_a_password_changed_meanwhile():
    user = make_user("racing", PASSWORD, role="viewer")
    store_hash(user.id, legacy_hash(PASSWORD))
    changed = passwords.hash_password("a-newer-synthetic-passphrase")
    with SessionLocal() as db:
        verified = db.get(User, user.id)
        assert verified.password_hash == legacy_hash(PASSWORD)
        # Another request changes the password after this one verified the
        # old one.
        with SessionLocal() as other:
            other.get(User, user.id).password_hash = changed
            other.commit()

        auth._raise_work_factor(db, verified, PASSWORD)

    assert stored_hash(user.id) == changed


def test_a_second_factor_ceremony_survives_the_rehash_of_its_password(monkeypatch):
    """The rehash happens before the ceremony starts, so the ceremony is made
    against the new hash and the person finishes signing in."""
    from cryptography.fernet import Fernet

    monkeypatch.setattr(settings, "public_base_url", "https://testserver")
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "mfa_policy", "all")
    user = make_user("ceremony", PASSWORD, role="viewer")
    store_hash(user.id, legacy_hash(PASSWORD))
    client = fresh_browser()
    client.headers["Origin"] = "https://testserver"

    started = login(client, "ceremony", PASSWORD, peer="7.7.7.2")
    assert started.json()["mfa_required"] is True
    assert passwords.needs_rehash(stored_hash(user.id)) is False
    state = client.post("/v1/auth/mfa/state", json={})
    assert (state.status_code, state.json()["stage"]) == (200, "enrol")
