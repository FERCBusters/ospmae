"""Local second-factor behaviour through the assembled application.

Covers TOTP enrolment and verification, recovery codes, the WebAuthn
registration/assertion flow against a fabricated authenticator (real EC
signatures, hand-rolled CBOR for the attestation shape), ceremony lifecycle
guards and the session-refusal semantics of enrolment changes. Rate-limit
allowances are exercised through the same database-backed ledger production
uses, so the suite changes database contents like the rest of the run.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import datetime, timedelta

import pyotp
import pytest
from app.core.config import settings
from app.db.models import MfaChallenge, MfaRecoveryCode, RateLimitEntry, User
from app.db.session import SessionLocal
from app.security import mfa
from app.security.sessions import session_row
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from tests.conftest import auth_client, login, make_user

ORIGIN = "https://testserver"
PASSWORD = "Pass-current-long1!"
INVALID_CODE = (400, {"detail": "Invalid or already-used code"})
EXPIRED = (401, {"detail": "Verification expired; start again"})
ACCEPTED = (200, {"ok": True})
ORIGIN_REFUSED = (403, {"detail": "Authentication request origin is not allowed"})
# Every write from a foreign origin is refused before any route runs.
CROSS_SITE_REFUSED = (403, {"detail": "Request origin is not allowed"})
NOT_VERIFIED = (403, {"detail": "Verify your existing second factor first"})
CODES_REFUSED = (
    401,
    {
        "detail": "Too many incorrect codes; sign in again in an hour, or use a security key"
    },
)
KEY_REFUSED = (
    400,
    {"detail": "Security key verification failed; request another challenge"},
)


@pytest.fixture(autouse=True)
def mfa_environment(monkeypatch):
    monkeypatch.setattr(settings, "mfa_policy", "optional")
    monkeypatch.setattr(settings, "public_base_url", ORIGIN)
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "local_auth_enabled", True)


def outcome(response):
    return response.status_code, response.json()


def post_mfa(client, path, data=None):
    headers = {"Origin": ORIGIN}
    csrf = client.cookies.get("__Host-ospmae_csrf")
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return client.post("/v1/auth/mfa/" + path, json=data or {}, headers=headers)


def sign_in(user):
    """A TestClient with the account's session, CSRF cookie and Origin set."""
    from app.main import app as application
    from fastapi.testclient import TestClient

    from tests.conftest import peer_wrapper

    c = TestClient(peer_wrapper(application), base_url="https://testserver")
    response = login(c, user.username, PASSWORD)
    assert response.status_code == 200 and "csrf_token" in response.json(), (
        response.text
    )
    c.headers["X-Forwarded-For"] = "8.8.8.8"
    c.headers["Origin"] = ORIGIN
    return c


def start_manage(client, user):
    """Enter the ceremony's manage stage through the account flow."""
    response = client.post(
        "/v1/auth/mfa/manage/start",
        json={"password": PASSWORD},
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": client.cookies.get("__Host-ospmae_csrf"),
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["mfa_required"] is True
    assert response.json()["next"] == "/mfa.html?purpose=manage"


def set_enabled(user_id: int, enabled: bool) -> None:
    with SessionLocal() as db:
        db.get(User, user_id).mfa_enabled = enabled
        db.commit()


def totp_secret(user_id: int) -> str | None:
    with SessionLocal() as db:
        return db.get(User, user_id, populate_existing=True).mfa_totp_secret


def drop_sessions(user_id: int, client=None) -> None:
    from app.security.sessions import delete_all_sessions_for_user

    with SessionLocal() as db:
        delete_all_sessions_for_user(db, user_id)
    if client is not None:
        client.cookies.clear()


def reset_totp_step(user_id: int) -> None:
    """The enrolment code consumed the only current step when enrolled."""
    with SessionLocal() as db:
        db.get(User, user_id).mfa_totp_last_step = -1
        db.commit()


def enrol_totp(client) -> list[str]:
    response = post_mfa(client, "totp/start")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["secret"] and payload["qr"].startswith("data:image/svg+xml;base64,")
    confirm = post_mfa(
        client, "totp/confirm", {"code": pyotp.TOTP(payload["secret"]).now()}
    )
    assert confirm.status_code == 200, confirm.text
    codes = confirm.json()["recovery_codes"]
    assert len(codes) == 10
    assert all(len(c.replace("-", "")) == 32 for c in codes)
    return codes


# ---------------------------------------------------------------------------
# CBOR minimal encoder: the exact subset the WebAuthn library parses for the
# fabricated authenticator's attestation (small int keys, bytes, strings and
# one empty map).
# ---------------------------------------------------------------------------


def _cbor_header(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) + length])
    if length <= 0xFF:
        return bytes([(major << 5) + 24, length])
    if length <= 0xFFFF:
        return bytes([(major << 5) + 25]) + length.to_bytes(2, "big")
    raise NotImplementedError(length)


def _cbor_int(value: int) -> bytes:
    if value >= 0:
        if value < 24:
            return bytes([value])
        if value <= 0xFF:
            return bytes([0x18, value])
        if value <= 0xFFFF:
            return bytes([0x19]) + value.to_bytes(2, "big")
        raise NotImplementedError(value)
    n = -1 - value
    if n < 24:
        return bytes([0x20 + n])
    if n <= 0xFF:
        return bytes([0x38, n])
    if n <= 0xFFFF:
        return bytes([0x39]) + n.to_bytes(2, "big")
    raise NotImplementedError(n)


def _cbor_str(value: str) -> bytes:
    return _cbor_header(3, len(raw := value.encode())) + raw


def _cbor_bytes(value: bytes) -> bytes:
    return _cbor_header(2, len(value)) + value


def _cbor_map(pairs) -> bytes:
    out = bytes([0xA0 + len(pairs)])
    for key, value in pairs:
        out += _cbor_int(key) if isinstance(key, int) else _cbor_str(key)
        if isinstance(value, int):
            out += _cbor_int(value)
        elif isinstance(value, bytes):
            out += _cbor_bytes(value)
        elif isinstance(value, str):
            out += _cbor_str(value)
        elif isinstance(value, dict):
            out += _cbor_map(list(value.items()))
        else:
            raise NotImplementedError(type(value))
    return out


class FakeKey:
    """A fabricated WebAuthn authenticator with a real EC P-256 key."""

    def __init__(self, rp_host: str = "testserver"):
        self.rp_host = rp_host
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.cid = os.urandom(32)
        public = self.private.public_key().public_numbers()
        self._cose = _cbor_map(
            [
                (1, 2),
                (3, -7),
                (-1, 1),
                (-2, public.x.to_bytes(32, "big")),
                (-3, public.y.to_bytes(32, "big")),
            ]
        )

    def registration(self, options) -> dict:
        client = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": options["challenge"],
                "origin": ORIGIN,
                "crossOrigin": False,
            }
        ).encode()
        authdata = (
            hashlib.sha256(self.rp_host.encode()).digest()
            + b"\x41"  # UP | AT
            + struct.pack(">I", 0)
            + bytes(16)  # AAGUID all-zero
            + struct.pack(">H", len(self.cid))
            + self.cid
            + self._cose
        )
        return {
            "id": mfa.b64(self.cid),
            "rawId": mfa.b64(self.cid),
            "type": "public-key",
            "response": {
                "clientDataJSON": mfa.b64(client),
                "attestationObject": mfa.b64(
                    _cbor_map(
                        [("fmt", "none"), ("attStmt", {}), ("authData", authdata)]
                    )
                ),
            },
        }

    def assertion(self, options, *, origin=None, user_handle=b"") -> dict:
        client = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": options["challenge"],
                "origin": origin if origin else ORIGIN,
                "crossOrigin": False,
            }
        ).encode()
        authdata = (
            hashlib.sha256(self.rp_host.encode()).digest()
            + b"\x01"
            + struct.pack(">I", 1)
        )
        signature = self.private.sign(
            authdata + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": mfa.b64(self.cid),
            "rawId": mfa.b64(self.cid),
            "type": "public-key",
            "response": {
                "clientDataJSON": mfa.b64(client),
                "authenticatorData": mfa.b64(authdata),
                "signature": mfa.b64(signature),
                "userHandle": mfa.b64(bytes(user_handle)),
            },
        }


@pytest.fixture()
def user(db):
    return make_user("mfa-user", PASSWORD, role="engineer")


def test_login_issues_a_pending_ceremony_for_enabled_users(client, db):
    client.headers["Origin"] = ORIGIN
    user = make_user("mfa-login-user", PASSWORD)
    set_enabled(user.id, True)

    response = login(client, user.username, PASSWORD)
    assert outcome(response) == (200, {"mfa_required": True, "next": "/mfa.html"})
    assert mfa.cookie_name() in {c.name for c in client.cookies.jar}

    state = post_mfa(client, "state")
    assert state.status_code == 200
    assert state.json()["stage"] == "verify"
    assert state.json()["purpose"] == "login"
    assert "__Host-ospmae_session" not in {c.name for c in client.cookies.jar}


def test_totp_enrolment_encrypts_and_hashes_stored_factors(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    state = post_mfa(c, "state")
    assert state.json()["stage"] == "manage"

    with SessionLocal() as db:
        assert db.get(User, user.id).mfa_enabled is False

    codes = enrol_totp(c)

    with SessionLocal() as db:
        row = db.get(User, user.id)
        assert row.mfa_enabled is True
        assert row.mfa_totp_secret
        assert pyotp.random_base32() != row.mfa_totp_secret
        stored_codes = db.query(MfaRecoveryCode).filter_by(user_id=user.id).all()
        assert len(stored_codes) == 10
        digests = {cdigest(raw) for raw in codes}
        assert {c.code_hash for c in stored_codes} == digests

        finish = post_mfa(c, "finish")
        assert finish.status_code == 200
        assert finish.json()["user"] == user.username
        sess = session_row(db, c.cookies.get("__Host-ospmae_session"))
        assert sess.mfa_verified is True
        assert sess.mfa_version == db.get(User, user.id).mfa_version

    status = c.get("/v1/me/mfa").json()
    assert status["enabled"] is True and status["totp"] is True
    assert status["recovery_codes_remaining"] == 10
    assert status["credentials"] == []


def cdigest(raw: str) -> str:
    from app.security.mfa import digest

    return digest(raw.replace("-", ""))


def test_verified_totp_signs_in_and_a_replayed_code_is_rejected(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)
    post_mfa(c, "finish")
    drop_sessions(user.id, c)

    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    secret = mfa.decrypt(totp_secret(user.id))
    totp = pyotp.TOTP(secret)
    reset_totp_step(user.id)
    code = totp.now()
    verified = post_mfa(c, "verify-code", {"kind": "totp", "code": code})
    assert outcome(verified) == ACCEPTED
    assert post_mfa(c, "finish").json()["user"] == user.username

    # The code that proved the factor cannot prove it again: the ceremony
    # consumed the step, so a replay is refused whatever the window does.
    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    replay = post_mfa(c, "verify-code", {"kind": "totp", "code": code})
    assert replay.status_code == 400


def test_recovery_codes_are_single_use(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    codes = enrol_totp(c)
    post_mfa(c, "finish")
    drop_sessions(user.id, c)

    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    first = post_mfa(c, "verify-code", {"kind": "recovery", "code": codes[0]})
    assert outcome(first) == ACCEPTED
    assert post_mfa(c, "finish").json()["user"] == user.username

    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    second = post_mfa(c, "verify-code", {"kind": "recovery", "code": codes[0]})
    assert second.status_code == 400

    with SessionLocal() as db:
        assert db.query(MfaRecoveryCode).filter_by(user_id=user.id).count() == 9


def test_a_malformed_recovery_code_never_touches_the_ledger(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    codes = enrol_totp(c)
    short = codes[0].replace("-", "")[:8]
    wrong_length = post_mfa(c, "verify-code", {"kind": "recovery", "code": short})
    assert wrong_length.status_code == 400
    with SessionLocal() as db:
        assert db.query(MfaRecoveryCode).filter_by(user_id=user.id).count() == 10


def test_wrong_codes_are_counted_across_sign_ins(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)

    for attempt in range(4):
        drop_sessions(user.id, c)
        assert login(c, user.username, PASSWORD).json()["mfa_required"]
        response = post_mfa(
            c, "verify-code", {"kind": "totp", "code": f"{attempt}12345"[:6]}
        )
        assert response.status_code == 400
    # The fifth wrong code spends the account's allowance: the ceremony ends.
    drop_sessions(user.id, c)
    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    last = post_mfa(c, "verify-code", {"kind": "totp", "code": "999999"})
    assert outcome(last) == CODES_REFUSED
    assert last.status_code == 401
    assert post_mfa(c, "finish").status_code == 401

    # A second factor code is still refused while the lockout holds: no new
    # challenge's session can be pushed through the same gate.
    with SessionLocal() as db:
        row = db.get(User, user.id)
        assert row.mfa_code_failures >= 5
        assert row.mfa_code_failures_since is not None


def test_expired_pending_ceremonies_fail_closed(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    with SessionLocal() as db:
        expired = db.query(MfaChallenge).first()
        expired.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    assert outcome(post_mfa(c, "state")) == EXPIRED


def test_wrong_origin_is_refused_before_any_state_change(client, db, user):
    c = sign_in(user)
    c.headers.pop("Origin", None)
    response = c.post(
        "/v1/auth/mfa/manage/start",
        json={"password": PASSWORD},
        headers={"X-CSRF-Token": c.cookies.get("__Host-ospmae_csrf")},
    )
    assert outcome(response) == ORIGIN_REFUSED
    response = c.post(
        "/v1/auth/mfa/manage/start",
        json={"password": PASSWORD},
        headers={
            "Origin": "https://evil.example",
            "X-CSRF-Token": c.cookies.get("__Host-ospmae_csrf"),
        },
    )
    assert outcome(response) == CROSS_SITE_REFUSED


def test_a_password_change_invalidates_a_pending_ceremony(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    with SessionLocal() as db:
        db.get(User, user.id).password_hash = "changed"
        db.commit()
    assert outcome(post_mfa(c, "state")) == EXPIRED


def test_ceremony_stage_guards(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    state = post_mfa(c, "state")
    assert state.json()["stage"] == "manage"
    # Verification-only steps refused while managing.
    assert post_mfa(c, "verify-code", {"code": "123456"}).status_code == 400
    assert post_mfa(c, "webauthn/options").status_code == 400


def test_real_webauthn_registration_and_signature(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    key = FakeKey()
    options = post_mfa(c, "webauthn/register-options")
    assert options.status_code == 200
    response = post_mfa(
        c,
        "webauthn/register",
        {"credential": key.registration(options.json()), "name": "Test key"},
    )
    assert response.status_code == 200, response.text
    assert len(response.json()["recovery_codes"]) == 10

    # The registration challenge is spent.
    assert (
        post_mfa(
            c, "webauthn/register", {"credential": key.registration(options.json())}
        ).status_code
        == 400
    )

    drop_sessions(user.id, c)
    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    assert post_mfa(c, "finish").status_code == 403
    auth_options = post_mfa(c, "webauthn/options")
    assert auth_options.status_code == 200
    assertion = key.assertion(auth_options.json(), user_handle=mfa.user_handle(user))
    assert post_mfa(c, "webauthn/verify", {"credential": assertion}).status_code == 200
    assert post_mfa(c, "finish").json()["user"] == user.username


def test_webauthn_assertions_of_the_wrong_origin_or_key_are_refused(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    key = FakeKey()
    built = key.registration(post_mfa(c, "webauthn/register-options").json())
    assert post_mfa(c, "webauthn/register", {"credential": built}).status_code == 200

    drop_sessions(user.id, c)
    assert login(c, user.username, PASSWORD).json()["mfa_required"]

    for kind in ("origin", "cross", "user", "signature"):
        options = post_mfa(c, "webauthn/options").json()
        if kind == "origin":
            assertion = key.assertion(options, origin="https://evil.example")
        else:
            assertion = key.assertion(options)
        if kind == "cross":
            assertion["response"]["crossOrigin"] = True
            assertion["response"]["clientDataJSON"] = mfa.b64(
                json.dumps(
                    {
                        "type": "webauthn.get",
                        "challenge": options["challenge"],
                        "origin": ORIGIN,
                        "crossOrigin": True,
                    }
                ).encode()
            )
        if kind == "user":
            assertion["response"]["userHandle"] = mfa.b64(os.urandom(8))
        if kind == "signature":
            assertion["response"]["signature"] = mfa.b64(b"tampered")
        refused = post_mfa(c, "webauthn/verify", {"credential": assertion})
        assert refused.status_code == 400, kind
        if kind in ("origin", "signature"):
            assert refused.json()["detail"] == KEY_REFUSED[1]["detail"], kind
        else:
            assert refused.json()["detail"] == "Invalid WebAuthn response", kind
        assert post_mfa(c, "finish").status_code == 403


def test_registration_needs_a_registered_challenge_and_credential(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    # An unregistered credential: an assertion cannot exist before the key is
    # registered through a ceremony that reached its management stage.
    assert post_mfa(c, "webauthn/options").status_code == 400


def test_an_enrolment_change_ends_other_local_sessions(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)

    # The enrolment bump invalidated the session the ceremony started from:
    # any other local session of the account ends at its next resolution.
    with SessionLocal() as db:
        from app.security.sessions import create_session

        other_sid = create_session(db, user_id=user.id, ttl_seconds=3600)

    assert c.get("/v1/me/mfa").status_code == 401
    with SessionLocal() as db:
        row = session_row(db, other_sid)
        user_row = db.get(User, user.id)
        assert user_row.mfa_enabled is True
        assert row is not None and row.mfa_version != user_row.mfa_version

    # A clean sign-in proves the factor once and reaches the account again.
    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    reset_totp_step(user.id)
    code = pyotp.TOTP(mfa.decrypt(totp_secret(user.id))).now()
    assert post_mfa(c, "verify-code", {"kind": "totp", "code": code}).status_code == 200
    assert post_mfa(c, "finish").json()["user"] == user.username
    assert c.get("/v1/me/mfa").status_code == 200


def test_removing_factors_keeps_the_rest_and_mfa_stays_on(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)
    key = FakeKey()
    built = key.registration(post_mfa(c, "webauthn/register-options").json())
    assert (
        post_mfa(
            c, "webauthn/register", {"credential": built, "name": "Key"}
        ).status_code
        == 200
    )

    assert post_mfa(c, "remove", {"id": "totp"}).status_code == 200
    status = post_mfa(c, "state").json()
    assert status["totp"] is False
    assert len(status["credentials"]) == 1

    cred_id = status["credentials"][0]["id"]
    assert post_mfa(c, "remove", {"id": cred_id}).status_code == 200
    with SessionLocal() as db:
        row = db.get(User, user.id)
        assert row.mfa_enabled is False
        assert db.query(MfaRecoveryCode).filter_by(user_id=user.id).count() == 0


def test_a_required_admin_enrols_before_anything_else(client, db):
    from app.core.config import settings

    c, admin_user = auth_client(username="mfa-admin", password=PASSWORD, role="admin")
    c.headers["Origin"] = ORIGIN
    try:
        settings.mfa_policy = "admins"
        response = login(c, admin_user.username, PASSWORD)
        assert response.json()["mfa_required"] is True
        state = post_mfa(c, "state")
        assert state.json()["stage"] == "enrol"
        assert state.json()["required"] is True
    finally:
        settings.mfa_policy = "optional"


def test_policy_blocked_sessions_end_while_optional_users_continue(client, db):
    from app.core.config import settings

    c, viewer = auth_client(username="mfa-viewer", password=PASSWORD, role="viewer")
    c.headers["Origin"] = ORIGIN
    try:
        settings.mfa_policy = "all"
        response = login(c, viewer.username, PASSWORD)
        assert response.json()["mfa_required"] is True
    finally:
        settings.mfa_policy = "optional"


LIMITED = (429, {"detail": "Too many verification attempts; try again later"})


def _manage(client, password):
    return client.post(
        "/v1/auth/mfa/manage/start",
        json={"password": password},
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": client.cookies.get("__Host-ospmae_csrf"),
        },
    )


def _ledger(prefix: str) -> int:
    with SessionLocal() as db:
        return (
            db.query(RateLimitEntry)
            .filter(RateLimitEntry.identifier.like(prefix + "%"))
            .count()
        )


def test_a_session_holder_cannot_keep_guessing_the_account_password(
    client, db, user, monkeypatch
):
    """Whoever holds a session (a borrowed browser, a stolen cookie) can ask
    the account's password to be confirmed; each account confirms it at most
    ACCOUNT_STEPS times in the window, right or wrong."""
    from app.security import passwords

    judged = []
    real = passwords.verify_password

    def counting(password, hashed):
        judged.append(password)
        return real(password, hashed)

    monkeypatch.setattr(passwords, "verify_password", counting)
    c = sign_in(user)
    judged.clear()

    answers = [
        outcome(_manage(c, f"guess-number-{n}")) for n in range(mfa.ACCOUNT_STEPS)
    ]
    assert answers == [(401, {"detail": "Invalid password"})] * mfa.ACCOUNT_STEPS
    assert len(judged) == mfa.ACCOUNT_STEPS
    # Every guess was counted, against the account and against the address.
    assert _ledger(f"mfa_user:{user.id}") == mfa.ACCOUNT_STEPS
    assert _ledger("mfa_addr:") == mfa.ACCOUNT_STEPS

    # The allowance is spent: the next guess, and the right password, are
    # refused before any password is judged.
    assert outcome(_manage(c, "guess-number-last")) == LIMITED
    assert outcome(_manage(c, PASSWORD)) == LIMITED
    assert len(judged) == mfa.ACCOUNT_STEPS

    # Another account at the same address still has its own allowance.
    other = sign_in(make_user("mfa-other", PASSWORD, role="engineer"))
    assert _manage(other, PASSWORD).status_code == 200


def test_each_address_makes_a_bounded_number_of_ceremony_steps(client, db, user):
    """An address spreads its steps over many accounts and is still bounded."""
    c = sign_in(user)
    start_manage(c, user)
    with SessionLocal() as s:
        now = datetime.utcnow()
        s.add_all(
            RateLimitEntry(identifier="mfa_addr:8.8.8.8", timestamp=now)
            for _ in range(mfa.ADDRESS_STEPS - _ledger("mfa_addr:8.8.8.8"))
        )
        s.commit()
    assert outcome(post_mfa(c, "totp/start")) == LIMITED
    # The refused step was not counted, and the account's own count is intact.
    assert _ledger("mfa_addr:8.8.8.8") == mfa.ADDRESS_STEPS
    # From another address the same browser carries on.
    c.headers["X-Forwarded-For"] = "8.8.4.4"
    assert post_mfa(c, "totp/start").status_code == 200


def test_ceremony_steps_stop_when_the_allowance_ledger_cannot_be_reached(
    client, db, user, monkeypatch
):
    c = sign_in(user)

    def unavailable(*_args, **_kwargs):
        raise OSError("synthetic ledger outage")

    monkeypatch.setattr(mfa, "take_rate_limit", unavailable)
    assert outcome(_manage(c, PASSWORD)) == (
        503,
        {"detail": "Authentication rate limiter unavailable"},
    )


def test_an_authenticator_joins_the_account_only_with_its_first_code(client, db, user):
    """A wrong code during setup leaves the account as it was: no secret is
    stored, nothing reports an authenticator, and setup can be finished."""
    c = sign_in(user)
    start_manage(c, user)
    secret = post_mfa(c, "totp/start").json()["secret"]

    wrong = "000000" if pyotp.TOTP(secret).now() != "000000" else "111111"
    assert outcome(post_mfa(c, "totp/confirm", {"code": wrong})) == (
        400,
        {"detail": "Invalid authenticator code"},
    )
    assert totp_secret(user.id) is None
    with SessionLocal() as s:
        row = s.get(User, user.id)
        assert (row.mfa_enabled, row.mfa_version) == (False, 0)
    assert c.get("/v1/me/mfa").json()["totp"] is False
    assert post_mfa(c, "state").json()["totp"] is False

    # The same setup is confirmed by its right code.
    confirmed = post_mfa(c, "totp/confirm", {"code": pyotp.TOTP(secret).now()})
    assert confirmed.status_code == 200, confirmed.text
    assert len(confirmed.json()["recovery_codes"]) == 10
    # The enrolment ended the session it was made from; finishing signs in.
    assert post_mfa(c, "finish").status_code == 200
    assert totp_secret(user.id) and c.get("/v1/me/mfa").json()["totp"] is True


def test_a_secret_nobody_confirmed_never_becomes_a_factor(client, db, user):
    """An account that is not enrolled holds no proven authenticator. A
    secret found on one was never confirmed (it could have been planted by
    someone who once held the session and password), so enrolling a security
    key removes it instead of making it a second way in."""
    planted = pyotp.random_base32()
    with SessionLocal() as s:
        s.get(User, user.id).mfa_totp_secret = (
            mfa.cipher().encrypt(planted.encode()).decode()
        )
        s.commit()

    c = sign_in(user)
    assert c.get("/v1/me/mfa").json()["totp"] is False
    start_manage(c, user)
    # Setup is not blocked by the unproven secret.
    assert post_mfa(c, "totp/start").status_code == 200

    key = FakeKey()
    options = post_mfa(c, "webauthn/register-options")
    registered = post_mfa(
        c, "webauthn/register", {"credential": key.registration(options.json())}
    )
    assert registered.status_code == 200, registered.text
    assert totp_secret(user.id) is None
    assert post_mfa(c, "finish").status_code == 200
    assert c.get("/v1/me/mfa").json() | {"credentials": []} == {
        "enabled": True,
        "totp": False,
        "credentials": [],
        "recovery_codes_remaining": 10,
        "policy": "optional",
        "required": False,
        "local_enabled": True,
    }

    # At the next sign-in the planted secret's codes prove nothing.
    drop_sessions(user.id, c)
    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    assert (
        outcome(post_mfa(c, "verify-code", {"code": pyotp.TOTP(planted).now()}))
        == INVALID_CODE
    )


def test_sso_sessions_are_not_subject_to_the_local_ceremony(client, db, user):
    """A session created by the SSO path keeps working without MFA proofs."""
    with SessionLocal() as db:
        from app.security.sessions import create_session

        sid = create_session(db, user_id=user.id, ttl_seconds=3600, auth_method="oidc")
        db.get(User, user.id).mfa_enabled = True
        db.commit()

    from app.main import app as application
    from fastapi.testclient import TestClient

    from tests.conftest import peer_wrapper

    bare = TestClient(peer_wrapper(application), base_url="https://testserver")
    bare.cookies.set("__Host-ospmae_session", sid)
    response = bare.get("/v1/me/mfa")
    assert response.status_code == 200, response.text


def test_policy_blocks_required_signins(client, db, user):
    from app.core.config import settings

    try:
        settings.mfa_policy = "all"
        client.headers["Origin"] = ORIGIN
        response = login(client, user.username, PASSWORD)
        assert response.json()["mfa_required"] is True
        state = post_mfa(client, "state")
        assert state.json()["stage"] == "enrol"
        assert state.json()["required"] is True
    finally:
        settings.mfa_policy = "optional"


def test_an_unfamiliar_address_is_learned_only_after_the_second_factor(
    client, db, user, outbox, monkeypatch
):
    """A password alone proves nothing new about the address: the notice and
    the known-address record wait until the second factor is verified."""
    from app.db.models import UserLoginIP

    monkeypatch.setattr(settings, "public_base_url", ORIGIN)
    with SessionLocal() as s:
        s.get(User, user.id).email = "mfa-user@example.com"
        s.commit()
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)
    post_mfa(c, "finish")
    drop_sessions(user.id, c)
    first = [m.subject for m in outbox.messages()]

    assert login(c, user.username, PASSWORD, peer="198.51.100.77").json()[
        "mfa_required"
    ]
    with SessionLocal() as s:
        known = {a for (a,) in s.query(UserLoginIP.address).filter_by(user_id=user.id)}
    assert "198.51.100.77" not in known
    assert [m.subject for m in outbox.messages()] == first

    reset_totp_step(user.id)
    code = pyotp.TOTP(mfa.decrypt(totp_secret(user.id))).now()
    assert outcome(post_mfa(c, "verify-code", {"kind": "totp", "code": code})) == (
        ACCEPTED
    )
    assert post_mfa(c, "finish").json()["user"] == user.username

    new = outbox.messages()[len(first) :]
    assert [m.recipient for m in new] == ["mfa-user@example.com"]
    assert "IP address: 198.51.100.77\n" in new[0].body


# ---------------------------------------------------------------------------
# Security notices and audit rows, ported from KEEN's mfa.audit.
# ---------------------------------------------------------------------------

SIGN_IN_NOTICE = "Sign-in from an unfamiliar IP address"


@pytest.fixture()
def notices(outbox, monkeypatch, user):
    """Mail on for the MFA user, with the ceremony origin still the public one."""
    monkeypatch.setattr(settings, "public_base_url", ORIGIN)
    monkeypatch.setattr(settings, "smtp_from_name", "OSPMAE")
    with SessionLocal() as s:
        s.get(User, user.id).email = "mfa-user@example.com"
        s.commit()
    return outbox


def notice_titles(outbox) -> list[str]:
    return [
        m.subject.removeprefix("OSPMAE security: ")
        for m in outbox.messages()
        if m.subject.startswith("OSPMAE security: ")
    ]


def mfa_audit(user) -> list[tuple[str, str | None]]:
    from app.db.models import AuditLog

    with SessionLocal() as s:
        rows = (
            s.query(AuditLog.path, AuditLog.client_ip)
            .filter(AuditLog.method == "MFA", AuditLog.username == user.username)
            .order_by(AuditLog.ts)
            .all()
        )
    return [(path.removeprefix("/v1/auth/mfa/"), ip) for path, ip in rows]


def test_every_factor_change_mails_the_owner(client, db, user, notices):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)
    key = FakeKey()
    options = post_mfa(c, "webauthn/register-options").json()
    registered = post_mfa(
        c, "webauthn/register", {"credential": key.registration(options), "name": "Key"}
    )
    assert registered.status_code == 200, registered.text
    assert post_mfa(c, "recovery/regenerate").status_code == 200
    assert post_mfa(c, "remove", {"id": "totp"}).status_code == 200

    # Each authenticator added is reported, the second as well as the first.
    assert notice_titles(notices) == [
        SIGN_IN_NOTICE,
        "An authenticator was added to your OSPMAE account",
        "An authenticator was added to your OSPMAE account",
        "Your OSPMAE recovery codes were replaced",
        "An authenticator was removed from your OSPMAE account",
    ]
    assert all(
        "IP address: 8.8.8.8\n" in m.body and m.recipient == "mfa-user@example.com"
        for m in notices.messages()
    )
    assert mfa_audit(user) == [
        ("factor-enrolled", "8.8.8.8"),
        ("factor-enrolled", "8.8.8.8"),
        ("recovery-codes-regenerated", "8.8.8.8"),
        ("factor-removed", "8.8.8.8"),
    ]


def test_signing_in_with_a_recovery_code_mails_the_owner(client, db, user, notices):
    c = sign_in(user)
    start_manage(c, user)
    codes = enrol_totp(c)
    post_mfa(c, "finish")
    drop_sessions(user.id, c)

    assert login(c, user.username, PASSWORD).json()["mfa_required"]
    used = post_mfa(c, "verify-code", {"kind": "recovery", "code": codes[0]})
    assert outcome(used) == ACCEPTED

    [notice] = [m for m in notices.messages() if "recovery code was used" in m.subject]
    assert "Each recovery code works once." in notice.body
    assert mfa_audit(user)[-1] == ("verified-recovery", "8.8.8.8")


def test_a_spent_code_allowance_mails_once(client, db, user, notices):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)
    for attempt in range(mfa.CODE_ATTEMPTS):
        drop_sessions(user.id, c)
        assert login(c, user.username, PASSWORD).json()["mfa_required"]
        post_mfa(c, "verify-code", {"kind": "totp", "code": f"{attempt}23456"})

    ended = "OSPMAE ended a two-factor verification after repeated incorrect codes"
    assert notice_titles(notices).count(ended) == 1
    [notice] = [m for m in notices.messages() if ended in m.subject]
    assert f"{mfa.CODE_ATTEMPTS} incorrect authenticator or recovery codes" in (
        notice.body
    )

    # Guesses during the lockout are refused without another notice, so they
    # cannot flood the owner's mailbox.
    for _ in range(3):
        drop_sessions(user.id, c)
        assert login(c, user.username, PASSWORD).json()["mfa_required"]
        refused = post_mfa(c, "verify-code", {"kind": "totp", "code": "123456"})
        assert outcome(refused) == CODES_REFUSED
    assert notice_titles(notices).count(ended) == 1
    actions = [action for action, _ip in mfa_audit(user)]
    assert actions[1:] == ["rejected-totp"] * (mfa.CODE_ATTEMPTS - 1) + [
        "verification-ended"
    ]


def test_a_code_kind_is_totp_or_recovery(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)
    post_mfa(c, "finish")
    drop_sessions(user.id, c)
    assert login(c, user.username, PASSWORD).json()["mfa_required"]

    response = post_mfa(c, "verify-code", {"kind": "sms", "code": "123456"})
    assert response.status_code == 422


def _mfa_admin():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "scripts" / "mfa_admin.py"
    spec = importlib.util.spec_from_file_location("mfa_admin", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_operator_reset_clears_factors_and_mails_the_owner(
    client, db, user, notices, capsys
):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)
    assert post_mfa(c, "finish").status_code == 200
    assert c.get("/v1/me").status_code == 200

    script = _mfa_admin()
    assert (
        script.main([user.username, "--reset", "--confirm-username", user.username])
        == 0
    )
    assert "local sessions revoked" in capsys.readouterr().out

    with SessionLocal() as s:
        row = s.get(User, user.id)
        assert row.mfa_enabled is False and row.mfa_totp_secret is None
        assert s.query(MfaRecoveryCode).filter_by(user_id=user.id).count() == 0
    # The enrolment version moved on, so the signed-in session ended.
    assert c.get("/v1/me").status_code == 401

    title = "Your OSPMAE two-factor authentication was reset by an operator"
    [notice] = [m for m in notices.messages() if title in m.subject]
    assert "IP address: Unavailable (operator action or unknown address)" in (
        notice.body
    )
    assert mfa_audit(user)[-1] == ("operator-reset", None)


def test_an_operator_reset_needs_the_name_twice(user, capsys):
    script = _mfa_admin()
    with pytest.raises(SystemExit):
        script.main([user.username, "--reset", "--confirm-username", "someone-else"])
    with pytest.raises(SystemExit):
        script.main(["nobody", "--reset", "--confirm-username", "nobody"])
    assert "User not found" in capsys.readouterr().err


def test_administrators_find_second_factor_actions_in_the_audit_trail(client, db, user):
    c = sign_in(user)
    start_manage(c, user)
    enrol_totp(c)

    admin, _admin_user = auth_client(role="admin")
    response = admin.get("/v1/admin/audit", params={"method": "MFA"})
    assert response.status_code == 200, response.text
    rows = response.json()["items"]
    assert [(r["username"], r["path"]) for r in rows] == [
        (user.username, "/v1/auth/mfa/factor-enrolled")
    ]
