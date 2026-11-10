"""Local second-factor primitives: TOTP, WebAuthn and recovery codes.

Pending challenges never enter the session namespace: the browser holds only
an unhashed ceremony token in its own short-lived cookie, the row is looked up
by digest in the database and carries the account state it was issued for, so
a stale or tampered cookie fails closed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

from app.core.config import settings
from app.db.models import MfaChallenge, MfaCredential, MfaRecoveryCode, User
from app.security.client_addr import public_client_address
from app.security.rate_limit import check_rate_limit

COOKIE = "ospmae_mfa_pending"


def cookie_name() -> str:
    if settings.public_base_url.startswith("https://"):
        return "__Host-" + COOKIE
    return COOKIE


def _now() -> datetime:
    return datetime.utcnow()


def clear_cookie(response) -> None:
    # Browsers refuse a __Host- cookie, even an expiring one, without Secure.
    response.delete_cookie(
        cookie_name(),
        path="/",
        secure=bool(settings.cookie_secure),
        httponly=True,
        samesite="strict",
    )


TTL = 300
# Wrong TOTP or recovery codes an account may receive, counted across sign-ins
# from the first of them; the one that reaches the limit ends the ceremony, and
# the account then accepts no code until CODE_LOCKOUT has passed.
CODE_ATTEMPTS = 5
CODE_LOCKOUT = timedelta(hours=1)
_MFA_WINDOW_SECONDS = 300


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def origin_config():
    """Return the WebAuthn origin and relying-party ID: the public origin and host."""
    origin = settings.public_base_url
    parsed = urlsplit(origin)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise HTTPException(503, "Local MFA requires an HTTPS OSPMAE_PUBLIC_BASE_URL")
    # The relying party is the exact host, so sibling subdomains never share it.
    return origin, parsed.hostname


def check_origin(request):
    if not bool(getattr(settings, "local_auth_enabled", True)):
        raise HTTPException(404, "Password authentication is disabled")
    origin, _ = origin_config()
    if request.headers.get("origin") != origin:
        raise HTTPException(403, "Authentication request origin is not allowed")


def cipher():
    try:
        return Fernet(settings.mfa_encryption_key.encode())
    except (ValueError, TypeError):
        raise HTTPException(503, "TOTP requires a valid OSPMAE_MFA_ENCRYPTION_KEY")


def decrypt(secret):
    try:
        return cipher().decrypt(secret.encode()).decode()
    except InvalidToken:
        raise HTTPException(
            503, "TOTP secret cannot be decrypted; restore the MFA encryption key"
        )


def required(db, user):
    if settings.mfa_policy == "all":
        return True
    if settings.mfa_policy == "admins":
        from app.security.roles import attach_effective_role

        return attach_effective_role(db, user) == "admin"
    return False


def local_session_allowed(db, user, session):
    """Whether the session row still carries a proven second factor.

    The caller's session resolution fails closed: a mismatched session row is
    removed, so every other browser session of the account ends with the
    enrolment bump that made the versions disagree.
    """
    if (session.auth_method or "local") not in {"local"}:
        return True
    if int(session.mfa_version) != int(user.mfa_version):
        return False
    if user.mfa_enabled or required(db, user):
        return bool(user.mfa_enabled and session.mfa_verified is True)
    return True


def limit(db, request, user_id=None):
    """Database-backed allowances for every ceremony step.

    Fail-closed on limiter errors: without a working ledger no second-factor
    state changes.
    """
    try:
        client_ip = public_client_address(
            request.client.host if request.client else None,
            request.headers.get("X-Forwarded-For"),
        )
        allowed, _ = check_rate_limit(
            db, f"mfa_addr:{client_ip or 'unknown'}", 40, _MFA_WINDOW_SECONDS
        )
        if allowed and user_id is not None:
            allowed, _ = check_rate_limit(
                db, f"mfa_user:{int(user_id)}", 15, _MFA_WINDOW_SECONDS
            )
        if not allowed:
            raise HTTPException(429, "Too many verification attempts; try again later")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Authentication rate limiter unavailable")


def _code_failures_current(user) -> bool:
    since = user.mfa_code_failures_since
    return since is not None and _now() - since < CODE_LOCKOUT


def codes_refused(user) -> bool:
    """Whether wrong codes have spent the account's allowance for now.

    The caller holds the account's row lock, as every ceremony step does.
    """
    return _code_failures_current(user) and user.mfa_code_failures >= CODE_ATTEMPTS


def record_wrong_code(user) -> bool:
    """Count a wrong code against the account; True once it spends the allowance.

    The refusal that follows lasts CODE_LOCKOUT from the code that spent it.
    """
    if not _code_failures_current(user):
        user.mfa_code_failures = 0
        user.mfa_code_failures_since = _now()
    user.mfa_code_failures += 1
    if user.mfa_code_failures < CODE_ATTEMPTS:
        return False
    user.mfa_code_failures_since = _now()
    return True


def clear_wrong_codes(user) -> None:
    """A right code shows the person holds the factor."""
    user.mfa_code_failures = 0
    user.mfa_code_failures_since = None


# Requests already reach the central audit middleware; going through it means
# every ceremony action is recorded with its caller context like any other
# audited route, so no separate writer lives here.


def _row_lock(db, user_id):
    return (
        db.query(User)
        .filter(User.id == int(user_id))
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )


def pending_response(payload, token):
    """Issue the ceremony cookie alongside the JSON direction to /mfa.html."""
    from fastapi.responses import JSONResponse

    response = JSONResponse(payload)
    response.set_cookie(
        cookie_name(),
        token,
        max_age=TTL,
        httponly=True,
        secure=bool(settings.cookie_secure),
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def start(db, user, request, purpose="login"):
    check_origin(request)
    # Serialize enrolment/reset/login state changes on the authoritative user row.
    password_before_lock = user.password_hash
    user = _row_lock(db, user.id)
    if user is None or user.password_hash != password_before_lock or not user.is_active:
        raise HTTPException(401, "Account changed; sign in again")
    token = secrets.token_urlsafe(32)
    # Bound outstanding challenges per account and invalidate older browser flows.
    db.query(MfaChallenge).filter(MfaChallenge.user_id == user.id).delete(
        synchronize_session=False
    )
    stage = (
        "verify" if user.mfa_enabled else ("enrol" if purpose == "login" else "manage")
    )
    row = MfaChallenge(
        token_hash=digest(token),
        user_id=user.id,
        purpose=purpose,
        stage=stage,
        version=user.mfa_version,
        password_digest=digest(user.password_hash),
        expires_at=_now() + timedelta(seconds=TTL),
        data={},
    )
    db.add(row)
    db.commit()
    payload = {"mfa_required": True, "next": "/mfa.html"}
    if purpose != "login":
        payload["next"] = "/mfa.html?purpose=manage"
    return pending_response(payload, token)


def pending(db, request):
    check_origin(request)
    token = request.cookies.get(cookie_name(), "")
    if not token or len(token) > 128:
        raise HTTPException(401, "Verification expired; start again")
    # Consistent lock order: user first, then challenge; serializes codes/changes.
    row = db.get(MfaChallenge, digest(token))
    if row is None:
        raise HTTPException(401, "Verification expired; start again")
    user = _row_lock(db, row.user_id)
    row = (
        db.query(MfaChallenge)
        .filter(MfaChallenge.token_hash == digest(token))
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if (
        not user
        or not user.is_active
        or not row
        or row.expires_at <= _now()
        or row.version != user.mfa_version
        or row.password_digest != digest(user.password_hash)
    ):
        raise HTTPException(401, "Verification expired; start again")
    return row, user


def management(row):
    if row.stage not in {"enrol", "manage"}:
        raise HTTPException(403, "Verify your existing second factor first")


def verified(row):
    row.stage = "manage" if row.purpose == "manage" else "ready"
    row.data = {}  # consume any WebAuthn or pending TOTP challenge


def bump(db, user, row):
    user.mfa_version += 1
    row.version = user.mfa_version
    db.flush()


def recovery_codes(db, user):
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id).delete(
        synchronize_session=False
    )
    codes = [
        "-".join(secrets.token_hex(4).upper() for _ in range(4)) for _ in range(10)
    ]
    db.add_all(
        [
            MfaRecoveryCode(user_id=user.id, code_hash=digest(c.replace("-", "")))
            for c in codes
        ]
    )
    return codes


def user_handle(user) -> bytes:
    """The WebAuthn user handle: a fixed-width big-endian encoding of the id.

    The same encoding goes into registration options and is checked against
    every assertion's userHandle, so identities between credentials cannot be
    confused.
    """
    return int(user.id).to_bytes(8, "big")


def verify_code(db, user, value, kind):
    if kind == "recovery":
        code = value.strip().replace("-", "").replace(" ", "").upper()
        if len(code) != 32:
            return False
        return (
            db.query(MfaRecoveryCode)
            .filter(
                MfaRecoveryCode.user_id == user.id,
                MfaRecoveryCode.code_hash == digest(code),
            )
            .delete(synchronize_session=False)
            == 1
        )
    if (
        kind != "totp"
        or not user.mfa_totp_secret
        or len(value) != 6
        or not value.isascii()
        or not value.isdigit()
    ):
        return False
    totp = pyotp.TOTP(decrypt(user.mfa_totp_secret))
    current = int(time.time()) // 30
    for step in (current, current - 1, current + 1):
        if step > user.mfa_totp_last_step and secrets.compare_digest(
            totp.at(step * 30), value
        ):
            user.mfa_totp_last_step = step
            return True
    return False


def registered(db, user):
    return (
        db.query(MfaCredential)
        .filter(MfaCredential.user_id == user.id)
        .order_by(MfaCredential.created_at)
        .all()
    )


factor_alerts = {
    "enrolled": "An authenticator was added to your account",
    "removed": "An authenticator was removed from your account",
    "regenerated": "Your recovery codes were replaced",
    "cleared": "An authenticator problem ended your verification",
}


def security_alert(db, user, event: str, title: str) -> None:
    """Mail the account owner that their second factor changed.

    Queueing goes through the shared outbox in the caller's transaction; a
    missing SMTP configuration or recipient skips it the same way every
    other queued e-mail does.
    """
    from app.services.mailer import queue_email
    from app.services.notification_recipients import notification_email_for_user
    from app.services.notifications import smtp_configured

    recipient = (notification_email_for_user(db, user=user) or "").strip()
    if not smtp_configured() or not recipient:
        return
    body = (
        f"{title}.\n\n"
        f"Account: {user.username}\n"
        f"OSPMAE installation: {settings.public_base_url}\n"
        f"Time (UTC): {_now().isoformat(timespec='seconds')}Z\n\n"
        "If this was you, no action is needed. If you do not recognise this "
        "activity, open your known OSPMAE address directly, review your "
        "password and authenticators under Account, and contact your "
        "administrator if anything looks wrong.\n"
    )
    queue_email(
        db,
        user_id=user.id,
        recipient=recipient,
        subject=f"OSPMAE security: {title}",
        body=body,
    )


def activate(db, row, user):
    first = not user.mfa_enabled
    user.mfa_enabled = True
    bump(db, user, row)
    codes = recovery_codes(db, user) if first else None
    if row.purpose == "login":
        row.stage = "ready"
    row.data = {}
    db.commit()
    if first:
        security_alert(db, user, "enrolled", factor_alerts["enrolled"])
        db.commit()
    return {"ok": True, "recovery_codes": codes}


def check_client_data(credential, user=None):
    try:
        if len(json.dumps(credential)) > 65536:
            raise ValueError()
        client = json.loads(unb64(credential["response"]["clientDataJSON"]))
        if client.get("crossOrigin") or client.get("topOrigin"):
            raise ValueError()
        handle = credential["response"].get("userHandle")
        if handle and user is not None and unb64(handle) != user_handle(user):
            raise ValueError()
    except Exception:
        raise HTTPException(400, "Invalid WebAuthn response")


def cancel(db, request, response):
    token = request.cookies.get(cookie_name(), "")
    if token and len(token) <= 128:
        db.query(MfaChallenge).filter(MfaChallenge.token_hash == digest(token)).delete(
            synchronize_session=False
        )
        db.commit()
    clear_cookie(response)
    return response
