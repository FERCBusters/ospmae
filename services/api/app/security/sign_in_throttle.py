"""Password sign-in throttling that an attacker cannot turn against the owner.

The policy, shared with KEEN, follows NIST SP 800-63B-4 section 3.2.2 and the
OWASP device-cookie protocol:

* A browser that has proved an account's password holds a device cookie for
  that account. Its attempts skip the per-address allowance and the account's
  throttle, and draw on their own allowance: five wrong passwords in a row
  revoke the cookie, after which the browser counts as unrecognised.
* Attempts from any other browser draw on the account's throttle. The first
  five consecutive failures are free; each later attempt opens a wait, 30
  seconds doubling to an hour, before the next one is heard, and after 100
  consecutive failures unrecognised browsers are refused until a correct
  password from a recognised browser or a password reset. A refused attempt
  never reaches password verification. Failures are forgotten 30 days after
  the last one.
* A correct password resets the account's count, and is answered with a fresh
  device cookie for the browser that sent it.

The throttle is keyed by a digest of the compared username whether or not an
account has it, so its answers reveal nothing about which accounts exist.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import unicodedata
from datetime import datetime, timedelta

from fastapi import Response
from sqlalchemy import delete, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import LoginDevice, LoginThrottle

FREE_FAILURES = 5
FAILURE_CEILING = 100
FIRST_WAIT_SECONDS = 30
MAX_WAIT_SECONDS = 3600
FORGET_FAILURES_AFTER = timedelta(days=30)

DEVICE_FAILURES = 5
DEVICE_LIFETIME = timedelta(days=90)
DEVICES_PER_ACCOUNT = 20
_DEVICE_TOKEN_MAX_LENGTH = 128

# Per-address allowance for unrecognised browsers, against spraying many
# usernames from one place.
ADDRESS_ATTEMPTS = 30
ADDRESS_WINDOW_SECONDS = 300

LIMITED = "Too many login attempts. Please try again later."

# Unicode Default_Ignorable_Code_Point ranges, plus the object replacement
# character that RFC 4518 also maps to nothing: they never distinguish one
# username from another.
_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0xFFFC, 0xFFFC),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def _ignorable(character: str) -> bool:
    point = ord(character)
    if unicodedata.category(character) == "Cc" and not character.isspace():
        return True
    return any(low <= point <= high for low, high in _IGNORABLE)


def login_name(username: str) -> str:
    """The form in which sign-in names are compared for throttling.

    Width, case, invisible characters and runs of spaces never make a
    different name, so every such spelling shares one throttle.
    """

    folded = unicodedata.normalize(
        "NFKC", unicodedata.normalize("NFKC", username).casefold()
    )
    visible = "".join(c for c in folded if not _ignorable(c))
    return " ".join(visible.split())


def name_key(username: str) -> str:
    """A fixed-size digest of the compared name: the ledger never stores a
    password typed into the username field."""

    return hashlib.sha256(login_name(username).encode("utf-8")).hexdigest()


def wait_seconds(failures: int) -> int:
    """The wait opened by an attempt made after ``failures`` failures."""

    if failures < FREE_FAILURES:
        return 0
    step = failures - FREE_FAILURES
    if step >= 7:  # 30 * 2**7 already passes the hour
        return MAX_WAIT_SECONDS
    return min(FIRST_WAIT_SECONDS * 2**step, MAX_WAIT_SECONDS)


def device_cookie_name() -> str:
    """A Secure cookie without a Domain takes the ``__Host-`` prefix, which a
    browser accepts only from this host over HTTPS, so a sibling site can
    neither plant nor shadow it."""

    name = "ospmae_device"
    if bool(settings.cookie_secure) and not (settings.cookie_domain or "").strip():
        return "__Host-" + name
    return name


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def recognised_device(
    db: Session, token: str | None, key: str, now: datetime
) -> LoginDevice | None:
    """The device record a presented cookie holds for this username."""

    raw = (token or "").strip()
    if not raw or len(raw) > _DEVICE_TOKEN_MAX_LENGTH:
        return None
    return (
        db.query(LoginDevice)
        .filter(LoginDevice.token_hash == _token_hash(raw))
        .filter(LoginDevice.name_key == key)
        .filter(LoginDevice.expires_at > now)
        .one_or_none()
    )


def reserve_unrecognised_attempt(
    db: Session, key: str, now: datetime
) -> tuple[bool, int]:
    """Admit one attempt from an unrecognised browser, or say how long to wait.

    The attempt is counted as a failure before the password is checked, under
    the throttle row's lock, so concurrent attempts cannot share one opening;
    a correct password then clears the count.
    """

    db.execute(
        pg_insert(LoginThrottle)
        .values(name_key=key, failures=0, gate_until=None, last_failure_at=now)
        .on_conflict_do_nothing(index_elements=[LoginThrottle.name_key])
    )
    row = (
        db.query(LoginThrottle)
        .filter(LoginThrottle.name_key == key)
        .with_for_update()
        .one()
    )
    if now - row.last_failure_at > FORGET_FAILURES_AFTER:
        row.failures = 0
        row.gate_until = None
    if row.failures >= FAILURE_CEILING:
        db.commit()
        return False, MAX_WAIT_SECONDS
    if row.gate_until is not None and row.gate_until > now:
        retry = math.ceil((row.gate_until - now).total_seconds())
        db.commit()
        return False, max(1, retry)
    wait = wait_seconds(row.failures)
    row.gate_until = now + timedelta(seconds=wait) if wait else None
    row.failures += 1
    row.last_failure_at = now
    db.commit()
    return True, 0


def clear_throttle(db: Session, key: str) -> None:
    """A correct password, or a completed reset, ends the count."""

    db.execute(delete(LoginThrottle).where(LoginThrottle.name_key == key))


def device_failed(db: Session, device: LoginDevice) -> None:
    """Count a wrong password from a recognised browser; the fifth in a row
    revokes its recognition."""

    failures = db.execute(
        update(LoginDevice)
        .where(LoginDevice.id == device.id)
        .values(failures=LoginDevice.failures + 1)
        .returning(LoginDevice.failures)
    ).scalar()
    if failures is not None and failures >= DEVICE_FAILURES:
        db.execute(delete(LoginDevice).where(LoginDevice.id == device.id))
    db.commit()


def issue_device(
    db: Session,
    *,
    user_id: int,
    key: str,
    now: datetime,
    replaces: LoginDevice | None = None,
) -> str:
    """Record a recognised browser for this account and return its token.

    The browser's previous token is retired, and an account keeps at most
    its newest DEVICES_PER_ACCOUNT browsers.
    """

    if replaces is not None:
        db.execute(delete(LoginDevice).where(LoginDevice.id == replaces.id))
    token = secrets.token_urlsafe(32)
    db.add(
        LoginDevice(
            token_hash=_token_hash(token),
            user_id=user_id,
            name_key=key,
            failures=0,
            created_at=now,
            expires_at=now + DEVICE_LIFETIME,
        )
    )
    db.flush()
    surplus = [
        row.id
        for row in db.query(LoginDevice.id)
        .filter(LoginDevice.user_id == user_id)
        .order_by(LoginDevice.created_at.desc(), LoginDevice.id.desc())
        .offset(DEVICES_PER_ACCOUNT)
        .all()
    ]
    if surplus:
        db.execute(delete(LoginDevice).where(LoginDevice.id.in_(surplus)))
    return token


def set_device_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=device_cookie_name(),
        value=token,
        max_age=int(DEVICE_LIFETIME.total_seconds()),
        httponly=True,
        secure=bool(settings.cookie_secure),
        samesite="strict",
        domain=(settings.cookie_domain or "").strip() or None,
        path="/",
    )
