"""Self-service, proof-of-ownership addresses for automatic SSO linking.

Ported from KEEN. An account proves an address by opening a link mailed to
it while signed in; an identity provider that later reports that address as
verified links its identity to the account at the first sign-in. Adding or
removing an address needs a sign-in within the last five minutes, and the
mailed link lasts 30 minutes, works once, and ends with a change to the
account's password or second factors.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.email_address import single_mailbox
from app.db.models import SsoEmailChallenge, User, UserSsoEmail
from app.security.rate_limit import take_rate_limit
from app.security.sessions import session_row
from app.services import security_notifications
from app.services.mailer import queue_email, smtp_configured

RECENT_SIGN_IN_SECONDS = 300
REQUESTS_PER_HOUR = 5
MAX_ADDRESSES = 10
LINK_LIFETIME = timedelta(minutes=30)


class Address(BaseModel):
    email: str = Field(min_length=3, max_length=256)


class Proof(BaseModel):
    token: str = Field(min_length=20, max_length=128)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.utcnow()


def clean_email(value: str) -> str:
    """A linking address: one mailbox, compared without regard to case."""
    email = single_mailbox(value)
    if not email:
        raise HTTPException(400, "Invalid email address")
    return email.lower()


def lock_user(db: Session, user: User) -> User:
    current = (
        db.query(User)
        .filter(User.id == user.id)
        .populate_existing()
        .with_for_update()
        .one()
    )
    if not current.is_active:
        raise HTTPException(403, "Account is inactive")
    return current


def recent_signin(db: Session, session_id: str, user: User) -> None:
    """The request's session belongs to the account and began in the last
    five minutes."""
    row = session_row(db, session_id)
    age = (
        (_now() - row.created_at).total_seconds()
        if row is not None and row.created_at is not None
        else -1
    )
    if row is None or row.user_id != user.id or not 0 <= age <= RECENT_SIGN_IN_SECONDS:
        raise HTTPException(
            403,
            "Sign out and sign in again, then manage SSO email addresses within five minutes",
        )


def limit(user: User) -> None:
    allowed, _retry = take_rate_limit(
        f"sso_email:{user.id}", max_attempts=REQUESTS_PER_HOUR, window_seconds=3600
    )
    if not allowed:
        raise HTTPException(429, "Too many verification requests; try again later")


def claimed_elsewhere(db: Session, user: User, email: str) -> bool:
    """Whether another account uses the address as its email or linking address."""
    address = db.get(UserSsoEmail, email)
    other_primary = (
        db.query(User.id)
        .filter(User.id != user.id, func.lower(func.trim(User.email)) == email)
        .first()
    )
    return bool((address and address.user_id != user.id) or other_primary)


def available(db: Session, user: User, email: str) -> UserSsoEmail | None:
    if claimed_elsewhere(db, user, email):
        raise HTTPException(409, "This address cannot be linked to this account")
    return db.get(UserSsoEmail, email)


def list_addresses(*, user: User, db: Session) -> dict:
    return {
        "smtp_configured": smtp_configured(),
        "primary_email": user.email,
        "addresses": [
            {"email": a.email, "verified_at": a.verified_at.isoformat()}
            for a in db.query(UserSsoEmail)
            .filter(UserSsoEmail.user_id == user.id)
            .order_by(UserSsoEmail.email)
            .all()
        ],
    }


def request_address(
    *, payload: Address, ip: str | None, user: User, db: Session, session_id: str
) -> dict:
    if not smtp_configured():
        raise HTTPException(
            503, "SMTP must be configured before verifying SSO email addresses"
        )
    if urlsplit(settings.public_base_url).scheme != "https":
        raise HTTPException(
            503, "An HTTPS OSPMAE_PUBLIC_BASE_URL is required for verification emails"
        )
    recent_signin(db, session_id, user)
    limit(user)
    user = lock_user(db, user)
    email = clean_email(payload.email)
    own = db.get(UserSsoEmail, email)
    if own and own.user_id == user.id:
        db.commit()
        return {"ok": True, "already_verified": True}
    if (
        db.query(UserSsoEmail).filter(UserSsoEmail.user_id == user.id).count()
        >= MAX_ADDRESSES
    ):
        raise HTTPException(
            400, "Remove an address before adding more than ten SSO email addresses"
        )
    token = secrets.token_urlsafe(32)
    # One outstanding link per account; requesting another invalidates the old link.
    db.query(SsoEmailChallenge).filter(SsoEmailChallenge.user_id == user.id).delete(
        synchronize_session=False
    )
    db.add(
        SsoEmailChallenge(
            token_hash=digest(token),
            user_id=user.id,
            email=email,
            expires_at=_now() + LINK_LIFETIME,
            mfa_version=user.mfa_version,
            password_digest=digest(user.password_hash),
        )
    )
    # An address another account uses gets the same answer and the same
    # replaced link, so a request reveals nothing about other accounts. Only a
    # free address is sent its link; confirmation checks the address again.
    if not claimed_elsewhere(db, user, email):
        base = settings.public_base_url.rstrip("/")
        queue_email(
            db,
            user_id=user.id,
            recipient=email,
            subject="Verify your OSPMAE SSO email address",
            body=f"You requested to add {email} to OSPMAE account {user.username}.\n\n"
            "While signed into that OSPMAE account, open this link and confirm:\n"
            f"{base}/sso-email.html#token={token}\n\n"
            "This link expires in 30 minutes and works once. If you did not "
            "request it, ignore this email.",
        )
    db.commit()
    return {"ok": True}


def confirm_address(*, payload: Proof, ip: str | None, user: User, db: Session) -> dict:
    user = lock_user(db, user)
    row = (
        db.query(SsoEmailChallenge)
        .filter(
            SsoEmailChallenge.token_hash == digest(payload.token),
            SsoEmailChallenge.user_id == user.id,
        )
        .with_for_update()
        .one_or_none()
    )
    if (
        not row
        or row.expires_at <= _now()
        or row.mfa_version != user.mfa_version
        or row.password_digest != digest(user.password_hash)
    ):
        raise HTTPException(400, "Verification link is invalid or expired")
    existing = available(db, user, row.email)
    if not existing:
        db.add(UserSsoEmail(email=row.email, user_id=user.id, verified_at=_now()))
    email = row.email
    security_notifications.enqueue(db, user, "sso-email-added", ip=ip)
    db.delete(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            409, "This address cannot be linked to this account"
        ) from None
    return {"ok": True, "email": email}


def remove_address(
    *, payload: Address, ip: str | None, user: User, db: Session, session_id: str
) -> dict:
    recent_signin(db, session_id, user)
    user = lock_user(db, user)
    email = clean_email(payload.email)
    db.query(SsoEmailChallenge).filter(
        SsoEmailChallenge.user_id == user.id, SsoEmailChallenge.email == email
    ).delete(synchronize_session=False)
    removed = (
        db.query(UserSsoEmail)
        .filter(UserSsoEmail.user_id == user.id, UserSsoEmail.email == email)
        .delete(synchronize_session=False)
    )
    if removed:
        security_notifications.enqueue(db, user, "sso-email-removed", ip=ip)
    db.commit()
    return {"ok": True}
