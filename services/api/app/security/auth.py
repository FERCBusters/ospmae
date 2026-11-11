from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.email_address import single_mailbox
from app.db.models import User
from app.db.session import get_db
from app.security.passwords import hash_password, verify_password
from app.security.roles import (
    ROLE_ADMIN,
    ROLE_ARCHITECT,
    ROLE_CONTRIBUTOR,
    ROLE_ENGINEER,
    ROLE_FRAMEWORK_ADMIN,
    ROLE_INHERIT,
    ROLE_MAINTAINER,
    ROLE_PRODUCT_OWNER,
    ROLE_VIEWER,
    attach_effective_role,
    canonicalize_role,
)
from app.security.sessions import (
    delete_session,
    get_session,
    refresh_session,
)

ALLOWED_USER_ROLES = {
    ROLE_ADMIN,
    ROLE_FRAMEWORK_ADMIN,
    ROLE_MAINTAINER,
    ROLE_CONTRIBUTOR,
    ROLE_ENGINEER,
    ROLE_PRODUCT_OWNER,
    ROLE_ARCHITECT,
    ROLE_VIEWER,
    ROLE_INHERIT,
}

# Every rejected sign-in pays one full password verification against this
# hash, whether or not the username names an account, so response timing
# cannot tell an attacker whether a username exists (or is active).
_DUMMY_PASSWORD_HASH = hash_password("ospmae-timing-equaliser-0" * 4)


def get_password_hash(password: str) -> str:
    return hash_password(password)


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).one_or_none()


def get_user_by_email(db: Session, email: str) -> User | None:
    """The account whose e-mail is this address, compared without case."""
    e = (email or "").strip().lower()
    if not e:
        return None
    return db.query(User).filter(func.lower(func.trim(User.email)) == e).one_or_none()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    """Verify local credentials.

    Unknown and inactive accounts verify against the dummy hash, so every
    rejection costs the same work whether or not the username names an
    account: response timing carries no account-existence signal.
    """
    user = get_user_by_username(db, username)
    if user is None or not user.is_active:
        verify_password(password, _DUMMY_PASSWORD_HASH)
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def _remote_user_from_headers(
    headers: Mapping[str, str], socket_peer: str | None = None
) -> str | None:
    """Read the trusted identity header.

    Only the single configured header is honoured, and only when the socket
    peer sits inside the trusted proxy networks: clients can send any header,
    so the value counts as authentication only when a trusted proxy delivered
    it. Deployees must also guarantee the API is reachable through that proxy
    alone, and that the proxy sets (or clears) the header on every route.
    """

    if not bool(settings.trust_remote_user):
        return None

    from app.security.client_addr import socket_peer_trusted

    if not socket_peer_trusted(socket_peer):
        return None

    configured = (settings.remote_user_header_name or "").strip() or "REMOTE_USER"
    raw = headers.get(configured)
    if raw is None:
        return None
    value = str(raw).strip()
    if not value:
        return None
    return value


def get_current_user_from_headers_cookies(
    headers: Mapping[str, str],
    cookies: Mapping[str, str],
    db: Session,
    socket_peer: str | None = None,
) -> User | None:
    """Return the current user, or None if not authenticated.

    Used by both HTTP requests and WebSocket handshakes; the socket peer gates
    trusted remote-user authentication.
    """
    remote_user = _remote_user_from_headers(headers, socket_peer)
    if remote_user:
        # The authenticating proxy names an existing account; OSPMAE creates
        # none here, as KEEN does not.
        user = get_user_by_username(db, remote_user)
        if user and user.is_active:
            user.last_login_at = datetime.utcnow()
            db.add(user)
            db.commit()
            db.refresh(user)
            return user
        return None

    session_cookie = cookies.get(settings.session_cookie_name)
    if not session_cookie:
        return None

    session_row = get_session(db, session_cookie)
    if not session_row:
        return None

    user = (
        db.query(User)
        .filter(User.id == session_row.user_id, User.is_active == True)  # noqa: E712 - SQLAlchemy boolean column predicate
        .one_or_none()
    )  # noqa: E712
    if not user:
        return None

    # A local session must still prove its second factor against the
    # account's current enrolment; anything stale is deleted and refused.
    from app.security.mfa import local_session_allowed

    if not local_session_allowed(db, user, session_row):
        delete_session(db, session_row.session_id)
        return None

    refresh_session(db, session_row, settings.session_ttl_seconds)
    return user


def get_current_user_from_request(request: Request, db: Session) -> User | None:
    peer = getattr(getattr(request, "client", None), "host", None)
    return get_current_user_from_headers_cookies(
        request.headers, request.cookies, db, peer
    )


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = getattr(request.state, "user", None)
    if user:
        return user

    user = get_current_user_from_request(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    eff = attach_effective_role(db, user)
    if (eff or "") != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def set_session_cookie(response: Response, session_id: str) -> None:
    samesite = (settings.cookie_samesite or "lax").lower()
    if samesite not in ("lax", "strict", "none"):
        samesite = "lax"

    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_id,
        httponly=True,
        secure=bool(settings.cookie_secure),
        samesite=samesite,  # type: ignore[arg-type]
        domain=(settings.cookie_domain or "").strip() or None,
        path="/",
        max_age=int(settings.session_ttl_seconds),
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        domain=(settings.cookie_domain or "").strip() or None,
        path="/",
    )


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    email: str | None = None,
    role: str = ROLE_VIEWER,
    is_active: bool = True,
) -> User:
    uname = (username or "").strip()
    if not uname:
        raise ValueError("username is required")
    # The username is reflected into response headers (X-Project-User) and is
    # compared case-insensitively during SSO linking, so it is restricted to a
    # conservative charset and length.
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", uname):
        raise ValueError(
            "username must be 1-64 characters of letters, digits, '_', '-' or '.'"
        )
    if get_user_by_username(db, uname):
        raise ValueError("username already exists")

    email_norm = None
    if email is not None and email.strip():
        email_norm = single_mailbox(email)
        if email_norm is None:
            raise ValueError("Invalid email address")
        if get_user_by_email(db, email_norm):
            raise ValueError("email already exists")
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 chars")

    normalized = canonicalize_role(role) if (role or "").strip() else ROLE_VIEWER
    if normalized not in ALLOWED_USER_ROLES:
        raise ValueError(
            "role must be one of: admin, framework_admin, maintainer, contributor, engineer, product_owner, architect, viewer, inherit"
        )

    u = User(
        username=uname,
        email=email_norm,
        password_hash=get_password_hash(password),
        role=normalized,
        is_active=bool(is_active),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u
