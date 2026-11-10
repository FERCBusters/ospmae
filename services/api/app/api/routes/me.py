from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.payloads import (
    EmailVerifyPayload,
    MeProfileUpdatePayload,
    UserEmailCreatePayload,
    UserPreferencesUpdatePayload,
    UserShortcutCreatePayload,
)
from app.core.config import settings
from app.db.models import (
    EmailVerificationToken,
    Group,
    Project,
    ProjectSubscription,
    User,
    UserEmail,
    UserGroup,
    UserIdentity,
    UserPreference,
    UserShortcut,
)
from app.db.models import (
    Session as SessionRow,
)
from app.db.session import get_db
from app.security.oidc import any_sso_enabled, get_sso_provider
from app.security.rate_limit import check_rate_limit, record_rate_limit_attempt
from app.security.roles import ROLE_PENDING, attach_effective_role

router = APIRouter()


ALLOWED_START_PAGES = {
    "/index.html",
    "/saved-manifests.html",
    "/project-manage.html",
    "/framework-manage.html",
    "/account.html",
    # Backwards-compatible: previously this page was named Preferences.
    "/preferences.html",
    "/admin.html",
    "/pending.html",
}


def _password_features_enabled() -> bool:
    """Match auth.py behaviour: disable local password flows when external SSO is enabled."""
    return bool(getattr(settings, "local_auth_enabled", True)) and not any_sso_enabled()


def _session_auth_method(request: Request, db: Session) -> str:
    sid = (request.cookies.get(settings.session_cookie_name) or "").strip()
    if not sid:
        return ""
    row = db.query(SessionRow).filter(SessionRow.session_id == sid).one_or_none()
    return str(getattr(row, "auth_method", "") or "") if row else ""


def _resolved_email(db: Session, user: User) -> tuple[str | None, str | None]:
    """Return (email, source) where source is one of: 'user', 'account', 'oidc', or None."""

    if (user.email or "").strip():
        return str(user.email).strip(), "user"

    account_email = (
        db.query(UserEmail)
        .filter(UserEmail.user_id == user.id)
        .order_by(UserEmail.is_primary.desc(), UserEmail.updated_at.desc())
        .first()
    )
    if account_email:
        return str(account_email.email).strip(), "account"

    ident = (
        db.query(UserIdentity.email)
        .filter(UserIdentity.user_id == user.id)
        .filter(UserIdentity.email.isnot(None))
        .order_by(desc(UserIdentity.updated_at))  # type: ignore[arg-type]  # SQLAlchemy accepts bool filters and desc() chains
        .first()
    )
    if ident and ident[0]:
        return str(ident[0]).strip(), "oidc"
    return None, None


def _normalize_email(value: str | None) -> str | None:
    email = str(value or "").strip().lower()
    if not email:
        return None
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=400, detail="Invalid email address")
    return email


def _maybe_send_email_verification(db: Session, user: User, row: UserEmail) -> None:
    """Email a one-time mailbox proof for a self-asserted address.

    Fails closed: with no SMTP configured or no explicit public base URL, the
    address simply stays unverified and SSO linking will never trust it.
    """

    if bool(row.is_verified):
        return
    smtp_host = (settings.smtp_host or "").strip()
    from_email = (settings.smtp_from_email or "").strip()
    base = (settings.public_base_url or "").strip().rstrip("/")
    if not smtp_host or not from_email or not base:
        return

    import hashlib
    import secrets as _secrets

    # Verification senders are rate limited per account.
    allowed, _info = check_rate_limit(
        db, f"email_verify:{int(user.id)}", max_attempts=5, window_seconds=3600
    )
    if not allowed:
        return
    record_rate_limit_attempt(db, f"email_verify:{int(user.id)}")

    token = _secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.utcnow()
    db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.email_lower == row.email_lower,
        EmailVerificationToken.used_at.is_(None),
    ).update({"used_at": now}, synchronize_session=False)
    db.add(
        EmailVerificationToken(
            user_id=user.id,
            email_lower=row.email_lower,
            token_hash=token_hash,
            created_at=now,
            expires_at=now + timedelta(seconds=60 * 60 * 24),
            used_at=None,
        )
    )
    db.commit()

    try:
        from app.services.mailer import send_email_verification_email

        send_email_verification_email(
            to_email=row.email,
            username=user.username,
            verification_link=f"{base}/account.html?verify_email={token}",
        )
    except Exception:
        # Mail failures must not block saving the account email.
        pass


def _serialize_user_email(row: UserEmail) -> dict:
    return {
        "id": int(row.id),
        "email": row.email,
        "source": row.source,
        "is_primary": bool(row.is_primary),
        "is_verified": bool(row.is_verified),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _ensure_user_email_row(
    db: Session,
    *,
    user_id: int,
    email: str,
    source: str = "user",
    is_primary: bool = False,
    is_verified: bool = False,
) -> UserEmail:
    normalized = _normalize_email(email)
    assert normalized is not None

    existing = (
        db.query(UserEmail).filter(UserEmail.email_lower == normalized).one_or_none()
    )
    if existing:
        if existing.user_id != user_id:
            raise HTTPException(
                status_code=409, detail="Email address already belongs to another user"
            )
        if is_primary:
            (
                db.query(UserEmail)
                .filter(UserEmail.user_id == user_id, UserEmail.is_primary == True)  # noqa: E712 - SQLAlchemy boolean column predicate
                .update({"is_primary": False}, synchronize_session=False)
            )  # noqa: E712
            existing.is_primary = True
        existing.is_verified = bool(existing.is_verified or is_verified)
        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing

    if is_primary:
        (
            db.query(UserEmail)
            .filter(UserEmail.user_id == user_id, UserEmail.is_primary == True)  # noqa: E712 - SQLAlchemy boolean column predicate
            .update({"is_primary": False}, synchronize_session=False)
        )  # noqa: E712

    row = UserEmail(
        user_id=user_id,
        email=normalized,
        email_lower=normalized,
        source=source,
        is_primary=bool(is_primary),
        is_verified=bool(is_verified),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _normalize_color(value: str | None) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    if not raw.startswith("#"):
        raw = f"#{raw}"
    if len(raw) != 7:
        return None
    if not all(ch in "0123456789abcdef#" for ch in raw):
        return None
    return raw


def _normalize_node_colors(value: dict | None) -> dict[str, str]:
    """Normalize node color overrides.

    Accepted structures:
      - Flattened (preferred): {"uwra:channel_tier": "#RRGGBB", ...}
      - Nested (legacy): {"uwra": {"channel_tier": "#RRGGBB", ...}, ...}
    """

    if not isinstance(value, dict):
        return {}

    out: dict[str, str] = {}

    for raw_key, raw_val in value.items():
        # Flattened form
        if isinstance(raw_val, str) or raw_val is None:
            full_key = str(raw_key or "").strip()
            if not full_key:
                continue
            color = _normalize_color(str(raw_val))
            if not color:
                continue
            if ":" not in full_key:
                # Backwards-compatible upgrade path: assume uwra when no framework prefix.
                full_key = f"uwra:{full_key}"
            fw, nk = full_key.split(":", 1)
            fw = fw.strip().lower()
            nk = nk.strip()
            if not fw or not nk:
                continue
            out[f"{fw}:{nk}"] = color
            continue

        # Nested form
        if isinstance(raw_val, dict):
            fw = str(raw_key or "").strip().lower()
            if not fw:
                continue
            for node_key, node_color in raw_val.items():
                nk = str(node_key or "").strip()
                if not nk:
                    continue
                color = _normalize_color(str(node_color))
                if not color:
                    continue
                out[f"{fw}:{nk}"] = color
            continue

    return out


def _pages_allowed_for_role(user: User) -> set[str]:
    role = str(getattr(user, "effective_role", "") or "").lower()
    if role == ROLE_PENDING:
        return {"/pending.html"}

    allowed = {
        "/index.html",
        "/account.html",
        # Backwards-compatible: previously this page was named Preferences.
        "/preferences.html",
    }

    if role in {"admin", "architect", "product_owner"}:
        allowed.add("/saved-manifests.html")

    if role in {"admin", "maintainer"}:
        allowed.add("/project-manage.html")

    if role in {"admin", "framework_admin"}:
        allowed.add("/framework-manage.html")

    if role == "admin":
        allowed.add("/admin.html")

    return allowed


def _normalize_start_page(
    value: str | None, allowed_pages: set[str] | None = None
) -> str:
    allowed = allowed_pages or ALLOWED_START_PAGES
    if allowed == {"/pending.html"}:
        return "/pending.html"

    raw = str(value or "").strip()
    if not raw:
        return "/index.html"
    if not raw.startswith("/"):
        raw = f"/{raw}"

    # Backwards-compatible rename.
    if raw == "/preferences.html":
        raw = "/account.html"

    if raw not in allowed:
        return "/index.html"
    return raw


# Keep this list in sync with the shared design system's palettes
# (mosp-design-system src/js/05-theme-attributes.js).
ALLOWED_THEMES: list[tuple[str, str]] = [
    ("ink", "Ink"),
    ("sand", "Sand"),
    ("ocean", "Ocean"),
    ("forest", "Forest"),
    ("sunset", "Sunset"),
    ("rose", "Rose"),
    ("slate", "Slate"),
    ("teal", "Teal"),
    ("purple", "Purple"),
]
ALLOWED_THEMES += [
    (f"{theme_id}-dark", f"{name} (dark)") for theme_id, name in ALLOWED_THEMES.copy()
]


def _validate_theme(theme: str | None) -> str:
    candidate = (theme or "").strip()
    if not candidate:
        return ""
    if candidate not in {t[0] for t in ALLOWED_THEMES}:
        raise HTTPException(status_code=400, detail="Unknown theme")
    return candidate


def _serialize_preferences(
    pref: UserPreference | None, allowed_pages: set[str] | None = None
) -> dict:
    if not pref:
        return {
            "theme": "ink",
            "node_colors": {},
            "default_start_page": _normalize_start_page(None, allowed_pages),
            "sticky_enabled": False,
            "auto_apply_enabled": True,
        }

    return {
        "node_colors": _normalize_node_colors(pref.node_colors),
        "default_start_page": _normalize_start_page(
            pref.default_start_page, allowed_pages
        ),
        "sticky_enabled": bool(getattr(pref, "sticky_enabled", False)),
        "auto_apply_enabled": bool(getattr(pref, "auto_apply_enabled", True)),
        "theme": _serialize_theme(getattr(pref, "theme", None)),
    }


def _serialize_theme(theme: str | None) -> str:
    candidate = (theme or "").strip()
    if candidate and candidate in {t[0] for t in ALLOWED_THEMES}:
        return candidate
    return "ink"


def _get_or_create_preferences(db: Session, user_id: int) -> UserPreference:
    pref = (
        db.query(UserPreference).filter(UserPreference.user_id == user_id).one_or_none()
    )
    if pref:
        return pref

    pref = UserPreference(
        user_id=user_id,
        node_colors={},
        default_start_page="/index.html",
        sticky_enabled=False,
        auto_apply_enabled=True,
    )
    db.add(pref)
    db.flush()
    return pref


@router.get("/v1/me")
def me(request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    eff = attach_effective_role(db, user)
    allowed_pages = _pages_allowed_for_role(user)
    pref = (
        db.query(UserPreference).filter(UserPreference.user_id == user.id).one_or_none()
    )
    csrf_token = (request.cookies.get(settings.csrf_cookie_name) or "").strip() or None

    # Logout helpers consumed by the shared MOSP navbar.
    # If the current session is an OIDC session and an end-session endpoint is
    # configured, expose a browser-friendly logout URL that will clear the local
    # session and then redirect to the provider for RP-initiated logout.
    logout_url = None
    auth_method = _session_auth_method(request, db) or "local"
    if auth_method != "local" and get_sso_provider(auth_method):
        logout_url = "/v1/auth/logout"

    email, email_source = _resolved_email(db, user)
    email_editable = auth_method == "local"

    return {
        "id": user.id,
        "username": user.username,
        "email": email,
        "email_source": email_source,
        "email_editable": email_editable,
        "auth_method": auth_method,
        "password_features_enabled": _password_features_enabled(),
        "role": user.role,
        "effective_role": eff,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at,
        "csrf_token": csrf_token,
        "app_title": settings.app_title,
        "preferences": _serialize_preferences(pref, allowed_pages),
        "available_themes": [{"id": t[0], "name": t[1]} for t in ALLOWED_THEMES],
        "logout_url": logout_url,
        "logout_redirect": "/login.html",
    }


@router.get("/v1/me/emails")
def list_my_emails(request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Keep the account-email table in sync with the legacy profile email,
    # without marking a self-asserted address verified.
    if (user.email or "").strip():
        _ensure_user_email_row(
            db,
            user_id=user.id,
            email=str(user.email),
            source="user",
            is_primary=False,
        )

    rows = (
        db.query(UserEmail)
        .filter(UserEmail.user_id == user.id)
        .order_by(UserEmail.is_primary.desc(), UserEmail.email.asc())
        .all()
    )
    return {"items": [_serialize_user_email(row) for row in rows]}


@router.post("/v1/me/emails")
def add_my_email(
    payload: UserEmailCreatePayload, request: Request, db: Session = Depends(get_db)
):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    row = _ensure_user_email_row(
        db,
        user_id=user.id,
        email=payload.email,
        source="user",
        is_primary=bool(payload.is_primary),
        # Local account additions are self-asserted: the row starts
        # unverified and a mailbox proof (verification email) can mark it
        # verified. A verified mailbox is what SSO auto-linking trusts.
        is_verified=False,
    )

    # If the user explicitly marks an address primary, keep the legacy user.email
    # column aligned because existing notification code reads it directly.
    if bool(payload.is_primary):
        user.email = row.email
        db.add(user)
        db.commit()

    _maybe_send_email_verification(db, user, row)

    return _serialize_user_email(row)


@router.post("/v1/me/emails/{email_id}/primary")
def make_my_email_primary(
    email_id: int, request: Request, db: Session = Depends(get_db)
):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    row = (
        db.query(UserEmail)
        .filter(UserEmail.id == email_id, UserEmail.user_id == user.id)
        .one_or_none()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Email address not found")

    (
        db.query(UserEmail)
        .filter(UserEmail.user_id == user.id, UserEmail.is_primary == True)  # noqa: E712 - SQLAlchemy boolean column predicate
        .update({"is_primary": False}, synchronize_session=False)
    )  # noqa: E712
    row.is_primary = True
    user.email = row.email
    db.add(row)
    db.add(user)
    db.commit()
    db.refresh(row)
    return _serialize_user_email(row)


@router.delete("/v1/me/emails/{email_id}")
def delete_my_email(email_id: int, request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    row = (
        db.query(UserEmail)
        .filter(UserEmail.id == email_id, UserEmail.user_id == user.id)
        .one_or_none()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Email address not found")

    was_primary = bool(row.is_primary)
    row_email = row.email
    db.delete(row)
    db.commit()

    if was_primary or (user.email or "").strip().lower() == row_email.lower():
        replacement = (
            db.query(UserEmail)
            .filter(UserEmail.user_id == user.id)
            .order_by(UserEmail.is_verified.desc(), UserEmail.email.asc())
            .first()
        )
        user.email = replacement.email if replacement else None
        if replacement:
            replacement.is_primary = True
            db.add(replacement)
        db.add(user)
        db.commit()

    return {"deleted": True}


@router.post("/v1/me/emails/{email_id}/verify-request")
def request_email_verification(
    email_id: int, request: Request, db: Session = Depends(get_db)
):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    row = (
        db.query(UserEmail)
        .filter(UserEmail.id == email_id, UserEmail.user_id == user.id)
        .one_or_none()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Email address not found")
    if bool(row.is_verified):
        return {"queued": False, "reason": "already verified"}
    _maybe_send_email_verification(db, user, row)
    return {"queued": True}


@router.post("/v1/me/emails/verify")
def verify_my_email(payload: EmailVerifyPayload, db: Session = Depends(get_db)):
    import hashlib

    token = (payload.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Invalid token")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = (
        db.query(EmailVerificationToken)
        .filter(EmailVerificationToken.token_hash == token_hash)
        .one_or_none()
    )
    now = datetime.utcnow()
    if not row or row.used_at is not None or row.expires_at <= now:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    email_row = (
        db.query(UserEmail)
        .filter(
            UserEmail.user_id == row.user_id, UserEmail.email_lower == row.email_lower
        )
        .one_or_none()
    )
    if not email_row:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    row.used_at = now
    email_row.is_verified = True
    db.add(row)
    db.add(email_row)
    db.commit()

    return {"verified": email_row.email}


@router.get("/v1/me/groups")
def my_groups(request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    rows = (
        db.query(Group.id, Group.name)
        .join(UserGroup, UserGroup.group_id == Group.id)
        .filter(UserGroup.user_id == user.id)
        .order_by(Group.name.asc())
        .all()
    )
    return {"items": [{"id": int(gid), "name": str(name)} for (gid, name) in rows]}


@router.get("/v1/me/subscriptions")
def list_my_subscriptions(request: Request, db: Session = Depends(get_db)):
    """List the authenticated user's project subscriptions.

    Used by account.html so users can manage subscriptions without visiting each project.
    """

    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    rows = (
        db.query(ProjectSubscription, Project)
        .join(Project, Project.id == ProjectSubscription.project_id)
        .filter(ProjectSubscription.user_id == user.id)
        .order_by(Project.display_name.asc())
        .all()
    )

    items = []
    for sub, proj in rows:
        items.append(
            {
                "project_id": int(proj.id),
                "project_name": str(proj.display_name or proj.machine_name),
                "project_machine_name": str(proj.machine_name),
                "organisation": str(proj.organisation) if proj.organisation else None,
                "project_type": str(proj.project_type) if proj.project_type else None,
                "notify_new_versions": bool(getattr(sub, "notify_new_versions", True)),
                "notify_questions": bool(getattr(sub, "notify_questions", False)),
            }
        )

    return {"items": items}


@router.put("/v1/me/profile")
def update_my_profile(
    payload: MeProfileUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    auth_method = _session_auth_method(request, db) or "local"
    if auth_method != "local":
        raise HTTPException(
            status_code=403,
            detail="Primary email is managed through the account emails list for SSO sessions",
        )

    # Basic validation.
    raw = str(payload.email or "").strip()
    new_email = raw or None
    if new_email is not None:
        if "@" not in new_email or new_email.startswith("@") or new_email.endswith("@"):
            raise HTTPException(status_code=400, detail="Invalid email address")

    # Enforce uniqueness (case-insensitive-ish).
    if new_email is not None:
        existing = (
            db.query(User.id)
            .filter(User.id != user.id)
            .filter(User.email.isnot(None))
            .filter(User.email.ilike(new_email))
            .one_or_none()
        )
        existing_alias = (
            db.query(UserEmail.id)
            .filter(UserEmail.email_lower == new_email.lower())
            .filter(UserEmail.user_id != user.id)
            .one_or_none()
        )
        if existing or existing_alias:
            raise HTTPException(status_code=409, detail="Email address already in use")

    user.email = new_email
    db.add(user)
    db.commit()
    db.refresh(user)

    if new_email:
        row = _ensure_user_email_row(
            db,
            user_id=user.id,
            email=new_email,
            source="user",
            is_primary=True,
            # Self-asserted profile addresses stay unverified until the
            # mailbox is proven with a verification link.
            is_verified=False,
        )
        _maybe_send_email_verification(db, user, row)

    return {"email": user.email}


@router.get("/v1/me/preferences")
def get_my_preferences(request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    attach_effective_role(db, user)
    allowed_pages = _pages_allowed_for_role(user)

    pref = (
        db.query(UserPreference).filter(UserPreference.user_id == user.id).one_or_none()
    )
    return _serialize_preferences(pref, allowed_pages)


@router.put("/v1/me/preferences")
def update_my_preferences(
    payload: UserPreferencesUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    attach_effective_role(db, user)
    allowed_pages = _pages_allowed_for_role(user)

    pref = _get_or_create_preferences(db, user.id)

    if payload.node_colors is not None:
        pref.node_colors = _normalize_node_colors(payload.node_colors)

    if payload.default_start_page is not None:
        pref.default_start_page = _normalize_start_page(
            payload.default_start_page, allowed_pages
        )

    if payload.sticky_enabled is not None:
        pref.sticky_enabled = bool(payload.sticky_enabled)

    if payload.auto_apply_enabled is not None:
        pref.auto_apply_enabled = bool(payload.auto_apply_enabled)

    if payload.theme is not None:
        pref.theme = _validate_theme(payload.theme)

    db.add(pref)
    db.commit()
    db.refresh(pref)

    return _serialize_preferences(pref, allowed_pages)


# -----------------------------------------------------------------------------
# Shortcuts (saved page views / filter URLs)
# -----------------------------------------------------------------------------


def _normalize_shortcut_url(value: str | None) -> str:
    import re as _re

    from app.security.url_safety import safe_relative_route_path

    raw = str(value or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="url is required")

    # Only same-origin relative routes are safe to navigate to from the
    # navbar: the shared helper rejects absolute URLs, protocol-relative URLs
    # (//evil), backslashes and control characters. A prefix that would turn
    # into a scheme-like path (//javascript:alert(1) aside, "/js:" shaped
    # values) is refused too.
    prefixed = raw if raw.startswith("/") else f"/{raw}"
    safe = safe_relative_route_path(prefixed)
    if not safe or safe != prefixed:
        raise HTTPException(status_code=400, detail="url must be a same-origin path")
    if _re.match(r"^/[A-Za-z][A-Za-z0-9+.\-]*:", safe):
        raise HTTPException(status_code=400, detail="url must not contain a scheme")

    if len(raw) > 4000:
        raise HTTPException(status_code=400, detail="url is too long")
    return safe


@router.get("/v1/me/shortcuts")
def list_my_shortcuts(request: Request, db: Session = Depends(get_db)) -> list[dict]:
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    rows = (
        db.query(UserShortcut)
        .filter(UserShortcut.user_id == user.id)
        .order_by(desc(UserShortcut.updated_at), UserShortcut.name.asc())  # type: ignore[arg-type]  # desc() chains are accepted by Query
        .all()
    )

    return [
        {
            "id": r.id,
            "name": r.name,
            "url": r.url,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        }
        for r in rows
    ]


@router.post("/v1/me/shortcuts")
def upsert_my_shortcut(
    payload: UserShortcutCreatePayload, request: Request, db: Session = Depends(get_db)
) -> dict:
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if len(name) > 200:
        raise HTTPException(status_code=400, detail="name is too long")

    url = _normalize_shortcut_url(payload.url)

    existing = (
        db.query(UserShortcut)
        .filter(UserShortcut.user_id == user.id)
        .filter(UserShortcut.name == name)
        .one_or_none()
    )

    if existing:
        existing.url = url
        existing.updated_at = datetime.utcnow()
        db.add(existing)
        db.commit()
        db.refresh(existing)
        r = existing
    else:
        r = UserShortcut(
            user_id=user.id,
            name=name,
            url=url,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(r)
        db.commit()
        db.refresh(r)

    return {
        "id": r.id,
        "name": r.name,
        "url": r.url,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }


@router.delete("/v1/me/shortcuts/{shortcut_id}")
def delete_my_shortcut(
    shortcut_id: int, request: Request, db: Session = Depends(get_db)
) -> dict:
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    row = (
        db.query(UserShortcut)
        .filter(UserShortcut.id == int(shortcut_id))
        .filter(UserShortcut.user_id == user.id)
        .one_or_none()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Not found")

    db.delete(row)
    db.commit()
    return {"ok": True}
