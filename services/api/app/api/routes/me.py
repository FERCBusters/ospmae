from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.payloads import (
    MeProfileUpdatePayload,
    UserEmailCreatePayload,
    UserPreferencesUpdatePayload,
    UserShortcutCreatePayload,
)
from app.core.config import settings
from app.security.oidc import any_sso_enabled, get_sso_provider
from app.db.models import (
    Session as SessionRow,
    User,
    UserEmail,
    UserIdentity,
    UserPreference,
    UserShortcut,
    Group,
    UserGroup,
    Project,
    ProjectSubscription,
)
from app.db.session import get_db
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
        .order_by(desc(UserIdentity.updated_at))
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
                .filter(UserEmail.user_id == user_id, UserEmail.is_primary == True)
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
            .filter(UserEmail.user_id == user_id, UserEmail.is_primary == True)
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


def _serialize_preferences(
    pref: UserPreference | None, allowed_pages: set[str] | None = None
) -> dict:
    if not pref:
        return {
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
    }


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
        "logout_url": logout_url,
        "logout_redirect": "/login.html",
    }


@router.get("/v1/me/emails")
def list_my_emails(request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Keep the account-email table in sync with the legacy profile email.
    if (user.email or "").strip():
        _ensure_user_email_row(
            db,
            user_id=user.id,
            email=str(user.email),
            source="user",
            is_primary=True,
            is_verified=True,
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
        # Local account additions are user-managed aliases. OSPMAE enforces that
        # a given email can belong to only one user and uses these aliases for
        # future SSO linking.
        is_verified=True,
    )

    # If the user explicitly marks an address primary, keep the legacy user.email
    # column aligned because existing notification code reads it directly.
    if bool(payload.is_primary):
        user.email = row.email
        db.add(user)
        db.commit()

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
        .filter(UserEmail.user_id == user.id, UserEmail.is_primary == True)
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
        _ensure_user_email_row(
            db,
            user_id=user.id,
            email=new_email,
            source="user",
            is_primary=True,
            is_verified=True,
        )

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

    db.add(pref)
    db.commit()
    db.refresh(pref)

    return _serialize_preferences(pref, allowed_pages)


# -----------------------------------------------------------------------------
# Shortcuts (saved page views / filter URLs)
# -----------------------------------------------------------------------------


def _normalize_shortcut_url(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="url is required")

    # Only allow same-origin relative URLs.
    if raw.startswith("http://") or raw.startswith("https://"):
        raise HTTPException(status_code=400, detail="url must be a relative path")

    if not raw.startswith("/"):
        raw = f"/{raw}"

    # Basic sanity: avoid whitespace/newlines
    if any(ch.isspace() for ch in raw):
        raise HTTPException(status_code=400, detail="url must not contain whitespace")

    if len(raw) > 4000:
        raise HTTPException(status_code=400, detail="url is too long")
    return raw


@router.get("/v1/me/shortcuts")
def list_my_shortcuts(request: Request, db: Session = Depends(get_db)) -> list[dict]:
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    rows = (
        db.query(UserShortcut)
        .filter(UserShortcut.user_id == user.id)
        .order_by(desc(UserShortcut.updated_at), UserShortcut.name.asc())
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
