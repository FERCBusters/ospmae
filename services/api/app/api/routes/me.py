from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request
from mosp.api.routing import Router
from mosp.core.datetime_utils import utc_now_naive
from mosp.core.valkey import get_valkey
from mosp.security.auth import cookie_name
from mosp.security.csrf import get_csrf_token_from_request
from mosp.security.oidc import configured_sso_providers
from mosp.security.permissions import get_effective_permission_codes, has_permission
from mosp.security.regex import scan_pattern
from mosp.security.roles import attach_effective_role
from mosp.security.sessions import get_session
from mosp.security.urls import same_site_path
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.deps import DbId, PageLimit
from app.api.payloads import (
    UserPreferencesUpdatePayload,
    UserShortcutCreatePayload,
)
from app.core.config import settings
from app.core.features import public_dict
from app.db.models import (
    Group,
    Project,
    ProjectSubscription,
    User,
    UserPreference,
    UserShortcut,
    user_groups,
)
from app.db.session import get_db
from app.security.permissions import PERM_FRAMEWORK_WRITE

router = Router()


ALLOWED_START_PAGES = {
    "/index.html",
    "/manifests.html",
    "/framework-manage.html",
    "/account.html",
    # Backwards-compatible: previously this page was named Preferences.
    "/preferences.html",
    "/admin.html",
}


def _password_features_enabled() -> bool:
    """Whether the account page offers a password change, as KEEN decides it."""
    return (
        bool(getattr(settings, "local_auth_enabled", True))
        and not bool(settings.trust_remote_user)
        and not configured_sso_providers()
    )


def _session_auth_method(request: Request) -> str:
    """How the request's session signed in: local, ldap, oidc or an SSO
    provider's key; empty for a browser a trusted proxy signs in."""
    sid = request.cookies.get(cookie_name())
    if not sid:
        return ""
    try:
        session = get_session(get_valkey(), sid, refresh_ttl_seconds=None)
    except Exception:
        return ""
    return str((session or {}).get("auth_method") or "")


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


# A preference row holds at most this many colour overrides.
_MAX_NODE_COLOURS = 200


def _normalize_node_colors(value: dict | None) -> dict[str, str]:
    """Normalize node color overrides.

    Accepted structures:
      - Flattened (preferred): {"uwra:channel_tier": "#RRGGBB", ...}
      - Nested (legacy): {"uwra": {"channel_tier": "#RRGGBB", ...}, ...}
    """

    if not isinstance(value, dict):
        return {}

    out: dict[str, str] = {}

    for raw_key, raw_val in list(value.items())[:_MAX_NODE_COLOURS]:
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
            if not fw or not nk or len(fw) > 80 or len(nk) > 160:
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
                if not nk or len(fw) > 80 or len(nk) > 160:
                    continue
                color = _normalize_color(str(node_color))
                if not color:
                    continue
                out[f"{fw}:{nk}"] = color
            continue

    return out


def _pages_allowed_for_role(db: Session, user: User) -> set[str]:
    role = str(getattr(user, "effective_role", "") or "").lower()
    allowed = {
        "/index.html",
        "/manifests.html",
        "/account.html",
        # Backwards-compatible: previously this page was named Preferences.
        "/preferences.html",
    }

    if has_permission(db, user, PERM_FRAMEWORK_WRITE):
        allowed.add("/framework-manage.html")

    if role == "admin":
        allowed.add("/admin.html")

    return allowed


def _normalize_start_page(
    value: str | None, allowed_pages: set[str] | None = None
) -> str:
    allowed = allowed_pages or ALLOWED_START_PAGES

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
        "auto_apply_enabled": pref.auto_apply_enabled,
        "theme": _serialize_theme(pref.theme),
    }


def _serialize_theme(theme: str | None) -> str:
    candidate = (theme or "").strip()
    if candidate and candidate in {t[0] for t in ALLOWED_THEMES}:
        return candidate
    return "ink"


def _get_or_create_preferences(db: Session, user_id: uuid.UUID) -> UserPreference:
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
    allowed_pages = _pages_allowed_for_role(db, user)
    pref = (
        db.query(UserPreference).filter(UserPreference.user_id == user.id).one_or_none()
    )
    # The session's own token; a browser signed in by a trusted proxy has no
    # session and repeats its cookie.
    csrf_token = user.session_csrf or get_csrf_token_from_request(request) or None
    auth_method = _session_auth_method(request) or "local"

    return {
        "id": str(user.id),
        "username": user.username,
        # Set by an administrator; account mail goes only here, as in KEEN.
        "email": user.email,
        "auth_method": auth_method,
        "password_features_enabled": _password_features_enabled(),
        "role": user.role,
        "effective_role": eff,
        # The permission codes the account holds, for the pages to choose
        # what to offer; every route checks its own.
        "permissions": sorted(get_effective_permission_codes(db, user)),
        "is_active": user.is_active,
        "last_login_at": user.last_login_at,
        "csrf_token": csrf_token,
        "app_title": settings.app_title,
        "preferences": _serialize_preferences(pref, allowed_pages),
        "available_themes": [{"id": t[0], "name": t[1]} for t in ALLOWED_THEMES],
        # Signing out is a POST here; a provider's session's answer names the
        # provider's end-session page.
        "logout_url": (
            "/api/v1/auth/logout"
            if auth_method in ("local", "ldap")
            else "/api/v1/auth/oidc/logout"
        ),
        "logout_redirect": "/login.html",
        # The navbar renders only the links of features that are on.
        "features": public_dict(db),
    }


@router.get("/v1/me/notifications")
def my_notifications(
    request: Request, db: Session = Depends(get_db), limit: PageLimit = 20
):
    """The account's e-mail outbox history: what was mailed and its state."""
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")
    from app.services.notifications import notification_snapshot

    limit = max(1, min(int(limit or 20), 100))
    return notification_snapshot(db, user_id=user.id, limit=limit)


@router.get("/v1/me/groups")
def my_groups(request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    rows = (
        db.query(Group.id, Group.name)
        .join(user_groups, user_groups.c.group_id == Group.id)
        .filter(user_groups.c.user_id == user.id)
        .order_by(Group.name.asc())
        .all()
    )
    return {"items": [{"id": str(gid), "name": str(name)} for (gid, name) in rows]}


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


@router.get("/v1/me/preferences")
def get_my_preferences(request: Request, db: Session = Depends(get_db)):
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    attach_effective_role(db, user)
    allowed_pages = _pages_allowed_for_role(db, user)

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
    allowed_pages = _pages_allowed_for_role(db, user)

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


_SCHEME_PATH = scan_pattern(r"/[A-Za-z][A-Za-z0-9+.\-]*:")


def _normalize_shortcut_url(value: str) -> str:
    """A shortcut leads to a page of this site only.

    The payload has already refused anything but a path on this site or an
    HTTP(S) URL without credentials (mosp.security.urls.external_url); an
    absolute URL, and a path whose first segment reads as a scheme
    ("/javascript:..."), are refused here.
    """
    raw = value.strip()
    if same_site_path(raw) != raw:
        raise HTTPException(status_code=400, detail="url must be a same-origin path")
    if _SCHEME_PATH.match(raw):
        raise HTTPException(status_code=400, detail="url must not contain a scheme")
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
        existing.updated_at = utc_now_naive()
        db.add(existing)
        db.commit()
        db.refresh(existing)
        r = existing
    else:
        r = UserShortcut(
            user_id=user.id,
            name=name,
            url=url,
            created_at=utc_now_naive(),
            updated_at=utc_now_naive(),
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
    shortcut_id: DbId, request: Request, db: Session = Depends(get_db)
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
