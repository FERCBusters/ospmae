from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import jwt
from authlib.oidc.core import CodeIDToken
from fastapi import HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import OidcLoginState, User, UserEmail, UserIdentity
from app.security.auth import get_password_hash, get_user_by_username
from app.security.roles import canonicalize_role


@dataclass(frozen=True)
class SsoProvider:
    key: str
    kind: str
    label: str
    enabled: bool
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    scopes: str
    redirect_uri: str = ""
    issuer: str = ""
    jwks_uri: str = ""
    userinfo_endpoint: str = ""
    emails_endpoint: str = ""
    end_session_endpoint: str = ""
    post_logout_redirect_uri: str = ""
    username_claims: str = "preferred_username,email"
    allowed_email_domains: str = ""
    auto_provision: bool = False
    auto_provision_role: str = "pending"
    auto_link_existing: bool = True
    token_endpoint_auth_method: str = "client_secret_basic"
    supports_id_token: bool = True
    id_token_leeway_seconds: int = 60
    legacy_oidc_routes: bool = False

    def public_dict(self) -> dict[str, str]:
        return {
            "key": self.key,
            "label": self.label,
            "kind": self.kind,
            "start_url": provider_start_url(self),
        }


def _now() -> datetime:
    return datetime.utcnow()


def _split_csv(value: str) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def _setting(name: str, default: Any = "") -> Any:
    return getattr(settings, name, default)


def _first_nonempty(*values: Any) -> str:
    for v in values:
        s = str(v or "").strip()
        if s:
            return s
    return ""


def _oidc_provider() -> SsoProvider:
    return SsoProvider(
        key="oidc",
        kind="oidc",
        label=_first_nonempty(_setting("oidc_provider_label", ""), "OpenID Connect"),
        enabled=bool(_setting("oidc_sso_enabled", False)),
        client_id=_first_nonempty(_setting("oidc_client_id", "")),
        client_secret=_first_nonempty(_setting("oidc_client_secret", "")),
        authorization_endpoint=_first_nonempty(
            _setting("oidc_authorization_endpoint", "")
        ),
        token_endpoint=_first_nonempty(_setting("oidc_token_endpoint", "")),
        jwks_uri=_first_nonempty(_setting("oidc_jwks_uri", "")),
        issuer=_first_nonempty(_setting("oidc_issuer", "")),
        userinfo_endpoint=_first_nonempty(_setting("oidc_userinfo_endpoint", "")),
        scopes=_first_nonempty(_setting("oidc_scopes", ""), "openid email profile"),
        redirect_uri=_first_nonempty(_setting("oidc_redirect_uri", "")),
        end_session_endpoint=_first_nonempty(_setting("oidc_end_session_endpoint", "")),
        post_logout_redirect_uri=_first_nonempty(
            _setting("oidc_post_logout_redirect_uri", "")
        ),
        username_claims=_first_nonempty(
            _setting("oidc_username_claims", ""),
            "preferred_username,email",
        ),
        allowed_email_domains=_first_nonempty(
            _setting("oidc_allowed_email_domains", "")
        ),
        auto_provision=bool(_setting("oidc_auto_provision", False)),
        auto_provision_role=_first_nonempty(
            _setting("oidc_auto_provision_role", ""), "pending"
        ),
        auto_link_existing=bool(_setting("oidc_auto_link_existing", True)),
        token_endpoint_auth_method="client_secret_basic",
        supports_id_token=True,
        id_token_leeway_seconds=int(_setting("oidc_id_token_leeway_seconds", 60) or 0),
    )


def _google_provider() -> SsoProvider:
    return SsoProvider(
        key="google",
        kind="oidc",
        label=_first_nonempty(_setting("google_provider_label", ""), "Google"),
        enabled=bool(_setting("google_sso_enabled", False)),
        client_id=_first_nonempty(_setting("google_client_id", "")),
        client_secret=_first_nonempty(_setting("google_client_secret", "")),
        authorization_endpoint=_first_nonempty(
            _setting("google_authorization_endpoint", ""),
            "https://accounts.google.com/o/oauth2/v2/auth",
        ),
        token_endpoint=_first_nonempty(
            _setting("google_token_endpoint", ""),
            "https://oauth2.googleapis.com/token",
        ),
        jwks_uri=_first_nonempty(
            _setting("google_jwks_uri", ""),
            "https://www.googleapis.com/oauth2/v3/certs",
        ),
        issuer=_first_nonempty(
            _setting("google_issuer", ""),
            "https://accounts.google.com,accounts.google.com",
        ),
        userinfo_endpoint=_first_nonempty(
            _setting("google_userinfo_endpoint", ""),
            "https://openidconnect.googleapis.com/v1/userinfo",
        ),
        scopes=_first_nonempty(_setting("google_scopes", ""), "openid email profile"),
        redirect_uri=_first_nonempty(_setting("google_redirect_uri", "")),
        end_session_endpoint=_first_nonempty(
            _setting("google_end_session_endpoint", "")
        ),
        post_logout_redirect_uri=_first_nonempty(
            _setting("google_post_logout_redirect_uri", "")
        ),
        username_claims=_first_nonempty(
            _setting("google_username_claims", ""), "email"
        ),
        allowed_email_domains=_first_nonempty(
            _setting("google_allowed_email_domains", "")
        ),
        auto_provision=bool(_setting("google_auto_provision", False)),
        auto_provision_role=_first_nonempty(
            _setting("google_auto_provision_role", ""), "pending"
        ),
        auto_link_existing=bool(_setting("google_auto_link_existing", True)),
        token_endpoint_auth_method="client_secret_post",
        supports_id_token=True,
    )


def _github_provider() -> SsoProvider:
    return SsoProvider(
        key="github",
        kind="github",
        label=_first_nonempty(_setting("github_provider_label", ""), "GitHub"),
        enabled=bool(_setting("github_sso_enabled", False)),
        client_id=_first_nonempty(_setting("github_client_id", "")),
        client_secret=_first_nonempty(_setting("github_client_secret", "")),
        authorization_endpoint=_first_nonempty(
            _setting("github_authorization_endpoint", ""),
            "https://github.com/login/oauth/authorize",
        ),
        token_endpoint=_first_nonempty(
            _setting("github_token_endpoint", ""),
            "https://github.com/login/oauth/access_token",
        ),
        userinfo_endpoint=_first_nonempty(
            _setting("github_user_endpoint", ""), "https://api.github.com/user"
        ),
        emails_endpoint=_first_nonempty(
            _setting("github_emails_endpoint", ""),
            "https://api.github.com/user/emails",
        ),
        issuer=_first_nonempty(
            _setting("github_issuer", ""), "https://github.com/login/oauth"
        ),
        scopes=_first_nonempty(_setting("github_scopes", ""), "read:user user:email"),
        redirect_uri=_first_nonempty(_setting("github_redirect_uri", "")),
        allowed_email_domains=_first_nonempty(
            _setting("github_allowed_email_domains", "")
        ),
        auto_provision=bool(_setting("github_auto_provision", False)),
        auto_provision_role=_first_nonempty(
            _setting("github_auto_provision_role", ""), "pending"
        ),
        auto_link_existing=bool(_setting("github_auto_link_existing", True)),
        token_endpoint_auth_method="client_secret_post",
        supports_id_token=False,
    )


def all_sso_providers() -> list[SsoProvider]:
    return [_oidc_provider(), _google_provider(), _github_provider()]


def get_sso_provider(provider_key: str | None) -> SsoProvider | None:
    key = (provider_key or "").strip().lower() or "oidc"
    for provider in all_sso_providers():
        if provider.key == key:
            return provider
    return None


def _canonical_issuer(provider: SsoProvider) -> str:
    values = _split_csv(provider.issuer)
    return values[0] if values else (provider.issuer or "")


def provider_start_url(provider: SsoProvider) -> str:
    if provider.legacy_oidc_routes:
        return "/v1/auth/oidc/start"
    return f"/v1/auth/sso/{provider.key}/start"


def configured_sso_providers() -> list[SsoProvider]:
    out: list[SsoProvider] = []
    for provider in all_sso_providers():
        if not provider.enabled:
            continue
        try:
            _require_provider_config(provider.key)
        except HTTPException:
            continue
        out.append(provider)
    return out


def any_sso_enabled() -> bool:
    return any(p.enabled for p in all_sso_providers())


def _required_missing(provider: SsoProvider) -> list[str]:
    prefix = {
        "oidc": "OSPMAE_OIDC",
        "google": "OSPMAE_GOOGLE",
        "github": "OSPMAE_GITHUB",
    }.get(provider.key, f"OSPMAE_{provider.key.upper()}")

    missing: list[str] = []
    if not provider.client_id:
        missing.append(f"{prefix}_CLIENT_ID")
    if not provider.client_secret:
        missing.append(f"{prefix}_CLIENT_SECRET")
    if not provider.authorization_endpoint:
        missing.append(f"{prefix}_AUTHORIZATION_ENDPOINT")
    if not provider.token_endpoint:
        missing.append(f"{prefix}_TOKEN_ENDPOINT")
    if not provider.redirect_uri:
        # Never derived from request hosts: the callback address is fixed.
        missing.append(f"{prefix}_REDIRECT_URI")
    if provider.kind == "oidc":
        if not provider.jwks_uri:
            missing.append(f"{prefix}_JWKS_URI")
        if not provider.issuer:
            missing.append(f"{prefix}_ISSUER")
    if provider.kind == "github" and not provider.userinfo_endpoint:
        missing.append(f"{prefix}_USER_ENDPOINT")
    return missing


def _require_provider_config(provider_key: str | None) -> SsoProvider:
    provider = get_sso_provider(provider_key)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="SSO provider disabled")

    missing = _required_missing(provider)
    if missing:
        raise HTTPException(
            status_code=500,
            detail=(
                f"{provider.label} SSO is enabled but required settings are missing: "
                f"{', '.join(missing)}"
            ),
        )
    return provider


_JWKS_CACHE: dict[str, tuple[dict[str, Any], datetime]] = {}


def _new_client(provider: SsoProvider, *, redirect_uri: str) -> AsyncOAuth2Client:
    scopes = (provider.scopes or "openid email profile").strip() or "openid"
    return AsyncOAuth2Client(
        client_id=provider.client_id,
        client_secret=provider.client_secret,
        scope=scopes,
        redirect_uri=redirect_uri,
        token_endpoint_auth_method=provider.token_endpoint_auth_method,
        # Enable PKCE (S256) for providers that support it. GitHub ignores this
        # safely for OAuth apps that do not require PKCE.
        code_challenge_method="S256",
        timeout=httpx.Timeout(10.0),
    )


async def _get_jwks(jwks_uri: str) -> dict[str, Any]:
    now = _now()
    cached = _JWKS_CACHE.get(jwks_uri)
    if cached:
        data, expires_at = cached
        if now < expires_at:
            return data

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        data = resp.json()
    if not isinstance(data, dict) or "keys" not in data:
        raise HTTPException(status_code=500, detail="OIDC JWKS response invalid")

    _JWKS_CACHE[jwks_uri] = (data, now + timedelta(hours=1))
    return data


def _redirect_uri_from_request(request: Request, provider: SsoProvider) -> str:
    configured = (provider.redirect_uri or "").strip()
    if configured:
        return configured

    # A callback address is never derived from the request: the Host header is
    # client-controlled and a derived redirect_uri could be steered by it.
    raise HTTPException(
        status_code=500,
        detail=(
            f"{provider.label} SSO requires an explicit redirect URI "
            "(OSPMAE_OIDC_REDIRECT_URI or the provider-specific setting); it is "
            "not derived from request hosts"
        ),
    )


def create_login_state(db: Session, *, next_url: str | None) -> OidcLoginState:
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(48)

    row = OidcLoginState(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        next_url=(next_url or "").strip() or None,
        expires_at=_now() + timedelta(minutes=10),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def pop_login_state(db: Session, *, state: str) -> OidcLoginState | None:
    key = (state or "").strip()
    if not key:
        return None

    row = db.query(OidcLoginState).filter(OidcLoginState.state == key).one_or_none()
    if not row:
        return None

    if row.expires_at <= _now():
        try:
            db.delete(row)
            db.commit()
        except Exception:
            db.rollback()
        return None

    try:
        db.delete(row)
        db.commit()
    except Exception:
        db.rollback()

    return row


def _normalize_next(next_url: str | None) -> str | None:
    from app.security.url_safety import safe_relative_route_path

    return safe_relative_route_path(next_url)


def _allowed_by_domain(provider: SsoProvider, email: str | None) -> bool:
    domains = _split_csv(provider.allowed_email_domains or "")
    if not domains:
        return True
    if not email or "@" not in email:
        return False
    dom = email.split("@", 1)[1].lower()
    return any(dom == d.lower() for d in domains)


def _claim_first(claims: dict[str, Any], keys: list[str]) -> str | None:
    for k in keys:
        v = claims.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return None


def _clean_username(candidate: str | None) -> str | None:
    if not candidate:
        return None
    if "@" in candidate:
        candidate = candidate.split("@", 1)[0]
    cleaned = "".join(
        ch for ch in candidate if ch.isalnum() or ch in ("_", "-", ".")
    ).strip("._-")
    return cleaned or None


def _derive_username(provider: SsoProvider, claims: dict[str, Any]) -> str | None:
    order = _split_csv(provider.username_claims or "preferred_username,email")
    if not order:
        order = ["preferred_username", "email"]
    candidate = _clean_username(_claim_first(claims, order))
    if candidate:
        return candidate

    sub = str(claims.get("sub") or "").strip()
    if sub:
        return _clean_username(sub[:160])
    return None


def _unique_username(db: Session, base: str) -> str:
    base_clean = (base or "").strip()[:160] or "user"
    if not get_user_by_username(db, base_clean):
        return base_clean

    for i in range(2, 1000):
        cand = f"{base_clean[:150]}_{i}"
        if not get_user_by_username(db, cand):
            return cand
    return f"{base_clean[:140]}_{secrets.token_hex(6)}"


def _claim_email(claims: dict[str, Any]) -> str | None:
    email = str(claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return None
    return email


def _email_is_verified(provider: SsoProvider, claims: dict[str, Any]) -> bool:
    raw = claims.get("email_verified")
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes"}
    # The GitHub callback only sets email after selecting a verified address from
    # /user/emails, so an email in its synthetic claims is safe to link on.
    return provider.key == "github" and bool(_claim_email(claims))


def _single_active_user_by_email(db: Session, email: str) -> User | None:
    """Find the one active account holding this *verified* mailbox.

    Only ``user_emails`` rows marked verified participate: a self-asserted,
    never-proofed address must not route a provider login into an account.
    """

    normalized = (email or "").strip().lower()
    if not normalized:
        return None

    users_by_id: dict[int, User] = {}

    for row in (
        db.query(UserEmail)
        .filter(UserEmail.email_lower == normalized, UserEmail.is_verified == True)  # noqa: E712
        .all()
    ):
        user = db.query(User).filter(User.id == row.user_id).one_or_none()
        if user and bool(getattr(user, "is_active", False)):
            users_by_id[int(user.id)] = user

    if len(users_by_id) > 1:
        raise HTTPException(
            status_code=409,
            detail="Multiple active OSPMAE users already use this SSO email address",
        )
    return next(iter(users_by_id.values()), None)


def _identity_kwargs(
    user: User, provider: SsoProvider, subject: str, claims: dict[str, Any]
) -> dict[str, Any]:
    return {
        "user_id": user.id,
        "provider": provider.key,
        "issuer": _canonical_issuer(provider),
        "subject": subject,
        "email": _claim_email(claims),
        "preferred_username": str(claims.get("preferred_username") or "").strip()
        or None,
        "display_name": str(claims.get("name") or "").strip() or None,
        "claims": claims or {},
    }


def _ensure_user_email(
    db: Session,
    *,
    user: User,
    email: str | None,
    source: str,
    verified: bool,
    primary: bool = False,
) -> None:
    normalized = (email or "").strip().lower()
    if not normalized or "@" not in normalized:
        return

    existing = (
        db.query(UserEmail).filter(UserEmail.email_lower == normalized).one_or_none()
    )
    if existing:
        if existing.user_id == user.id:
            existing.email = normalized
            existing.source = existing.source or source
            existing.is_verified = bool(existing.is_verified or verified)
            existing.is_primary = bool(existing.is_primary or primary)
            db.add(existing)
        return

    if primary:
        (
            db.query(UserEmail)
            .filter(UserEmail.user_id == user.id, UserEmail.is_primary == True)  # noqa: E712 - SQLAlchemy boolean column predicate
            .update({"is_primary": False}, synchronize_session=False)
        )  # noqa: E712

    db.add(
        UserEmail(
            user_id=user.id,
            email=normalized,
            email_lower=normalized,
            source=source,
            is_verified=bool(verified),
            is_primary=bool(primary),
        )
    )


def _link_identity(
    db: Session,
    *,
    user: User,
    provider: SsoProvider,
    subject: str,
    claims: dict[str, Any],
) -> User:
    ident = UserIdentity(**_identity_kwargs(user, provider, subject, claims))
    try:
        user.last_login_at = _now()
        db.add(user)
        db.add(ident)
        _ensure_user_email(
            db,
            user=user,
            email=_claim_email(claims),
            source=f"sso:{provider.key}",
            verified=_email_is_verified(provider, claims),
        )
        db.commit()
        db.refresh(user)
        return user
    except IntegrityError:
        db.rollback()
        ident2 = (
            db.query(UserIdentity)
            .filter(
                UserIdentity.issuer == _canonical_issuer(provider),
                UserIdentity.subject == subject,
            )
            .one_or_none()
        )
        if ident2:
            user2 = db.query(User).filter(User.id == ident2.user_id).one_or_none()
            if user2 and user2.is_active:
                return user2
        raise
    except Exception:
        db.rollback()
        raise


def _get_or_create_user_for_identity(
    db: Session, *, provider: SsoProvider, subject: str, claims: dict[str, Any]
) -> User:
    ident = (
        db.query(UserIdentity)
        .filter(
            UserIdentity.issuer == _canonical_issuer(provider),
            UserIdentity.subject == subject,
        )
        .one_or_none()
    )
    if ident:
        user = db.query(User).filter(User.id == ident.user_id).one_or_none()
        if user and user.is_active:
            try:
                ident.provider = provider.key
                ident.email = _claim_email(claims) or ident.email
                ident.preferred_username = (
                    str(
                        claims.get("preferred_username")
                        or ident.preferred_username
                        or ""
                    ).strip()
                    or None
                )
                ident.display_name = (
                    str(claims.get("name") or ident.display_name or "").strip() or None
                )
                ident.claims = claims or {}
                user.last_login_at = _now()
                db.add(ident)
                db.add(user)
                _ensure_user_email(
                    db,
                    user=user,
                    email=_claim_email(claims),
                    source=f"sso:{provider.key}",
                    verified=_email_is_verified(provider, claims),
                )
                db.commit()
                db.refresh(user)
            except Exception:
                db.rollback()
            return user
        raise HTTPException(status_code=403, detail="User is inactive")

    email = _claim_email(claims)
    if not _allowed_by_domain(provider, email):
        raise HTTPException(status_code=403, detail="Email domain is not allowed")

    if bool(provider.auto_link_existing):
        # Automatic linking needs proof on both sides: the provider must mark
        # the address verified, and OSPMAE must already hold that mailbox as a
        # verified email. Usernames are never linked -- an identity provider's
        # preferred_username claim is selectable by whoever registers it, so
        # matching a local account on it would hand that account over.
        if email and _email_is_verified(provider, claims):
            user = _single_active_user_by_email(db, email)
            if user:
                return _link_identity(
                    db, user=user, provider=provider, subject=subject, claims=claims
                )

    if not bool(provider.auto_provision):
        raise HTTPException(
            status_code=403, detail="No local account linked to this identity"
        )

    base_username = _derive_username(provider, claims) or "user"
    username = _unique_username(db, base_username)
    role = canonicalize_role(provider.auto_provision_role) or "pending"

    user = User(
        username=username,
        password_hash=get_password_hash(secrets.token_urlsafe(24)),
        role=role,
        is_active=True,
        last_login_at=_now(),
    )
    db.add(user)
    db.flush()

    ident = UserIdentity(**_identity_kwargs(user, provider, subject, claims))
    db.add(ident)
    _ensure_user_email(
        db,
        user=user,
        email=_claim_email(claims),
        source=f"sso:{provider.key}",
        verified=_email_is_verified(provider, claims),
        primary=True,
    )
    db.commit()
    db.refresh(user)

    try:
        from app.services.mailer import send_new_user_admin_notification_email

        base_url = (getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
        send_new_user_admin_notification_email(
            username=user.username,
            email=_claim_email(claims),
            provider_label=provider.label,
            role=role,
            admin_url=(f"{base_url}/admin.html" if base_url else None),
        )
    except Exception:
        # Admin notification failures must not break successful SSO login.
        pass

    return user


async def build_authorize_redirect(
    request: Request, db: Session, next_url: str | None, provider_key: str | None = None
) -> str:
    provider = _require_provider_config(provider_key)
    redirect_uri = _redirect_uri_from_request(request, provider)
    state_row = create_login_state(db, next_url=_normalize_next(next_url))

    client = _new_client(provider, redirect_uri=redirect_uri)
    url, _ = client.create_authorization_url(
        provider.authorization_endpoint,
        state=state_row.state,
        nonce=state_row.nonce if provider.supports_id_token else None,
        code_verifier=state_row.code_verifier,
        redirect_uri=redirect_uri,
    )
    url = str(url or "").strip()
    if not url:
        raise HTTPException(status_code=500, detail="Failed to build SSO authorize URL")
    return url


async def _fetch_github_claims(
    provider: SsoProvider, token: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    access_token = str((token or {}).get("access_token") or "").strip()
    if not access_token:
        raise HTTPException(
            status_code=400, detail="GitHub token response missing access_token"
        )

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        user_resp = await client.get(provider.userinfo_endpoint, headers=headers)
        user_resp.raise_for_status()
        user_info = user_resp.json()

        emails: list[dict[str, Any]] = []
        if provider.emails_endpoint:
            email_resp = await client.get(provider.emails_endpoint, headers=headers)
            if email_resp.status_code < 400:
                raw = email_resp.json()
                if isinstance(raw, list):
                    emails = [e for e in raw if isinstance(e, dict)]

    if not isinstance(user_info, dict):
        raise HTTPException(status_code=400, detail="GitHub user response invalid")

    subject = str(user_info.get("id") or "").strip()
    login = str(user_info.get("login") or "").strip()
    if not subject or not login:
        raise HTTPException(
            status_code=400, detail="GitHub user response missing id/login"
        )

    email = str(user_info.get("email") or "").strip().lower() or None
    email_verified = False
    primary_verified = next(
        (
            e
            for e in emails
            if bool(e.get("primary"))
            and bool(e.get("verified"))
            and str(e.get("email") or "").strip()
        ),
        None,
    )
    if primary_verified:
        email = str(primary_verified.get("email") or "").strip().lower() or email
        email_verified = True
    elif email:
        # Public GitHub profile email is not accompanied by a verification flag.
        # Keep it for display, but do not use it for cross-provider linking.
        email_verified = False

    claims = {
        "iss": _canonical_issuer(provider),
        "sub": subject,
        "preferred_username": login,
        "email": email,
        "email_verified": email_verified,
        "name": str(user_info.get("name") or "").strip() or None,
        "github_login": login,
        "github_id": subject,
        "avatar_url": str(user_info.get("avatar_url") or "").strip() or None,
        "html_url": str(user_info.get("html_url") or "").strip() or None,
    }
    return subject, claims


async def _handle_github_callback(
    request: Request, db: Session, provider: SsoProvider, row: OidcLoginState
) -> tuple[User, str | None, str | None]:
    redirect_uri = _redirect_uri_from_request(request, provider)
    client = _new_client(provider, redirect_uri=redirect_uri)
    token = await client.fetch_token(
        provider.token_endpoint,
        authorization_response=str(request.url),
        redirect_uri=redirect_uri,
        code_verifier=row.code_verifier,
    )
    subject, claims = await _fetch_github_claims(provider, token)
    user = _get_or_create_user_for_identity(
        db, provider=provider, subject=subject, claims=claims
    )
    next_url = _normalize_next(row.next_url) or None
    return user, next_url, None


async def _handle_oidc_callback(
    request: Request, db: Session, provider: SsoProvider, row: OidcLoginState
) -> tuple[User, str | None, str | None]:
    redirect_uri = _redirect_uri_from_request(request, provider)
    client = _new_client(provider, redirect_uri=redirect_uri)

    token = await client.fetch_token(
        provider.token_endpoint,
        authorization_response=str(request.url),
        redirect_uri=redirect_uri,
        code_verifier=row.code_verifier,
    )

    id_token = (token or {}).get("id_token")
    if not id_token:
        raise HTTPException(
            status_code=400, detail="OIDC token response missing id_token"
        )

    jwks = await _get_jwks(provider.jwks_uri)

    issuer_values = _split_csv(provider.issuer)
    if not issuer_values:
        issuer_values = [provider.issuer]

    claims_options = {
        "iss": {"essential": True, "values": issuer_values},
        "aud": {"essential": True, "values": [provider.client_id]},
    }
    claims_params = {
        "nonce": row.nonce,
        "client_id": provider.client_id,
        "access_token": (token or {}).get("access_token"),
    }

    claims = jwt.decode(
        id_token,
        jwks,
        claims_cls=CodeIDToken,
        claims_options=claims_options,
        claims_params=claims_params,
    )
    claims.validate(leeway=int(provider.id_token_leeway_seconds or 0))

    claims_dict: dict[str, Any] = dict(claims)
    subject = str(claims_dict.get("sub") or "").strip()
    if not subject:
        raise HTTPException(status_code=400, detail="OIDC claims missing sub")

    # Store the configured provider issuer for identity uniqueness even when a
    # provider accepts more than one issuer string.
    claims_dict["iss"] = _canonical_issuer(provider)

    user = _get_or_create_user_for_identity(
        db, provider=provider, subject=subject, claims=claims_dict
    )
    next_url = _normalize_next(row.next_url) or None
    return user, next_url, str(id_token)


async def handle_callback(
    request: Request, db: Session, provider_key: str | None = None
) -> tuple[User, str | None, str | None, SsoProvider]:
    provider = _require_provider_config(provider_key)
    state = (request.query_params.get("state") or "").strip()
    row = pop_login_state(db, state=state)
    if not row:
        raise HTTPException(status_code=400, detail="SSO state missing or expired")

    if provider.kind == "github":
        user, next_url, id_token = await _handle_github_callback(
            request, db, provider, row
        )
    else:
        user, next_url, id_token = await _handle_oidc_callback(
            request, db, provider, row
        )
    return user, next_url, id_token, provider
