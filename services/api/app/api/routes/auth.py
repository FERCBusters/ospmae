from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
)
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api.payloads import (
    ChangePasswordPayload,
    LoginPayload,
    PasswordResetConfirmPayload,
    PasswordResetRequestPayload,
)
from app.core.config import settings
from app.db.models import (
    PasswordResetToken,
    RateLimitEntry,
    User,
)
from app.db.models import (
    Session as SessionRow,
)
from app.db.session import get_db
from app.security.audit import (
    log_login_failure,
    log_login_success,
    log_logout,
    log_password_reset_confirm,
    log_password_reset_request,
    log_security_alert,
)
from app.security.auth import (
    ROLE_ADMIN,
    authenticate_user,
    clear_session_cookie,
    get_current_user,
    get_password_hash,
    get_user_by_email,
    set_session_cookie,
)
from app.security.client_addr import public_client_address
from app.security.csrf import clear_csrf_cookie, generate_csrf_token, set_csrf_cookie
from app.security.oidc import (
    any_sso_enabled,
    build_authorize_redirect,
    configured_sso_providers,
    get_sso_provider,
    handle_callback,
)
from app.security.passwords import verify_password
from app.security.rate_limit import check_rate_limit, record_rate_limit_attempt
from app.security.roles import ROLE_PENDING, attach_effective_role
from app.security.sessions import (
    create_session,
    delete_all_sessions_for_user,
    delete_session,
)
from app.security.url_safety import safe_relative_route_path
from app.services.mailer import send_password_reset_email
from app.services.notification_recipients import notification_email_for_user

router = APIRouter()


@router.get("/v1/auth/methods")
def auth_methods():
    """Public endpoint describing which login methods are enabled."""
    providers = configured_sso_providers()
    oidc_provider = get_sso_provider("oidc")
    oidc_enabled = bool(
        oidc_provider and any(provider.key == "oidc" for provider in providers)
    )
    allowed_hosts_raw = (
        getattr(settings, "login_redirect_allowed_hosts", "") or ""
    ).strip()
    allowed_hosts = (
        [h.strip().lower() for h in allowed_hosts_raw.split(",") if h.strip()]
        if allowed_hosts_raw
        else []
    )

    sso_providers = [provider.public_dict() for provider in providers]

    return {
        "local_enabled": bool(getattr(settings, "local_auth_enabled", True)),
        "remote_user_enabled": bool(getattr(settings, "trust_remote_user", False)),
        # Backwards-compatible fields for the original single OIDC button.
        "oidc_enabled": oidc_enabled,
        "oidc": (
            {
                "label": oidc_provider.label if oidc_provider else "Single sign-on",
                "start_url": (
                    oidc_provider.public_dict()["start_url"]
                    if oidc_provider
                    else "/v1/auth/oidc/start"
                ),
            }
            if oidc_enabled
            else None
        ),
        # New multi-provider SSO contract for the login page.
        "sso_enabled": bool(sso_providers),
        "sso_providers": sso_providers,
        # Used by the UI to safely handle ?next= after login.
        # Same-origin relative paths are always allowed; this list only applies
        # to absolute cross-origin URLs.
        "redirect_allowed_hosts": allowed_hosts,
        "password_reset_enabled": (
            bool(getattr(settings, "local_auth_enabled", True))
            and not any_sso_enabled()
            and bool((getattr(settings, "smtp_host", "") or "").strip())
            and bool((getattr(settings, "smtp_from_email", "") or "").strip())
        ),
        "password_reset": {
            "request_url": "/v1/auth/request-password-reset",
            "page_url": "/forgot-password.html",
        },
    }


def _get_client_ip(request: Request) -> str:
    """Client address resolved from the trusted-proxy chain, never the first
    X-Forwarded-For entry, which clients control."""
    peer = request.client.host if request.client else None
    return (
        public_client_address(peer, request.headers.get("X-Forwarded-For")) or "unknown"
    )


def _get_user_agent(request: Request) -> str | None:
    return request.headers.get("User-Agent") or None


# Window for the per-address and per-username sign-in allowances.
_LOGIN_WINDOW_SECONDS = 300
_LOGIN_PER_ADDRESS = 10
# Failed attempts one username name may absorb before every further failure
# must run under the controlled-verification allowance below.
_LOGIN_FAILURES_PER_NAME = 15
# Once the failure allowance is spent, at most this many further password
# verifications run per (username, address) window: a legitimate user's
# correct password still logs in, while brute-force work stays bounded.
_LOGIN_VERIFY_BUDGET = 5


def _normalize_login_name(username: str) -> str:
    """The form in which sign-in names are compared for limiting.

    Folds case so spellings that name the same account share one allowance.
    """
    return " ".join(str(username or "").strip().casefold().split())


@router.post("/v1/auth/login")
def login(
    payload: LoginPayload, request: Request, db: Session = Depends(get_db)
) -> Response:
    if not bool(getattr(settings, "local_auth_enabled", True)):
        raise HTTPException(status_code=404, detail="Local auth disabled")

    client_ip = _get_client_ip(request)
    user_agent = _get_user_agent(request)
    username = (payload.username or "").strip()
    # A blank username is refused before any rate limit or password work.
    if not username:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    rate_id = f"login:{client_ip}"

    allowed, info = check_rate_limit(
        db,
        rate_id,
        max_attempts=_LOGIN_PER_ADDRESS,
        window_seconds=_LOGIN_WINDOW_SECONDS,
    )
    if not allowed:
        log_security_alert(
            db,
            "rate_limit_exceeded",
            {"action": "login"},
            None,
            client_ip,
            user_agent,
        )
        return JSONResponse(
            {"detail": "Too many login attempts", "retry_after": info["retry_after"]},
            status_code=429,
            headers={"Retry-After": str(info["retry_after"] // 1000)},
        )

    record_rate_limit_attempt(db, rate_id)

    # One allowance per compared username, keyed by digest so the ledger
    # neither grows with name length nor stores the attempted name.
    from app.security.client_addr import allowance_address

    name_key = hashlib.sha256(
        _normalize_login_name(username).encode("utf-8")
    ).hexdigest()
    user_fail_id = f"login_fail_user:{name_key}"
    user_allowed, user_info = check_rate_limit(
        db,
        user_fail_id,
        max_attempts=_LOGIN_FAILURES_PER_NAME,
        window_seconds=_LOGIN_WINDOW_SECONDS,
    )

    if user_allowed:
        user = authenticate_user(db, payload.username, payload.password)
        if not user:
            record_rate_limit_attempt(db, user_fail_id)
            log_login_failure(
                db, username, "invalid_credentials", client_ip, user_agent
            )
            raise HTTPException(status_code=401, detail="Invalid username or password")
        # Success clears any accumulating failure state for this name.
        db.query(RateLimitEntry).filter(
            RateLimitEntry.identifier == user_fail_id
        ).delete(synchronize_session=False)
        db.commit()
    else:
        # The failure allowance is spent -- someone is attacking this account.
        # A correct password must still sign in: verifications proceed only
        # under a small per-(name, address) budget, so distributed guessing
        # can stay slow while the legitimate user always gets through.
        verify_id = (
            f"login_verify_user:{name_key}:{allowance_address(client_ip) or 'unknown'}"
        )
        verify_allowed, verify_info = check_rate_limit(
            db,
            verify_id,
            max_attempts=_LOGIN_VERIFY_BUDGET,
            window_seconds=_LOGIN_WINDOW_SECONDS,
        )
        if not verify_allowed:
            return JSONResponse(
                {
                    "detail": "Too many failed attempts",
                    "retry_after": user_info["retry_after"],
                },
                status_code=429,
            )
        record_rate_limit_attempt(db, verify_id)
        user = authenticate_user(db, payload.username, payload.password)
        if not user:
            log_login_failure(
                db, username, "invalid_credentials", client_ip, user_agent
            )
            raise HTTPException(status_code=401, detail="Invalid username or password")
        # A success under the spent-failure budget clears the attack state.
        db.query(RateLimitEntry).filter(
            RateLimitEntry.identifier == user_fail_id
        ).delete(synchronize_session=False)
        db.commit()

    delete_all_sessions_for_user(db, user.id)

    from app.security import mfa

    if user.mfa_enabled or mfa.required(db, user):
        # The password is proven; the browser now holds the ceremony cookie
        # while /v1/auth/mfa/* runs outside of any session.
        return mfa.start(db, user, request)

    return complete_local_login(db, user, request)


def complete_local_login(
    db: Session,
    user: User,
    request: Request,
    *,
    mfa_verified: bool = False,
    verified_version: int | None = None,
):
    sid = create_session(
        db,
        user_id=user.id,
        ttl_seconds=int(settings.session_ttl_seconds),
        auth_method="local",
        mfa_verified=bool(mfa_verified),
        mfa_version=int(user.mfa_version)
        if verified_version is None
        else int(verified_version),
    )

    try:
        user.last_login_at = datetime.utcnow()
        db.add(user)
        db.commit()
        request.state.user = user

        log_login_success(
            db, user.id, "local", _get_client_ip(request), _get_user_agent(request)
        )
    except Exception:
        db.rollback()

    eff = attach_effective_role(db, user)
    csrf_token = generate_csrf_token()

    resp = JSONResponse(
        {
            "user": user.username,
            "role": user.role,
            "effective_role": eff,
            "is_admin": (eff or "") == ROLE_ADMIN,
            "csrf_token": csrf_token,
        }
    )
    set_session_cookie(resp, sid)
    set_csrf_cookie(resp, csrf_token)
    return resp


def _limit_sso_start(db: Session, request: Request) -> bool:
    """A small per-address allowance on SSO starts: each writes a login-state
    row, so an unauthenticated flood must not churn the database."""
    allowed, _info = check_rate_limit(
        db, f"sso_start:{_get_client_ip(request)}", max_attempts=20, window_seconds=300
    )
    return allowed


@router.get("/v1/auth/oidc/start")
async def oidc_start(request: Request, db: Session = Depends(get_db)):
    # Stable URL alias for the generic OpenID Connect provider.
    if not _limit_sso_start(db, request):
        raise HTTPException(status_code=429, detail="Too many requests")
    next_url = request.query_params.get("next")
    url = await build_authorize_redirect(
        request, db, next_url=next_url, provider_key="oidc"
    )
    return RedirectResponse(url, status_code=302)


@router.get("/v1/auth/oidc/callback")
async def oidc_callback(request: Request, db: Session = Depends(get_db)):
    # Stable URL alias for the generic OpenID Connect callback.
    return await _complete_sso_callback(request, db, provider_key="oidc")


@router.get("/v1/auth/sso/{provider_key}/start")
async def sso_start(provider_key: str, request: Request, db: Session = Depends(get_db)):
    if not _limit_sso_start(db, request):
        raise HTTPException(status_code=429, detail="Too many requests")
    next_url = request.query_params.get("next")
    url = await build_authorize_redirect(
        request, db, next_url=next_url, provider_key=provider_key
    )
    return RedirectResponse(url, status_code=302)


@router.get("/v1/auth/sso/{provider_key}/callback")
async def sso_callback(
    provider_key: str, request: Request, db: Session = Depends(get_db)
):
    return await _complete_sso_callback(request, db, provider_key=provider_key)


async def _complete_sso_callback(
    request: Request, db: Session, *, provider_key: str
) -> Response:
    user, next_url, id_token, provider = await handle_callback(
        request, db, provider_key=provider_key
    )
    request.state.user = user

    delete_all_sessions_for_user(db, user.id)

    log_login_success(
        db, user.id, provider.key, _get_client_ip(request), _get_user_agent(request)
    )

    sid = create_session(
        db,
        user_id=user.id,
        ttl_seconds=int(settings.session_ttl_seconds),
        auth_method=provider.key,
        oidc_id_token=id_token,
    )
    csrf_token = generate_csrf_token()

    effective_role = attach_effective_role(db, user)
    dest = (
        "/pending.html"
        if effective_role == ROLE_PENDING
        else (next_url or "/index.html")
    )
    resp = RedirectResponse(dest, status_code=302)
    set_session_cookie(resp, sid)
    set_csrf_cookie(resp, csrf_token)
    return resp


@router.post("/v1/auth/logout")
def logout(request: Request, db: Session = Depends(get_db)) -> Response:
    sid = request.cookies.get(settings.session_cookie_name) or ""
    if sid:
        delete_session(db, sid)

    user = getattr(request.state, "user", None)
    if user and isinstance(user, User):
        delete_all_sessions_for_user(db, user.id)
        log_logout(db, user.id, _get_client_ip(request), _get_user_agent(request))

    from app.security import mfa

    resp = Response(status_code=204)
    mfa.cancel(db, request, resp)
    clear_session_cookie(resp)
    clear_csrf_cookie(resp)
    return resp


def _local_password_features_enabled() -> bool:
    # Explicitly disable local password flows when any external SSO provider is enabled.
    return bool(getattr(settings, "local_auth_enabled", True)) and not any_sso_enabled()


def _hash_reset_token(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _derive_public_base_url(request: Request) -> str:
    """The public origin for links sent by email.

    Host headers are client-controlled, so the base URL is never derived from
    the request: without explicit configuration no absolute link can be built
    and mail-dependent flows stay disabled (fail closed).
    """

    configured = (getattr(settings, "public_base_url", "") or "").strip()
    return configured.rstrip("/") if configured else ""


@router.post("/v1/auth/change-password")
def change_password(
    payload: ChangePasswordPayload,
    request: Request,
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    if not _local_password_features_enabled():
        raise HTTPException(status_code=404, detail="Password change disabled")

    # Current-password guessing through a stolen session is bounded per account.
    attempt_id = f"pw_change:{int(me.id)}"
    allowed, _info = check_rate_limit(
        db, attempt_id, max_attempts=5, window_seconds=300
    )
    if not allowed:
        raise HTTPException(
            status_code=429, detail="Too many attempts; try again later"
        )
    record_rate_limit_attempt(db, attempt_id)

    # Only allow password change for local sessions.
    sid = (request.cookies.get(settings.session_cookie_name) or "").strip()
    row = (
        db.query(SessionRow).filter(SessionRow.session_id == sid).one_or_none()
        if sid
        else None
    )
    if row and str(getattr(row, "auth_method", "") or "") != "local":
        raise HTTPException(
            status_code=400,
            detail="Password changes are not available for SSO sessions",
        )

    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if not verify_password(payload.current_password, me.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # The middleware attaches the actor to its own session; this route's
    # session is a different one, so re-read the row here before writing.
    user_row = db.query(User).filter(User.id == me.id).one_or_none()
    if not user_row:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_row.password_hash = get_password_hash(payload.new_password)
    db.add(user_row)
    db.commit()
    return Response(status_code=204)


@router.post("/v1/auth/request-password-reset")
def request_password_reset(
    payload: PasswordResetRequestPayload,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Response:
    if not _local_password_features_enabled():
        # Don't leak configuration details.
        return Response(status_code=204)

    smtp_host = (getattr(settings, "smtp_host", "") or "").strip()
    from_email = (getattr(settings, "smtp_from_email", "") or "").strip()
    if not smtp_host or not from_email:
        # Still avoid account enumeration.
        return Response(status_code=204)

    ident = (payload.identifier or "").strip()
    if not ident:
        return Response(status_code=204)

    # The endpoint answers identically for known and unknown names, so it is
    # a favourite of both enumerators and mail-bombers: both allowances are
    # checked before any account-dependent work.
    client_ip = _get_client_ip(request)
    allowed, _info = check_rate_limit(
        db, f"pwreset_ip:{client_ip}", max_attempts=5, window_seconds=900
    )
    if not allowed:
        return Response(status_code=204)

    user = None
    if "@" in ident:
        ident_l = ident.lower()
        user = (
            get_user_by_email(db, ident_l)
            or db.query(User).filter(User.username == ident).one_or_none()
        )
    else:
        user = db.query(User).filter(User.username == ident).one_or_none()

    # Always return 204 to avoid enumeration.
    if not user or not bool(getattr(user, "is_active", False)):
        # A rejection pays the same committed write as an issue, so wall
        # clock cannot separate the two paths.
        record_rate_limit_attempt(db, f"pwreset_dummy:{_hash_reset_token(ident)}")
        log_password_reset_request(
            db,
            None,  # type: ignore[arg-type]  # an unknown name has no account row
            client_ip,
            _get_user_agent(request),
        )
        return Response(status_code=204)

    target_id = f"pwreset_target:{int(user.id)}"
    allowed, _info = check_rate_limit(db, target_id, max_attempts=3, window_seconds=900)
    if not allowed:
        record_rate_limit_attempt(db, target_id)
        return Response(status_code=204)
    record_rate_limit_attempt(db, target_id)

    # Always send account mail to the address the user has explicitly marked
    # primary. The resolver retains legacy fallbacks for pre-migration accounts.
    recipient = notification_email_for_user(db, user=user) or ""
    if not recipient:
        # Fallback: if username is an email.
        if "@" in (user.username or ""):
            recipient = user.username.strip()
    if not recipient:
        log_password_reset_request(
            db, user.id, _get_client_ip(request), _get_user_agent(request)
        )
        return Response(status_code=204)

    base = _derive_public_base_url(request)
    if not base:
        # Without a configured public origin, the link's host would be chosen
        # the requester's Host header, so no token is issued (fail closed).
        log_password_reset_request(
            db, user.id, _get_client_ip(request), _get_user_agent(request)
        )
        return Response(status_code=204)

    import secrets
    from datetime import datetime

    token = secrets.token_urlsafe(32)
    token_hash = _hash_reset_token(token)

    expires = datetime.utcnow() + timedelta(
        minutes=int(getattr(settings, "password_reset_token_ttl_minutes", 60))
    )

    row = PasswordResetToken(
        user_id=user.id, token_hash=token_hash, expires_at=expires, used_at=None
    )
    db.add(row)
    db.commit()

    reset_link = f"{base}/reset-password.html?token={token}"

    log_password_reset_request(
        db, user.id, _get_client_ip(request), _get_user_agent(request)
    )

    # Send email in the background to keep response quick.
    background.add_task(
        send_password_reset_email,
        to_email=recipient,
        username=user.username,
        reset_link=reset_link,
        expires_minutes=int(getattr(settings, "password_reset_token_ttl_minutes", 60)),
    )

    return Response(status_code=204)


@router.post("/v1/auth/reset-password")
def reset_password(
    payload: PasswordResetConfirmPayload,
    db: Session = Depends(get_db),
) -> Response:
    if not _local_password_features_enabled():
        raise HTTPException(status_code=404, detail="Password reset disabled")

    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    token = (payload.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Invalid token")

    from datetime import datetime

    token_hash = _hash_reset_token(token)
    row = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash)
        .one_or_none()
    )
    if not row:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    now = datetime.utcnow()
    if row.used_at is not None or row.expires_at <= now:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == row.user_id).one_or_none()
    if not user or not bool(getattr(user, "is_active", False)):
        raise HTTPException(status_code=400, detail="Invalid token")

    user.password_hash = get_password_hash(payload.new_password)
    row.used_at = now

    db.add(user)
    db.add(row)
    db.commit()

    log_password_reset_confirm(db, user.id, None, None)
    return Response(status_code=204)


def _safe_next(next_url: str | None) -> str | None:
    """Same-origin relative route only; one shared helper decides safety."""
    return safe_relative_route_path(next_url)


def _derive_absolute_post_logout_redirect(request: Request, auth_method: str) -> str:
    provider = get_sso_provider(auth_method)
    configured = (provider.post_logout_redirect_uri or "").strip() if provider else ""
    if configured:
        return configured

    # A post-logout redirect address is never derived from the request: the
    # Host header is client-controlled, so any derived value could send the
    # browser to an attacker host. With no explicit configuration the provider
    # lands on its own default page.
    return ""


@router.get("/v1/auth/logout")
def logout_redirect(request: Request, db: Session = Depends(get_db)) -> Response:
    """Browser-friendly logout endpoint.

    - A `csrf` parameter must match the CSRF cookie before the server-side
      session is destroyed, so a cross-site link cannot log a user out.
    - If the current session was created via OIDC and an end-session endpoint
      is configured, performs RP-initiated logout by redirecting to the
      provider.
    """

    sid = (request.cookies.get(settings.session_cookie_name) or "").strip()
    csrf_cookie = (request.cookies.get(settings.csrf_cookie_name) or "").strip()
    csrf_ok = bool(
        csrf_cookie
        and secrets.compare_digest(
            (request.query_params.get("csrf") or "").strip(), csrf_cookie
        )
    )
    if sid and not csrf_ok:
        # Leave authentication state untouched and land somewhere harmless.
        return RedirectResponse("/index.html", status_code=302)

    auth_method = ""
    oidc_id_token = ""

    if sid:
        row = db.query(SessionRow).filter(SessionRow.session_id == sid).one_or_none()
        if row:
            auth_method = str(getattr(row, "auth_method", "") or "")
            oidc_id_token = str(getattr(row, "oidc_id_token", "") or "")
            try:
                db.delete(row)
                db.commit()
            except Exception:
                db.rollback()

    next_url = _safe_next(request.query_params.get("next")) or "/login.html"
    dest = next_url

    provider = get_sso_provider(auth_method)
    end_session = (provider.end_session_endpoint if provider else "").strip()
    client_id = (provider.client_id if provider else "").strip()

    if auth_method != "local" and end_session:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

        post_logout = _derive_absolute_post_logout_redirect(request, auth_method)
        params = dict(parse_qsl(urlsplit(end_session).query, keep_blank_values=True))

        # Spec parameters
        if oidc_id_token:
            params.setdefault("id_token_hint", oidc_id_token)
        if post_logout:
            params.setdefault("post_logout_redirect_uri", post_logout)

        # Some providers accept/require client_id when id_token_hint is absent.
        if client_id:
            params.setdefault("client_id", client_id)

        parts = urlsplit(end_session)
        dest = urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode(params, doseq=True),
                parts.fragment,
            )
        )

    from app.security import mfa

    resp = RedirectResponse(dest, status_code=302)
    mfa.cancel(db, request, resp)
    clear_session_cookie(resp)
    clear_csrf_cookie(resp)
    return resp


@router.get("/v1/auth/check")
def auth_check(request: Request) -> Response:
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    resp = Response(status_code=204)
    resp.headers["X-Project-User"] = user.username
    resp.headers["X-Project-Role"] = getattr(user, "effective_role", None) or user.role
    return resp


@router.get("/v1/auth/check-admin")
def auth_check_admin(request: Request) -> Response:
    user = getattr(request.state, "user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="Not authenticated")

    eff = getattr(user, "effective_role", None) or user.role
    if (eff or "") != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")

    resp = Response(status_code=204)
    resp.headers["X-Project-User"] = user.username
    resp.headers["X-Project-Role"] = eff
    return resp
