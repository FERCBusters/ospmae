from __future__ import annotations

import secrets
from datetime import datetime

from fastapi import (
    APIRouter,
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
)
from app.core.config import settings
from app.db.models import (
    LoginDevice,
    User,
)
from app.db.models import (
    Session as SessionRow,
)
from app.db.session import get_db
from app.security import sign_in_throttle as throttle
from app.security.audit import record_sign_in
from app.security.auth import (
    ROLE_ADMIN,
    authenticate_user,
    clear_session_cookie,
    get_current_user,
    get_password_hash,
    get_user_by_username,
    set_session_cookie,
)
from app.security.client_addr import request_allowance_key, request_client_address
from app.security.csrf import clear_csrf_cookie, generate_csrf_token, set_csrf_cookie
from app.security.oidc import (
    any_sso_enabled,
    build_authorize_redirect,
    configured_sso_providers,
    get_sso_provider,
    handle_callback,
    linked_account,
    sso_attempt,
)
from app.security.passwords import verify_password
from app.security.rate_limit import check_rate_limit, record_rate_limit_attempt
from app.security.roles import attach_effective_role
from app.security.sessions import (
    create_session,
    delete_all_sessions_for_user,
    delete_session,
)
from app.security.url_safety import safe_relative_route_path
from app.services import security_notifications

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
    }


@router.post("/v1/auth/login")
def login(
    payload: LoginPayload, request: Request, db: Session = Depends(get_db)
) -> Response:
    """Password sign-in under the shared throttling policy.

    See app/security/sign_in_throttle.py: a browser that has signed in to this
    account before is heard whatever an attacker does elsewhere, and every
    other browser shares the account's growing waits.
    """

    if not bool(getattr(settings, "local_auth_enabled", True)):
        raise HTTPException(status_code=404, detail="Local auth disabled")

    username = (payload.username or "").strip()
    # A blank username is refused before any throttling or password work.
    if not username or not throttle.login_name(username):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    now = datetime.utcnow()
    key = throttle.name_key(username)
    device = throttle.recognised_device(
        db, request.cookies.get(throttle.device_cookie_name()), key, now
    )

    if device is None:
        address_id = request_allowance_key("login", request)
        allowed, info = check_rate_limit(
            db,
            address_id,
            max_attempts=throttle.ADDRESS_ATTEMPTS,
            window_seconds=throttle.ADDRESS_WINDOW_SECONDS,
        )
        if not allowed:
            return _limited(int(info["retry_after"]) // 1000)
        record_rate_limit_attempt(db, address_id)

        admitted, retry = throttle.reserve_unrecognised_attempt(db, key, now)
        if not admitted:
            return _limited(retry)

    user = authenticate_user(db, payload.username, payload.password)
    if not user:
        if device is not None:
            throttle.device_failed(db, device)
        record_sign_in(
            db,
            request,
            method="local",
            outcome="failed",
            account=get_user_by_username(db, username),
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # The password is proven: the account's count ends, and this browser is
    # recognised for it from now on (its previous token retired).
    throttle.clear_throttle(db, key)
    token = throttle.issue_device(
        db, user_id=user.id, key=key, now=now, replaces=device
    )
    db.commit()

    from app.security import mfa

    if user.mfa_enabled or mfa.required(db, user):
        # The password is proven; the browser now holds the ceremony cookie
        # while /v1/auth/mfa/* runs outside of any session.
        response = mfa.start(db, user, request)
    else:
        response = complete_local_login(db, user, request)
    throttle.set_device_cookie(response, token)
    return response


def _limited(retry_after: int) -> JSONResponse:
    retry = max(1, int(retry_after))
    return JSONResponse(
        {"detail": throttle.LIMITED, "retry_after": retry},
        status_code=429,
        headers={"Retry-After": str(retry)},
    )


def _record_completed_sign_in(
    db: Session, request: Request, user: User, *, method: str
) -> bool:
    """The audit row and known-address check for a completed sign-in.

    The caller commits. Returns True when an unfamiliar-address notice was
    queued, so the caller can hand it to the mail worker after committing.
    """
    record_sign_in(db, request, method=method, outcome="success", account=user)
    return security_notifications.record_login(
        db, user, ip=request_client_address(request)
    )


def _kick_delivery() -> None:
    from app.tasks.notifications import kick_delivery

    kick_delivery()


def complete_local_login(
    db: Session,
    user: User,
    request: Request,
    *,
    mfa_verified: bool = False,
    verified_version: int | None = None,
):
    # The account's earlier sessions end only once sign-in is complete, any
    # second factor included: a password alone cannot sign anyone out.
    delete_all_sessions_for_user(db, user.id)
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

    # Signing in is complete only here, any second factor included.
    user.last_login_at = datetime.utcnow()
    db.add(user)
    notice_queued = _record_completed_sign_in(db, request, user, method="local")
    db.commit()
    if notice_queued:
        _kick_delivery()
    request.state.user = user
    request.state.audit_username = user.username

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
        db,
        request_allowance_key("sso_start", request),
        max_attempts=20,
        window_seconds=300,
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
    try:
        user, next_url, id_token, provider = await handle_callback(
            request, db, provider_key=provider_key
        )
    except HTTPException as error:
        # Audit a refusal of a sign-in this browser started, naming the
        # account only when the provider's identity is linked to one.
        attempted = sso_attempt(request)
        if attempted is not None:
            db.rollback()
            record_sign_in(
                db,
                request,
                method=attempted,
                outcome="failed",
                account=linked_account(error),
            )
            db.commit()
        raise
    request.state.user = user
    request.state.audit_username = user.username

    delete_all_sessions_for_user(db, user.id)
    notice_queued = _record_completed_sign_in(db, request, user, method=provider.key)

    # Creating the session commits the sign-in's records with it.
    sid = create_session(
        db,
        user_id=user.id,
        ttl_seconds=int(settings.session_ttl_seconds),
        auth_method=provider.key,
        oidc_id_token=id_token,
    )
    if notice_queued:
        _kick_delivery()
    csrf_token = generate_csrf_token()

    resp = RedirectResponse(next_url or "/index.html", status_code=302)
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

    from app.security import mfa

    resp = Response(status_code=204)
    mfa.cancel(db, request, resp)
    clear_session_cookie(resp)
    clear_csrf_cookie(resp)
    return resp


def _local_password_features_enabled() -> bool:
    # Explicitly disable local password flows when any external SSO provider is enabled.
    return bool(getattr(settings, "local_auth_enabled", True)) and not any_sso_enabled()


# Current-password confirmations a session may make, per address (the sign-in
# allowance) and per account within the same window, as KEEN limits them.
PASSWORD_CHANGES_PER_ACCOUNT = 15


@router.post("/v1/auth/change-password")
def change_password(
    payload: ChangePasswordPayload,
    request: Request,
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    if not _local_password_features_enabled():
        raise HTTPException(status_code=404, detail="Password change disabled")
    if settings.trust_remote_user:
        raise HTTPException(
            status_code=403,
            detail="Password changes are disabled when OSPMAE_TRUST_REMOTE_USER is enabled",
        )

    # A session holder must not be able to test many current passwords, from
    # one address or by spreading attempts across addresses.
    for attempt_id, allowance in (
        (request_allowance_key("password_change", request), throttle.ADDRESS_ATTEMPTS),
        (f"pw_change:{int(me.id)}", PASSWORD_CHANGES_PER_ACCOUNT),
    ):
        allowed, _info = check_rate_limit(
            db,
            attempt_id,
            max_attempts=allowance,
            window_seconds=throttle.ADDRESS_WINDOW_SECONDS,
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many password change attempts. Please try again later.",
            )
    for attempt_id in (
        request_allowance_key("password_change", request),
        f"pw_change:{int(me.id)}",
    ):
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

    user_row = (
        db.query(User)
        .filter(User.id == me.id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if not user_row:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not verify_password(payload.current_password, user_row.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    user_row.password_hash = get_password_hash(payload.new_password)
    # As in KEEN, the new password ends every local session of the account,
    # this one included, and every browser's recognition: each signs in again.
    user_row.mfa_version += 1
    db.query(LoginDevice).filter(LoginDevice.user_id == user_row.id).delete(
        synchronize_session=False
    )
    notice_queued = security_notifications.enqueue(
        db, user_row, "password-changed", ip=request_client_address(request)
    )
    db.add(user_row)
    db.commit()
    if notice_queued:
        _kick_delivery()
    response = Response(status_code=204)
    clear_session_cookie(response)
    clear_csrf_cookie(response)
    return response


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
