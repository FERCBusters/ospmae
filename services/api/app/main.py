from __future__ import annotations

from datetime import datetime
import time
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket
from starlette.websockets import WebSocketDisconnect

from app.api.routes import router as api_router
from app.core.config import settings
from app.db.models import AuditLog
from app.db.capability_taxonomy import ensure_default_frameworks
from app.db.session import SessionLocal
from app.realtime.notifications import hub
from app.security.auth import (
    get_current_user_from_request,
    get_current_user_from_headers_cookies,
)
from app.security.csrf import csrf_valid
from app.security.permissions import seed_default_permissions
from app.security.redaction import redact_query_string
from app.security.roles import ROLE_PENDING, attach_effective_role

app = FastAPI(title=settings.app_title)


def _client_ip(request: Request) -> str | None:
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        return xff.split(",")[0].strip() or None
    xri = (request.headers.get("x-real-ip") or "").strip()
    if xri:
        return xri
    return getattr(getattr(request, "client", None), "host", None)


if bool(getattr(settings, "trust_proxy_headers", False)):
    # Starlette's ProxyHeadersMiddleware has moved/been removed across versions.
    # Uvicorn ships a compatible middleware that we can safely use.
    try:
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware  # type: ignore

        app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")
    except Exception:
        # If running under an ASGI server without uvicorn's middleware available,
        # we simply skip this. In that case, set the provider-specific redirect URI explicitly.
        pass


def _pending_user_api_allowed(method: str, path: str) -> bool:
    """Return True for the tiny API surface a pending user needs.

    Pending users are authenticated accounts awaiting administrative review. They
    may only discover their own session state and log out; catalogue, framework,
    manifest, dependency, question and admin APIs remain unavailable.
    """

    method_u = (method or "GET").upper()
    normalized = str(path or "")
    if normalized == "/v1/me" and method_u == "GET":
        return True
    if normalized == "/v1/auth/logout":
        return True
    if normalized in {"/v1/auth/check", "/v1/auth/methods"} and method_u == "GET":
        return True
    return False


@app.middleware("http")
async def load_user_and_enforce_csrf(request: Request, call_next):
    db = SessionLocal()
    try:
        user = get_current_user_from_request(request, db)
        request.state.user = user

        if user is not None and (request.url.path or "").startswith("/v1"):
            effective_role = attach_effective_role(db, user)
            if effective_role == ROLE_PENDING and not _pending_user_api_allowed(
                request.method, request.url.path or ""
            ):
                from fastapi.responses import JSONResponse

                return JSONResponse(
                    {"detail": "Your account is pending administrator approval."},
                    status_code=403,
                )

        if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            path = request.url.path or ""
            # Logout is intentionally exempt: it is safe to allow CSRF-less
            # logout (worst-case is an attacker logs a user out).
            if path not in {"/v1/auth/login", "/v1/auth/logout"}:
                # Only enforce csrf for cookie-authenticated calls.
                has_session_cookie = bool(
                    request.cookies.get(settings.session_cookie_name)
                )
                if has_session_cookie and not csrf_valid(request):
                    from fastapi.responses import JSONResponse

                    return JSONResponse(
                        {"detail": "CSRF token missing or invalid"}, status_code=403
                    )

        response = await call_next(request)
        return response
    finally:
        db.close()


def _is_sensitive_auth_callback_path(path: str | None) -> bool:
    normalized = str(path or "").lower()
    return "/v1/auth" in normalized and "callback" in normalized


@app.middleware("http")
async def audit_trail_middleware(request: Request, call_next):
    """Persist a KEEN-style request audit trail for UI/API calls.

    The semantic before/after details of project catalog mutations are stored in
    entity_changelogs; this table records request metadata, status, duration and
    caller context.
    """

    path = request.url.path or ""
    if path in {"/health", "/v1/system/health", "/v1/admin/questions/summary"}:
        return await call_next(request)
    if _is_sensitive_auth_callback_path(path):
        return await call_next(request)

    start = time.perf_counter()
    response = None
    try:
        response = await call_next(request)
        return response
    finally:
        try:
            if not path.startswith("/v1"):
                return

            status_code = getattr(response, "status_code", 500)
            duration_ms = int((time.perf_counter() - start) * 1000)
            user = getattr(request.state, "user", None)
            username = getattr(user, "username", None) if user else None

            query_string = redact_query_string(request.url.query)
            if query_string and len(query_string) > 4096:
                query_string = query_string[:4096]

            user_agent = (request.headers.get("user-agent") or "").strip() or None
            referer = (request.headers.get("referer") or "").strip() or None
            if user_agent and len(user_agent) > 256:
                user_agent = user_agent[:256]
            if referer and len(referer) > 512:
                referer = referer[:512]

            db = SessionLocal()
            try:
                db.add(
                    AuditLog(
                        ts=datetime.utcnow(),
                        username=username,
                        method=request.method,
                        path=path,
                        query_string=query_string,
                        status_code=int(status_code or 0),
                        duration_ms=duration_ms,
                        client_ip=_client_ip(request),
                        user_agent=user_agent,
                        referer=referer,
                    )
                )
                db.commit()
            finally:
                db.close()
        except Exception:
            # Audit logging must never break the request path.
            pass


@app.on_event("startup")
def _bootstrap_catalog_data() -> None:
    """Seed idempotent catalog data.

    - Ensures default permissions exist.
    - Ensures the default frameworks (e.g. UWRA) exist.

    NOTE: we intentionally do *not* auto-create any admin users here.
    """

    db = SessionLocal()
    try:
        seed_default_permissions(db)
        ensure_default_frameworks(db)
    finally:
        db.close()


def _origin_host(value: str) -> str:
    try:
        u = urlparse(value)
        return (u.hostname or "").strip().lower()
    except Exception:
        return ""


def _ws_origin_allowed(ws: WebSocket) -> bool:
    """Basic protection against cross-site WebSocket hijacking.

    Since UI and API are served same-origin behind nginx, we only allow browser
    WS handshakes whose Origin host matches Host.

    Non-browser clients may omit Origin, which we allow.
    """

    origin = (ws.headers.get("origin") or "").strip()
    if not origin:
        return True

    try:
        o = urlparse(origin)
    except Exception:
        return False

    if (o.scheme or "").lower() not in {"http", "https"}:
        return False

    origin_host = (o.hostname or "").strip().lower()
    host_hdr = (ws.headers.get("host") or "").split(":", 1)[0].strip().lower()
    if not origin_host or not host_hdr:
        return False

    return origin_host == host_hdr


@app.websocket("/ws/notifications")
async def ws_notifications(ws: WebSocket):
    """WebSocket notifications endpoint.

    Uses the same authentication sources as HTTP requests (REMOTE_USER headers or session cookie).
    """

    if not _ws_origin_allowed(ws):
        await ws.close(code=4403)
        return

    db = SessionLocal()
    user = None
    try:
        user = get_current_user_from_headers_cookies(ws.headers, ws.cookies, db)
        if not user:
            await ws.close(code=4401)
            return
        if attach_effective_role(db, user) == ROLE_PENDING:
            await ws.close(code=4403)
            return

        await hub.connect(user.id, ws)

        try:
            while True:
                # Keep the socket alive and detect disconnects.
                _ = await ws.receive_text()
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            await hub.disconnect(user.id, ws)
    finally:
        try:
            db.close()
        except Exception:
            pass


@app.get("/")
def root():
    return {"ok": True, "service": "project-api"}


app.include_router(api_router)
