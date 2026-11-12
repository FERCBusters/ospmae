from __future__ import annotations

import time
from datetime import datetime

import anyio
from fastapi import FastAPI, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketDisconnect

from app.api.routes import router as api_router
from app.core.config import settings
from app.db.capability_taxonomy import ensure_default_frameworks
from app.db.models import AuditLog
from app.db.session import SessionLocal
from app.realtime.notifications import hub
from app.security.auth import (
    get_current_user_from_headers_cookies,
    get_current_user_from_request,
)
from app.security.client_addr import (
    allowance_address,
    request_client_address,
    socket_peer_trusted,
)
from app.security.csrf import (
    csrf_valid,
    generate_csrf_token,
    get_csrf_token_from_request,
    request_origin_allowed,
    session_csrf_token,
    set_csrf_cookie,
)
from app.security.local_allowance import LocalAllowance
from app.security.permissions import seed_default_permissions
from app.security.redaction import redact_query_string
from app.security.request_limits import (
    RequestLimitMiddleware,
    validation_error_response,
)
from app.security.roles import attach_effective_role

# The interactive API pages and the schema they read describe every route to
# whoever can reach the API, and the pages load their scripts from another
# site, so the application serves none of them.
app = FastAPI(
    title=settings.app_title,
    exception_handlers={RequestValidationError: validation_error_response},
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_MAX_NOTIFICATION_SOCKETS_PER_USER = 8
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Requests without a signed-in account carry no identity, so each client
# address (each /64 network for IPv6) adds at most this many audit records a
# minute, whatever their status: refusals, and public routes such as signing
# in. Signed-in requests are always recorded. The same figure as KEEN's.
_ANONYMOUS_AUDIT_PER_MINUTE = 60
# WebSocket handshakes cost a session checkout and a user lookup each.
_WS_HANDSHAKES_PER_MINUTE = 30
_anonymous_audit = LocalAllowance(_ANONYMOUS_AUDIT_PER_MINUTE, 60)
_ws_handshakes = LocalAllowance(_WS_HANDSHAKES_PER_MINUTE, 60)

# Public read-only documents and pollers that anyone may fetch at any rate.
_UNAUDITED_PUBLIC_READS = frozenset({"/v1/system/health", "/v1/auth/methods"})
# The navbar's unanswered-questions badge polls this on every page.
_UNAUDITED_POLLS = frozenset({"/v1/questions/unanswered/summary"})


class _TrustedProxySchemeMiddleware:
    """Trust X-Forwarded-Proto from a trusted socket peer only.

    Uvicorn's ProxyHeadersMiddleware cannot gate by CIDR networks and, when
    trusted broadly, lets any client rewrite the connection's peer address and
    scheme, so forwarded headers are handled here instead and the server's
    proxy-header rewriting must stay disabled.
    """

    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and bool(
            getattr(settings, "trust_proxy_headers", False)
        ):
            client = scope.get("client") or (None, None)
            if client[0] and socket_peer_trusted(client[0]):
                proto = None
                for key, value in scope.get("headers") or []:
                    if key == b"x-forwarded-proto":
                        proto = value.decode("latin-1").strip().lower()
                        break
                if proto in ("http", "https"):
                    scope = dict(scope)
                    scope["scheme"] = proto
        await self.asgi_app(scope, receive, send)


def _authenticate(request: Request) -> JSONResponse | None:
    """Attach the request's user, or return the response refusing the request.

    The account is loaded in a short-lived session that closes before the
    route runs, so no connection is held for the length of a request. The
    instance is detached: a route that changes it adds it to its own session.
    """
    db = SessionLocal()
    try:
        user = get_current_user_from_request(request, db)
        if user is None:
            return None
        # Loads every column, so the detached instance stays readable.
        attach_effective_role(db, user)
        db.expunge(user)
        request.state.user = user
        request.state.audit_username = user.username
        return None
    finally:
        db.close()


@app.middleware("http")
async def load_user_and_enforce_csrf(request: Request, call_next):
    # Database work runs in the thread pool, so one slow lookup never holds up
    # the requests the event loop is serving.
    refused = await run_in_threadpool(_authenticate, request)
    if refused is not None:
        return refused
    user = getattr(request.state, "user", None)

    if request.method.upper() in _UNSAFE_METHODS:
        # A browser sends every write from OSPMAE's own origin, including
        # writes before anyone is signed in (signing in, password resets, a
        # second factor in progress), which have no CSRF token to check.
        if not request_origin_allowed(request):
            return JSONResponse(
                {"detail": "Request origin is not allowed"}, status_code=403
            )
        # Every signed-in write needs the token, whether the account came from
        # a session cookie or a trusted identity header.
        path = request.url.path or ""
        if user is not None and path != "/v1/auth/login" and not csrf_valid(request):
            return JSONResponse(
                {"detail": "CSRF token missing or invalid"}, status_code=403
            )

    response = await call_next(request)

    # Browsers signed in by a trusted proxy get no OSPMAE sign-in response to
    # carry the CSRF cookie, and a browser may lose the cookie before its
    # session ends; either receives a token with this response: the session's
    # own where there is a session.
    if user is not None and not get_csrf_token_from_request(request):
        try:
            set_csrf_cookie(
                response, session_csrf_token(request) or generate_csrf_token()
            )
        except Exception:
            pass
    return response


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
    if (
        not path.startswith("/v1")
        or path in _UNAUDITED_POLLS
        or (request.method.upper() == "GET" and path in _UNAUDITED_PUBLIC_READS)
        or _is_sensitive_auth_callback_path(path)
    ):
        return await call_next(request)

    start = time.perf_counter()
    response = None
    try:
        response = await call_next(request)
        return response
    finally:
        status_code = getattr(response, "status_code", 500)
        duration_ms = int((time.perf_counter() - start) * 1000)
        try:
            # Written in the thread pool, off the event loop, and kept even
            # when the client goes away before it is written.
            with anyio.CancelScope(shield=True):
                await run_in_threadpool(
                    _record_request, request, path, status_code, duration_ms
                )
        except Exception:
            # Audit logging must never break the request path.
            pass


def _record_request(
    request: Request, path: str, status_code: int, duration_ms: int
) -> None:
    username = getattr(request.state, "audit_username", None)
    client_ip = request_client_address(request)
    if username is None and not _anonymous_audit.allow(allowance_address(client_ip)):
        return

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
                client_ip=client_ip,
                user_agent=user_agent,
                referer=referer,
            )
        )
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
def _bootstrap_catalog_data() -> None:
    """Seed idempotent catalog data.

    - Ensures default permissions exist.
    - Ensures the default frameworks (e.g. UWRA) exist when framework
      management is enabled for this installation.
    """

    from app.core.features import is_enabled

    db = SessionLocal()
    try:
        seed_default_permissions(db)
        if is_enabled("frameworks", db):
            ensure_default_frameworks(db)
    finally:
        db.close()


@app.websocket("/ws/notifications")
async def ws_notifications(ws: WebSocket):
    """WebSocket notifications endpoint.

    Uses the same authentication sources as HTTP requests (session cookie or
    the configured trusted identity header). The authentication database
    session is released as soon as the handshake completes; it never spans the
    idle lifetime of the connection.
    """

    # Cross-site WebSocket hijacking: browsers always send Origin, and it must
    # name OSPMAE itself.
    if not request_origin_allowed(ws, require_origin=True):
        await ws.close(code=4403)
        return

    # Handshake attempts themselves are floodable work (one session checkout
    # and user lookup each), so each client address gets a small allowance
    # before the database is touched. Behind the proxy every socket peer is
    # the proxy itself, so the allowance counts the resolved client address.
    peer = getattr(getattr(ws, "client", None), "host", None)
    if not _ws_handshakes.allow(allowance_address(request_client_address(ws))):
        await ws.close(code=4429)
        return

    user = None
    db = SessionLocal()
    try:
        user = get_current_user_from_headers_cookies(
            ws.headers, ws.cookies, db, socket_peer=peer
        )
        if not user:
            await ws.close(code=4401)
            return

        if not await hub.connect_if_capacity(
            user.id, ws, _MAX_NOTIFICATION_SOCKETS_PER_USER
        ):
            user = None
            return
    finally:
        # Authentication work is done; the connection itself holds no session.
        db.close()

    if user is None:
        return

    try:
        while True:
            # Keep the socket alive and detect disconnects. Client text is
            # ignored; the server bounds the size of each frame.
            _ = await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await hub.disconnect(user.id, ws)


@app.get("/")
def root():
    return {"ok": True, "service": "project-api"}


app.include_router(api_router)

# Byte, shape and target limits apply before any middleware reads the request.
app.add_middleware(RequestLimitMiddleware)

# Outermost, so every middleware and route sees the forwarded scheme.
if bool(getattr(settings, "trust_proxy_headers", False)):
    app.add_middleware(_TrustedProxySchemeMiddleware)
