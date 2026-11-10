from __future__ import annotations

import threading
import time
from datetime import datetime
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket
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
from app.security.client_addr import public_client_address, socket_peer_trusted
from app.security.csrf import csrf_valid
from app.security.permissions import seed_default_permissions
from app.security.redaction import redact_query_string
from app.security.roles import ROLE_PENDING, attach_effective_role


class _MemoryWindowLimiter:
    """Process-local fixed-window allowances for cheap per-address bounds.

    The database-backed limiter is too heavy to sit in front of the audit
    trail and WebSocket handshakes, where the bound is an availability guard
    against unauthenticated floods, not a brute-force counter.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, list[float]]] = {}

    def _prune(self, key: str, now: float, window: float) -> int:
        entry = self._buckets.get(key)
        if not entry:
            return 0
        _, stamps = entry
        fresh = [t for t in stamps if now - t < window]
        if fresh:
            self._buckets[key] = (now, fresh)
        else:
            self._buckets.pop(key, None)
        return len(fresh)

    def allow(self, key: str | None, limit: int, window_seconds: float) -> bool:
        if limit <= 0 or window_seconds <= 0:
            return True
        addr = key or "unknown"
        now = time.monotonic()
        with self._lock:
            count = self._prune(addr, now, window_seconds)
            if count >= limit:
                return False
            entry = self._buckets.get(addr)
            stamps = entry[1] + [now] if entry else [now]
            self._buckets[addr] = (now, stamps)
            return True


_memory_limiter = _MemoryWindowLimiter()


app = FastAPI(title=settings.app_title)

_MAX_NOTIFICATION_SOCKETS_PER_USER = 8
# Unauthenticated or cheap-to-repeat work gets a small per-address budget:
# audit-trail writes and WebSocket handshakes cannot be flooded into database
# churn from a single address.
_AUDIT_ROWS_PER_ADDRESS_PER_MINUTE = 120
_WS_HANDSHAKES_PER_ADDRESS_PER_MINUTE = 30


def _client_ip(request: Request) -> str | None:
    return public_client_address(
        getattr(getattr(request, "client", None), "host", None),
        request.headers.get("x-forwarded-for"),
    )


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


if bool(getattr(settings, "trust_proxy_headers", False)):
    app.add_middleware(_TrustedProxySchemeMiddleware)


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
            # Login stays exempt: a first-time browser has neither session nor
            # CSRF cookie. Every other cookie-authenticated unsafe write,
            # logout included, must carry the matching CSRF token.
            if path != "/v1/auth/login":
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

            client_ip = _client_ip(request)

            # One committed row per request is a floodable write: an
            # unauthenticated client gets a bounded per-address audit
            # allowance, and paths that are refused before any work (rate
            # limits, CSRF) are sampled, not committed.
            write_row = True
            if client_ip:
                write_row = _memory_limiter.allow(
                    client_ip, _AUDIT_ROWS_PER_ADDRESS_PER_MINUTE, 60.0
                )

            if write_row:
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
        except Exception:
            # Audit logging must never break the request path.
            pass


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
        if is_enabled("frameworks"):
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
    """Protect against cross-site WebSocket hijacking.

    When ``OSPMAE_PUBLIC_BASE_URL`` is configured, an Origin must name that
    origin exactly. Otherwise the Origin host must match the request's Host
    header, and the Origin may never be absent: browsers always send one, so a
    missing Origin from a browser page is already attacker-shaped. This check
    is in addition to same-origin cookie protections, not instead of them.
    """

    origin = (ws.headers.get("origin") or "").strip()
    if not origin:
        return False

    try:
        o = urlparse(origin)
    except Exception:
        return False

    if (o.scheme or "").lower() not in {"http", "https"}:
        return False

    origin_host = (o.hostname or "").strip().lower()
    if not origin_host:
        return False

    expected_base = (getattr(settings, "public_base_url", "") or "").strip()
    if expected_base:
        expected = _origin_host(expected_base)
        return bool(expected) and origin_host == expected

    host_hdr = (ws.headers.get("host") or "").split(":", 1)[0].strip().lower()
    if not host_hdr:
        return False

    return origin_host == host_hdr


@app.websocket("/ws/notifications")
async def ws_notifications(ws: WebSocket):
    """WebSocket notifications endpoint.

    Uses the same authentication sources as HTTP requests (session cookie or
    the configured trusted identity header). The authentication database
    session is released as soon as the handshake completes; it never spans the
    idle lifetime of the connection.
    """

    if not _ws_origin_allowed(ws):
        await ws.close(code=4403)
        return

    # Handshake attempts themselves are floodable work (one session checkout
    # and user lookup each), so each address gets a small allowance before the
    # database is touched.
    peer = getattr(getattr(ws, "client", None), "host", None)
    if not _memory_limiter.allow(peer, _WS_HANDSHAKES_PER_ADDRESS_PER_MINUTE, 60.0):
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
        if attach_effective_role(db, user) == ROLE_PENDING:
            user = None
            await ws.close(code=4403)
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
            # ignored, and NumPy-free frame buffering stays bounded by ASGI.
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
