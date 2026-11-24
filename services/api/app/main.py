from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket
from fastapi.exceptions import RequestValidationError
from mosp import middleware
from mosp.api.errors import domain_error_response, validation_error_response
from mosp.api.routes import account, auth, mfa, sso_emails
from mosp.api.sql_trace import RequestLabelMiddleware
from mosp.realtime import sockets
from mosp.realtime.notifications import (
    start_notification_listener,
    stop_notification_listener,
)
from mosp.security.headers import SecurityHeadersMiddleware
from mosp.security.request_limits import RequestBodyLimitMiddleware
from mosp.services.errors import DomainError
from starlette.concurrency import run_in_threadpool

from app.api.routes import router as api_router
from app.core.config import settings
from app.db.session import SessionLocal
from app.security.permissions import seed_default_permissions


def _bootstrap() -> None:
    """Seed idempotent data and the optional first administrator: the
    permission catalogue, and the default frameworks (e.g. UWRA) when
    framework management is on for this installation."""
    from app.core.features import is_enabled
    from app.db.capability_taxonomy import ensure_default_frameworks

    db = SessionLocal()
    try:
        seed_default_permissions(db)
        if is_enabled("frameworks", db):
            ensure_default_frameworks(db)
    finally:
        db.close()
    middleware.bootstrap_initial_admin()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Best-effort: the API still starts while Valkey is briefly unavailable.
    try:
        await start_notification_listener()
    except Exception:
        pass
    try:
        await run_in_threadpool(_bootstrap)
        yield
    finally:
        try:
            await stop_notification_listener()
        except Exception:
            pass


# The interactive API pages and the schema they read describe every route to
# whoever can reach the API, and the pages load their scripts from another
# site, so the application serves none of them.
app = FastAPI(
    title=settings.app_title,
    lifespan=lifespan,
    exception_handlers={
        DomainError: domain_error_response,
        RequestValidationError: validation_error_response,
    },
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.websocket("/ws/notifications")
async def ws_notifications(websocket: WebSocket):
    """A signed-in browser's notification socket (mosp.realtime.sockets)."""
    await sockets.serve(websocket)


@app.get("/")
def root():
    return {"ok": True, "service": "ospmae-api"}


# Signing in and out, second factors, single sign-on, and the account's own
# password and SSO addresses (mosp).
for router in (auth.router, mfa.router, account.router, sso_emails.router):
    app.include_router(router, tags=["auth"])
app.include_router(api_router)

# Authentication, CSRF and the audit trail (mosp), inside the middleware below.
middleware.install(app)
# Byte limits apply before any middleware reads the body.
app.add_middleware(RequestBodyLimitMiddleware)
# Response policy also covers refusals from every inner middleware.
app.add_middleware(SecurityHeadersMiddleware)
# Statements from every middleware are labelled when tracing.
if settings.sql_trace:
    app.add_middleware(RequestLabelMiddleware)
