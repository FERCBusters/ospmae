from __future__ import annotations

import ipaddress
import os
import secrets
import sys
from pathlib import Path

# The test database must be chosen before the application imports: settings
# read OSPMAE_DATABASE_URL once at import time. The suite runs on PostgreSQL
# only, the database the application is deployed on, so every test exercises
# the real types, constraints, locks and migrations. OSPMAE_TEST_DATABASE_URL
# names a disposable database (tests.sh and CI export it); the suite empties
# it.
_TEST_DB = os.environ.get("OSPMAE_TEST_DATABASE_URL", "")
if not _TEST_DB.startswith("postgresql"):
    raise RuntimeError(
        "Set OSPMAE_TEST_DATABASE_URL to a disposable PostgreSQL database, "
        "for example postgresql+psycopg://ospmae_test:ospmae_test@localhost:5432/"
        "ospmae_test. The tests empty it: never name an operational database."
    )
os.environ["OSPMAE_DATABASE_URL"] = _TEST_DB
# No broker runs beside the tests. Hand-offs go to Celery's in-memory
# transport, where nothing consumes them: a request under test returns at
# once, and each test that cares about a task runs or records it itself.
os.environ["OSPMAE_CELERY_BROKER_URL"] = "memory://"
os.environ["OSPMAE_CELERY_RESULT_BACKEND"] = "cache+memory://"
# Test clients authenticate over https so Secure cookies round-trip.
os.environ.setdefault("OSPMAE_COOKIE_SECURE", "true")
os.environ.setdefault("OSPMAE_TRUST_PROXY_CIDRS", "127.0.0.1,::1")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.api.routes  # noqa: E402,F401
import app.db.models  # noqa: E402,F401
import pytest  # noqa: E402

# Import the model modules so their tables register on the shared metadata
# before any create_all: nothing in this conftest imports the application
# eagerly, and an empty metadata silently creates an empty schema.
from app import db as _app_db  # noqa: E402,F401  (keeps models registered)
from app.db.session import Base, SessionLocal, engine  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402


def create_all() -> None:
    Base.metadata.create_all(engine)


@pytest.fixture(scope="session", autouse=True)
def _schema():
    """A schema rebuilt once per run: truncation-only fixtures cannot refresh
    tables across code upgrades, so a stale file would hide new columns."""
    Base.metadata.drop_all(engine)
    create_all()
    yield


def truncate_all() -> None:
    with engine.begin() as conn:
        names = [
            r[0]
            for r in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        ]
        # A leaked idle-in-transaction connection would block this exclusive
        # lock forever; a bounded wait turns the hang into a loud failure.
        conn.execute(text("SET LOCAL lock_timeout = '30s'"))
        # Identity columns restart with the tables: tests assume fresh
        # sequences, and a shared database must not leak counters between
        # tests or runs.
        conn.execute(
            text(
                "TRUNCATE TABLE "
                + ", ".join(f'"{n}"' for n in names)
                + " RESTART IDENTITY CASCADE"
            )
        )


@pytest.fixture(autouse=True)
def _fresh_database():
    """Every test starts from empty tables."""
    create_all()
    truncate_all()
    yield
    truncate_all()


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client():
    from app.main import app as application

    with TestClient(peer_wrapper(application), base_url="https://testserver") as c:
        yield c


_PEER_WRAPPER_CACHE: dict[int, object] = {}


def peer_wrapper(app_obj):
    """One peer-derivation wrapper per app instance.

    The harness cannot open real TCP connections with distinct peers, so a
    request header names the socket peer, mirroring what a deployment's
    socket does. Unparseable peers leave the scope untouched.
    """

    key = id(app_obj)
    instance = _PEER_WRAPPER_CACHE.get(key)
    if instance is not None:
        return instance

    class PeerFromHeader:
        def __init__(self, inner):
            self.inner = inner

        async def __call__(self, scope, receive, send):
            if scope.get("type") in ("http", "websocket"):
                for k, v in scope.get("headers") or []:
                    if k == b"x-test-peer":
                        scope = dict(scope)
                        try:
                            ipaddress.ip_address(v.decode())
                            scope["client"] = (v.decode(), 50000)
                        except ValueError:
                            pass
                        break
            # Every scope type, lifespan included, must reach the inner app.
            await self.inner(scope, receive, send)

    instance = PeerFromHeader(app_obj)
    _PEER_WRAPPER_CACHE[key] = instance
    return instance


def generated_password() -> str:
    """A fresh password the new-password rules always accept.

    The random part sits between two fixed words: the rules strip digits and
    punctuation from a password's ends before comparing it with common
    passwords, so "Pass-<hex>1!" became plain "pass" whenever every hex
    character was a digit (about one call in 1,800).
    """
    return f"Synthetic-{secrets.token_hex(8)}-passphrase"


def make_user(username: str, password: str, role: str = "admin", **kw):
    from app.security.auth import create_user

    s = SessionLocal()
    try:
        return create_user(s, username=username, password=password, role=role, **kw)
    finally:
        s.close()


def login(client: TestClient, username: str, password: str, peer: str = "8.8.8.8"):
    """Sign in from a specific client address.

    The trusted loopback peer walks X-Forwarded-For right-to-left, so the
    rightmost entry becomes the claimed address -- exactly what a real
    browser behind the supplied nginx produces.
    """
    client.headers["X-Test-Peer"] = "127.0.0.1"
    client.headers["X-Forwarded-For"] = peer
    return client.post(
        "/v1/auth/login", json={"username": username, "password": password}
    )


def auth_client(
    username: str | None = None,
    password: str | None = None,
    role: str = "admin",
    app_obj=None,
) -> tuple[TestClient, "object"]:
    """A signed-in TestClient and its user row."""
    if username is None:
        username = f"user-{secrets.token_hex(4)}"
    if password is None:
        password = generated_password()
    user = make_user(username, password, role=role)
    if app_obj is None:
        from app.main import app as app_obj  # noqa: F811

    c = TestClient(peer_wrapper(app_obj), base_url="https://testserver")
    resp = login(c, username, password)
    assert resp.status_code == 200, f"login failed: {resp.status_code} {resp.text}"
    # After signing in, requests run from this client's own steady address.
    c.headers["X-Forwarded-For"] = "8.8.8.8"
    return c, user


class _Outbox:
    """The committed e-mail outbox and the delivery hand-offs made."""

    def __init__(self) -> None:
        self.kicks: list[dict] = []

    def apply_async(self, *args, **options) -> None:
        self.kicks.append(options)

    def messages(self) -> list:
        """Committed outbox rows, read from a fresh session: mail a request
        added but never committed is not counted."""
        from app.db.models import Notification

        s = SessionLocal()
        try:
            rows = s.query(Notification).order_by(Notification.created_at).all()
            s.expunge_all()
            return rows
        finally:
            s.close()


@pytest.fixture()
def outbox(monkeypatch):
    """Mail configured, with delivery hand-offs recorded instead of sent."""
    from app.core.config import settings
    from app.tasks import notifications as notification_tasks

    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_from_email", "noreply@example.com")
    monkeypatch.setattr(settings, "public_base_url", "https://ospmae.example.com")
    box = _Outbox()
    monkeypatch.setattr(notification_tasks, "deliver_notifications", box)
    return box
