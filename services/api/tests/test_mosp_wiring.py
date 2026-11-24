"""OSPMAE assembled on mosp: the sign-in, session, CSRF, socket and request
rules mosp provides apply to OSPMAE's own routes and settings.

mosp's own suite covers those rules in depth; these tests check that OSPMAE
mounts them, and the few things OSPMAE adds (its body limits, its mail
outbox, its example environment).
"""

from __future__ import annotations

import re
import time
from datetime import timedelta
from pathlib import Path

import pytest
from app import mosp_hooks
from app.core.config import settings
from app.db.models import Notification, UserShortcut
from app.db.session import SessionLocal
from app.services import notifications
from fastapi.testclient import TestClient
from mosp.core.datetime_utils import utc_now_naive
from mosp.host import hooks
from mosp.realtime import sockets
from mosp.realtime.notifications import notification_hub
from mosp.security.auth import cookie_name
from mosp.services import outbox
from starlette.websockets import WebSocketDisconnect

from tests.conftest import auth_client, generated_password, make_user, peer_wrapper
from tests.support import csrf, ok

ORIGIN_REFUSED = (403, {"detail": "Authentication request origin is not allowed"})


def outcome(response):
    return response.status_code, response.json()


@pytest.mark.parametrize(
    "path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"]
)
def test_the_api_serves_no_schema_or_interactive_pages(path):
    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    # Deny by default: a signed-out client learns nothing about which paths
    # exist; a signed-in one is told the page does not exist.
    assert c.get(path).status_code == 401
    signed_in, _ = auth_client(role="admin")
    assert signed_in.get(path).status_code == 404


def test_the_example_environment_ships_no_usable_credential():
    """Compose refuses to start while a required password is empty, and an
    installation copied from the example must not run on a value anyone can
    read in it."""
    example = Path(__file__).resolve().parents[3] / ".env.example"
    values = dict(
        line.split("=", 1)
        for line in example.read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    credential = re.compile(r"(PASSWORD|_SECRET|_TOKEN|ENCRYPTION_KEY)$")

    def shipped(found: dict[str, str]) -> list[str]:
        return sorted(
            name
            for name, value in found.items()
            if credential.search(name) and value.strip()
        )

    assert shipped(values) == []
    assert sum(1 for name in values if credential.search(name)) >= 7
    assert values["POSTGRES_PASSWORD"] == values["REDIS_PASSWORD"] == ""
    # No setting holds a placeholder that would work as a value, and the
    # addresses built from the passwords name them instead of repeating them.
    assert [
        name for name, value in values.items() if re.search(r"<[A-Z_]+>", value)
    ] == []
    assert "${POSTGRES_PASSWORD}" in values["OSPMAE_DATABASE_URL"]
    assert "${REDIS_PASSWORD}" in values["OSPMAE_CELERY_BROKER_URL"]
    assert "${REDIS_PASSWORD}" in values["OSPMAE_REDIS_URL"]
    # The check finds what the example used to ship.
    assert shipped({"POSTGRES_PASSWORD": "<GENERATE_STRONG_PASSWORD>"}) == [
        "POSTGRES_PASSWORD"
    ]


def test_a_mail_that_will_never_be_sent_keeps_no_body(monkeypatch):
    monkeypatch.setattr(notifications, "smtp_configured", lambda: True)

    def refuse(**_):
        raise OSError("smtp down: password=hunter2")

    monkeypatch.setattr(notifications, "send_email", refuse)
    with SessionLocal() as s:
        row = Notification(
            recipient="a@x.test",
            subject="A manifest was shared with your group",
            body="https://ospmae.example/manifests.html?id=one-time-secret",
            status="pending",
            attempts=outbox.MAX_ATTEMPTS - 2,
            next_attempt_at=utc_now_naive() - timedelta(minutes=1),
        )
        s.add(row)
        s.commit()
        row_id = row.id

    assert notifications.deliver_pending(limit=1) == 0
    with SessionLocal() as s:
        row = s.get(Notification, row_id)
        # Still to be retried: the body is what the retry sends.
        assert (row.status, row.attempts) == (
            "pending",
            outbox.MAX_ATTEMPTS - 1,
        )
        assert "one-time-secret" in row.body
        row.next_attempt_at = utc_now_naive() - timedelta(minutes=1)
        s.commit()
    assert notifications.deliver_pending(limit=1) == 0
    with SessionLocal() as s:
        row = s.get(Notification, row_id)
        assert (row.status, row.body) == ("failed", "")
        assert row.last_error == "OSError"


def test_the_time_limit_ends_a_notification_run(monkeypatch):
    """One outbox's failure leaves the next to be sent; the task's time limit
    is no outbox's failure and ends the run."""
    from app.tasks import notifications as task
    from celery.exceptions import SoftTimeLimitExceeded
    from mosp.services import security_notifications

    drained = []

    def broken(limit):
        drained.append("app")
        raise RuntimeError("smtp down")

    monkeypatch.setattr(notifications, "deliver_pending", broken)
    monkeypatch.setattr(
        security_notifications,
        "deliver_pending",
        lambda limit: drained.append("mosp") or 2,
    )
    assert task.deliver_notifications() == {"sent": 2}
    assert drained == ["app", "mosp"]

    def stopped(limit):
        drained.append("stopped")
        raise SoftTimeLimitExceeded()

    drained.clear()
    monkeypatch.setattr(notifications, "deliver_pending", stopped)
    with pytest.raises(SoftTimeLimitExceeded):
        task.deliver_notifications()
    assert drained == ["stopped"]


def test_body_limits_by_route():
    assert hooks.body_limit("/v1/auth/login") == 16 * 1024
    assert hooks.body_limit("/v1/me/password") == 16 * 1024
    assert hooks.body_limit("/v1/auth/mfa/webauthn/register") == 256 * 1024
    # Every OSPMAE write is a small JSON form.
    for path in ("/v1/projects", "/v1/projects/1/versions", "/v1/manifests"):
        assert hooks.body_limit(path) == mosp_hooks.MAX_BODY


def test_sign_in_needs_ospmaes_own_origin(client):
    password = generated_password()
    make_user("origin-user", password)
    for headers in (
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
        # Every browser OSPMAE serves sends Origin with its writes.
        {},
    ):
        response = client.post(
            "/v1/auth/login",
            json={"username": "origin-user", "password": password},
            headers=headers,
        )
        assert outcome(response) == ORIGIN_REFUSED, headers
    response = client.post(
        "/v1/auth/login",
        json={"username": "origin-user", "password": password},
        headers={"Origin": "https://testserver"},
    )
    assert response.status_code == 200, response.text


def test_signed_in_writes_need_the_origin_and_the_sessions_token():
    c, user = auth_client(role="admin")
    body = {"name": "x", "url": "/folders.html"}
    refused = c.post(
        "/v1/me/shortcuts",
        json=body,
        headers={**csrf(c), "Origin": "https://evil.example"},
    )
    assert refused.status_code == 403
    missing = c.post("/v1/me/shortcuts", json=body)
    assert outcome(missing) == (403, {"detail": "CSRF token missing or invalid"})
    with SessionLocal() as db:
        assert db.query(UserShortcut).filter_by(user_id=user.id).count() == 0
    ok(c.post("/v1/me/shortcuts", json=body, headers=csrf(c)))


def test_the_account_changes_its_own_password_through_mosp():
    password = generated_password()
    c, user = auth_client(role="viewer", password=password)
    changed = c.post(
        "/v1/me/password",
        json={"current_password": password, "new_password": generated_password()},
        headers=csrf(c),
    )
    assert changed.json() == {"ok": True}
    # The change ends the session it came from.
    assert c.get("/v1/me").status_code == 401


def _socket_headers(client):
    # The test client opens sockets over plain ws, where it withholds Secure
    # cookies; a browser's wss handshake carries them, as this header does.
    name = cookie_name()
    return {
        "X-Test-Peer": "127.0.0.1",
        "Origin": "https://testserver",
        "Cookie": f"{name}={client.cookies.get(name)}",
    }


def test_a_socket_needs_ospmaes_origin(client):
    for origin in (None, "https://evil.example"):
        headers = {"X-Test-Peer": "198.51.100.3"}
        if origin:
            headers["Origin"] = origin
        with pytest.raises(WebSocketDisconnect) as closed:
            with client.websocket_connect("/ws/notifications", headers=headers):
                pass
        assert (closed.value.code, closed.value.reason) == (1008, "Origin not allowed")


def test_an_open_socket_ends_when_its_session_does(monkeypatch, valkey):
    """The socket is authenticated at its handshake; a sign-out afterwards
    ends it at its next check instead of leaving it to receive."""
    monkeypatch.setattr(sockets, "RECHECK_SECONDS", 0.05)
    client, user = auth_client(role="viewer")
    with client.websocket_connect(
        "/ws/notifications", headers=_socket_headers(client)
    ) as ws:
        assert ws.receive_json() == {"type": "ping"}
        assert str(user.id) in notification_hub._user_sockets
        for key in valkey.keys("ospmae:session:*"):
            valkey.delete(key)
        with pytest.raises(WebSocketDisconnect) as closed:
            for _ in range(50):
                ws.receive_json()
        assert closed.value.code == 1008
    time.sleep(0.05)
    assert str(user.id) not in notification_hub._user_sockets


def test_a_provider_starts_where_nginx_serves_the_api(monkeypatch):
    # nginx serves the API under /api/, as KEEN's does.
    from mosp.security import oidc

    monkeypatch.setattr(settings, "oidc_enabled", True)
    provider = oidc.get_sso_provider("oidc")
    assert oidc.provider_start_url(provider) == "/api/v1/auth/sso/oidc/start"
