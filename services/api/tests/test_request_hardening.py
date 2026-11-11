"""Request limits, origin and CSRF checks, the audit trail allowance and
supplied-pattern checks: the hardening shared with KEEN."""

from __future__ import annotations

import asyncio
import json
import re

import app.main as main_module
import pytest
from app.api.payloads import ReleaseFeedIgnorePatternPayload
from app.core.config import settings
from app.db.models import AuditLog, LoginThrottle, Project, User, UserShortcut
from app.db.session import SessionLocal
from app.security import request_limits
from app.security.local_allowance import LocalAllowance
from app.security.regex_shape import check_pattern_shape
from app.security.request_limits import RequestLimitMiddleware, json_body_refusal
from app.tasks.release_feed import _release_feed_entry_is_ignored
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.websockets import WebSocketDisconnect

from tests.conftest import auth_client, make_user, peer_wrapper

TARGET_REFUSED = (400, {"detail": "Invalid request target"})
TOO_LARGE = (413, {"detail": "Request body too large"})
ORIGIN_REFUSED = (403, {"detail": "Request origin is not allowed"})
CSRF_REFUSED = (403, {"detail": "CSRF token missing or invalid"})


def outcome(response):
    return response.status_code, response.json()


def run_asgi(app, *, path="/v1/x", headers=(), chunks=(b"",), delay=0.0):
    """Drive an ASGI app directly with a body sent in the given chunks."""
    sent: list[dict] = []
    pending = list(chunks)

    async def receive():
        if delay:
            await asyncio.sleep(delay)
        if pending:
            body = pending.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(k.encode(), v.encode()) for k, v in headers],
    }
    asyncio.run(app(scope, receive, send))
    status = next(
        (m["status"] for m in sent if m["type"] == "http.response.start"), None
    )
    body = b"".join(
        m.get("body", b"") for m in sent if m["type"] == "http.response.body"
    )
    return status, (json.loads(body) if body else None)


class Recorder:
    """An inner application that records what it received."""

    def __init__(self):
        self.calls = 0
        self.bodies: list[bytes] = []

    async def __call__(self, scope, receive, send):
        self.calls += 1
        message = await receive()
        self.bodies.append(message["body"])
        assert message["more_body"] is False
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})


# --- Body limits -------------------------------------------------------------


def test_the_whole_body_is_read_before_the_application_runs():
    inner = Recorder()
    status, _ = run_asgi(
        RequestLimitMiddleware(inner),
        headers=[("content-type", "application/json")],
        chunks=[b'{"a": ', b'"b"', b"}"],
    )
    assert status == 204
    assert inner.bodies == [b'{"a": "b"}']


def test_an_oversized_tail_is_refused_before_the_application_sees_any_of_it():
    inner = Recorder()
    head = b'{"a": "' + b"x" * (16 * 1024 - 8)
    status, body = run_asgi(
        RequestLimitMiddleware(inner),
        path="/v1/auth/login",
        chunks=[head, b"y" * 64, b'"}'],
    )
    assert (status, body) == TOO_LARGE
    assert inner.calls == 0


def test_body_limits_by_route():
    assert request_limits.body_limit("/v1/auth/login") == 16 * 1024
    assert request_limits.body_limit("/v1/auth/change-password") == 16 * 1024
    assert request_limits.body_limit("/v1/auth/mfa/webauthn/register") == 256 * 1024
    assert request_limits.body_limit("/v1/projects") == 2 * 1024 * 1024


@pytest.mark.parametrize(
    ("value", "expected"),
    [("abc", (400, {"detail": "Invalid Content-Length"})), ("99999999999", TOO_LARGE)],
)
def test_content_length_is_checked_before_reading(value, expected):
    inner = Recorder()
    status, body = run_asgi(
        RequestLimitMiddleware(inner), headers=[("content-length", value)]
    )
    assert (status, body) == expected
    assert inner.calls == 0


def test_a_slow_body_is_refused(monkeypatch):
    monkeypatch.setattr(request_limits, "BODY_TIMEOUT_SECONDS", 0.05)
    inner = Recorder()
    status, body = run_asgi(
        RequestLimitMiddleware(inner), chunks=[b"{", b"}"], delay=0.2
    )
    assert (status, body) == (408, {"detail": "Request body timeout"})
    assert inner.calls == 0


def test_an_oversized_write_changes_nothing():
    c, _ = auth_client(role="admin")
    big = {"name": "huge", "description": "x" * (2 * 1024 * 1024)}
    response = c.post(
        "/v1/projects", json=big, headers={"X-CSRF-Token": c.cookies["ospmae_csrf"]}
    )
    assert outcome(response) == TOO_LARGE
    with SessionLocal() as db:
        assert db.query(Project).count() == 0


# --- JSON shape --------------------------------------------------------------


def _nested(depth):
    return "[" * depth + "]" * depth


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"{", (400, "Request body must be valid JSON")),
        (b'{"a": NaN}', (400, "Request body must be valid JSON")),
        (b'{"a": 1e999}', (400, "Request body must be valid JSON")),
        (_nested(65).encode(), (400, "Request body is nested too deeply")),
        (
            json.dumps([0] * 20_000).encode(),
            (413, "Request body holds too many values"),
        ),
        (b'{"a": "x\\u0000y"}', (400, "Request body cannot contain NUL characters")),
        (b'{"x\\u0000": 1}', (400, "Request body cannot contain NUL characters")),
    ],
)
def test_json_documents_outside_the_limits_are_refused(body, expected):
    assert json_body_refusal(body) == expected


@pytest.mark.parametrize(
    "body",
    [
        _nested(64).encode(),
        json.dumps([0] * 19_999).encode(),
        # An escaped backslash followed by "u0000" is ordinary text.
        b'{"path": "C:\\\\u0000"}',
        b'{"n": 1.5, "ok": true, "none": null}',
    ],
)
def test_json_documents_inside_the_limits_pass(body):
    assert json_body_refusal(body) is None


def test_json_limits_apply_to_requests_without_a_content_type():
    inner = Recorder()
    status, body = run_asgi(RequestLimitMiddleware(inner), chunks=[b'{"a": NaN}'])
    assert (status, body) == (400, {"detail": "Request body must be valid JSON"})
    assert inner.calls == 0


def test_other_media_types_reach_the_route_unparsed():
    inner = Recorder()
    status, _ = run_asgi(
        RequestLimitMiddleware(inner),
        headers=[("content-type", "text/plain")],
        chunks=[b"not json"],
    )
    assert status == 204
    assert inner.bodies == [b"not json"]


def test_a_refused_json_write_changes_nothing():
    c, _ = auth_client(role="admin")
    response = c.post(
        "/v1/projects",
        content=b'{"name": "a\\u0000b"}',
        headers={
            "X-CSRF-Token": c.cookies["ospmae_csrf"],
            "Content-Type": "application/json",
        },
    )
    assert outcome(response) == (
        400,
        {"detail": "Request body cannot contain NUL characters"},
    )
    with SessionLocal() as db:
        assert db.query(Project).count() == 0


# --- Request targets ---------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "/v1/projects/a%2Fb",
        "/v1/projects/a%5Cb",
        "/v1/projects/a%2fb",
        "/v1/projects?q=a%00b",
    ],
)
def test_misleading_request_targets_are_refused(client, target):
    assert outcome(client.get(target)) == TARGET_REFUSED


@pytest.mark.parametrize("path", ["/v1/projects/../admin/users", "/v1/./me"])
def test_dot_segments_are_refused(path):
    inner = Recorder()
    status, body = run_asgi(RequestLimitMiddleware(inner), path=path)
    assert (status, body) == TARGET_REFUSED
    assert inner.calls == 0


def test_validation_errors_do_not_echo_submitted_values(client):
    secret = "correct-horse-battery-staple"
    response = client.post(
        "/v1/auth/login", json={"username": ["not", "text"], "password": secret}
    )
    assert response.status_code == 422
    assert secret not in response.text
    for item in response.json()["detail"]:
        assert set(item) == {"type", "loc", "msg"}
    assert response.json()["detail"][0]["loc"] == ["body", "username"]


# --- Origin and CSRF ---------------------------------------------------------


def test_sign_in_from_a_foreign_origin_is_refused_before_any_state_changes(client):
    make_user("origin-user", "Secret-pass-1!")
    for headers in (
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
    ):
        response = client.post(
            "/v1/auth/login",
            json={"username": "origin-user", "password": "wrong"},
            headers=headers,
        )
        assert outcome(response) == ORIGIN_REFUSED
    with SessionLocal() as db:
        assert db.query(LoginThrottle).count() == 0
    # Same-origin browsers and clients that send no Origin are unaffected.
    for headers in ({"Origin": "https://testserver"}, {}):
        response = client.post(
            "/v1/auth/login",
            json={"username": "origin-user", "password": "Secret-pass-1!"},
            headers=headers,
        )
        assert response.status_code == 200


def test_password_reset_requests_need_the_application_origin(client):
    response = client.post(
        "/v1/auth/request-password-reset",
        json={"identifier": "someone@example.com"},
        headers={"Origin": "https://evil.example"},
    )
    assert outcome(response) == ORIGIN_REFUSED


def test_the_public_base_url_is_the_one_accepted_origin(client, monkeypatch):
    monkeypatch.setattr(settings, "public_base_url", "https://ospmae.example")
    make_user("base-user", "Secret-pass-1!")

    def attempt(origin):
        return client.post(
            "/v1/auth/login",
            json={"username": "base-user", "password": "Secret-pass-1!"},
            headers={"Origin": origin},
        )

    for foreign in (
        "https://testserver",
        "http://ospmae.example",
        "https://ospmae.example:8443",
        "https://ospmae.example.evil.test",
        "https://user@ospmae.example",
    ):
        assert outcome(attempt(foreign)) == ORIGIN_REFUSED
    assert attempt("https://ospmae.example").status_code == 200
    assert attempt("https://OSPMAE.example:443").status_code == 200


def test_signed_in_writes_from_a_foreign_origin_are_refused_with_a_valid_token():
    c, user = auth_client(role="admin")
    response = c.post(
        "/v1/me/shortcuts",
        json={"name": "x", "url": "/projects.html"},
        headers={
            "X-CSRF-Token": c.cookies["ospmae_csrf"],
            "Origin": "https://evil.example",
        },
    )
    assert outcome(response) == ORIGIN_REFUSED
    with SessionLocal() as db:
        assert db.query(UserShortcut).filter_by(user_id=user.id).count() == 0


@pytest.fixture()
def header_signed_in(monkeypatch):
    monkeypatch.setattr(settings, "trust_remote_user", True)
    make_user("proxied", "Secret-pass-1!", role="admin")
    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    c.headers.update({"X-Test-Peer": "127.0.0.1", "REMOTE_USER": "proxied"})
    return c


def test_header_signed_in_writes_need_the_csrf_token(header_signed_in):
    c = header_signed_in
    me = c.get("/v1/me")
    assert me.status_code == 200
    # No sign-in response carried the token, so this one does.
    token = me.cookies.get("ospmae_csrf")
    assert token
    shortcut = {"name": "x", "url": "/projects.html"}
    c.cookies.clear()
    assert outcome(c.post("/v1/me/shortcuts", json=shortcut)) == CSRF_REFUSED
    c.cookies.set("ospmae_csrf", token, domain="testserver.local")
    response = c.post(
        "/v1/me/shortcuts", json=shortcut, headers={"X-CSRF-Token": token}
    )
    assert response.status_code == 200, response.text
    # A browser that already holds the token is not issued another.
    assert "ospmae_csrf" not in c.get("/v1/me").cookies


# --- The signed-in account in routes ----------------------------------------


def test_routes_can_change_the_signed_in_account(monkeypatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    c, user = auth_client(password="Old-password-1!", role="admin")
    with SessionLocal() as db:
        before = db.get(User, user.id).password_hash
    response = c.post(
        "/v1/auth/change-password",
        json={
            "current_password": "Old-password-1!",
            "new_password": "New-password-2!",
            "confirm_password": "New-password-2!",
        },
        headers={"X-CSRF-Token": c.cookies["ospmae_csrf"]},
    )
    assert response.status_code == 204, response.text
    with SessionLocal() as db:
        assert db.get(User, user.id).password_hash != before


# --- Audit trail -------------------------------------------------------------


def audit_rows(**filters):
    with SessionLocal() as db:
        return db.query(AuditLog).filter_by(**filters).all()


@pytest.fixture()
def fresh_allowances(monkeypatch):
    monkeypatch.setattr(main_module, "_anonymous_audit", LocalAllowance(60, 60))
    monkeypatch.setattr(main_module, "_ws_handshakes", LocalAllowance(3, 60))


def from_address(client, address):
    client.headers.update({"X-Test-Peer": "127.0.0.1", "X-Forwarded-For": address})


def test_anonymous_requests_are_recorded_at_most_sixty_a_minute(
    client, fresh_allowances
):
    from_address(client, "203.0.113.5")
    for _ in range(65):
        assert client.get("/v1/me").status_code == 401
    rows = audit_rows(client_ip="203.0.113.5")
    assert len(rows) == 60
    assert {(r.username, r.path, r.status_code) for r in rows} == {
        (None, "/v1/me", 401)
    }
    # Each address has its own allowance.
    from_address(client, "203.0.113.6")
    client.get("/v1/me")
    assert len(audit_rows(client_ip="203.0.113.6")) == 1


def test_one_ipv6_network_shares_one_audit_allowance(client, fresh_allowances):
    for host in range(61):
        from_address(client, f"2001:db8:1:2::{host + 1:x}")
        client.get("/v1/me")
    with SessionLocal() as db:
        assert (
            db.query(AuditLog)
            .filter(AuditLog.client_ip.like("2001:db8:1:2::%"))
            .count()
            == 60
        )
    from_address(client, "2001:db8:1:3::1")
    client.get("/v1/me")
    assert len(audit_rows(client_ip="2001:db8:1:3::1")) == 1


def test_signed_in_requests_are_always_recorded(fresh_allowances):
    c, user = auth_client(role="admin")
    from_address(c, "203.0.113.9")
    anonymous = TestClient(c.app, base_url="https://testserver")
    from_address(anonymous, "203.0.113.9")
    for _ in range(61):
        anonymous.get("/v1/me")
    for _ in range(5):
        assert c.get("/v1/me").status_code == 200
    assert len(audit_rows(username=user.username, path="/v1/me")) == 5
    assert len(audit_rows(username=None, client_ip="203.0.113.9")) == 60


def test_public_reads_and_polls_are_not_recorded(client, fresh_allowances):
    assert client.get("/v1/auth/methods").status_code == 200
    client.get("/v1/system/health")
    c, _ = auth_client(role="admin")
    before = len(audit_rows())
    assert c.get("/v1/questions/unanswered/summary").status_code == 200
    assert len(audit_rows()) == before
    assert not audit_rows(path="/v1/auth/methods")
    assert not audit_rows(path="/v1/system/health")


def test_refusals_before_any_route_are_recorded(client, fresh_allowances):
    from_address(client, "203.0.113.7")
    client.post(
        "/v1/auth/login",
        json={"username": "a", "password": "b"},
        headers={"Origin": "https://evil.example"},
    )
    assert [(r.path, r.status_code) for r in audit_rows(client_ip="203.0.113.7")] == [
        ("/v1/auth/login", 403)
    ]


# --- Local allowances --------------------------------------------------------


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_local_allowance_resets_with_its_window():
    clock = Clock()
    allowance = LocalAllowance(2, 60, clock=clock)
    assert [allowance.allow("a") for _ in range(3)] == [True, True, False]
    assert allowance.allow("b") is True
    clock.now += 59.9
    assert allowance.allow("a") is False
    clock.now += 0.1
    assert allowance.allow("a") is True


def test_a_full_local_allowance_fails_closed_until_its_windows_pass():
    clock = Clock()
    allowance = LocalAllowance(5, 60, capacity=2, clock=clock)
    assert allowance.allow("a") and allowance.allow("b")
    assert allowance.allow("c") is False
    assert allowance.allow("a") is True  # known addresses keep counting
    clock.now += 60
    # Expired windows are dropped, so the table holds two fresh addresses again.
    assert allowance.allow("c") is True
    assert allowance.allow("d") is True
    assert allowance.allow("e") is False


def test_requests_without_an_address_share_one_allowance():
    allowance = LocalAllowance(1, 60, clock=Clock())
    assert allowance.allow(None) is True
    assert allowance.allow(None) is False


# --- WebSocket handshakes ----------------------------------------------------


def handshake(client, address, origin="https://testserver"):
    headers = {"X-Test-Peer": "127.0.0.1", "X-Forwarded-For": address}
    if origin:
        headers["Origin"] = origin
    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect("/ws/notifications", headers=headers) as ws:
            ws.receive_text()
    return closed.value.code


def test_handshake_allowances_count_the_resolved_client_address(
    client, fresh_allowances
):
    assert [handshake(client, "198.51.100.1") for _ in range(4)] == [
        4401,
        4401,
        4401,
        4429,
    ]
    # Another client behind the same proxy keeps its own allowance.
    assert handshake(client, "198.51.100.2") == 4401


def test_handshakes_need_the_application_origin(client, fresh_allowances):
    assert handshake(client, "198.51.100.3", origin=None) == 4403
    assert handshake(client, "198.51.100.3", origin="https://evil.example") == 4403


# --- Supplied patterns -------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"(a|a)*$",
        r"(.*a){20}",
        r"(\w+)\1",
        r"(?x)a b",
        r"(ab){2000}",
        "a" * 257,
        r"([a-z",
    ],
)
def test_patterns_that_can_backtrack_without_bound_are_refused(pattern):
    with pytest.raises(ValueError):
        check_pattern_shape(pattern)
    with pytest.raises(ValidationError):
        ReleaseFeedIgnorePatternPayload.model_validate(
            {"match_type": "regex", "pattern": pattern}
        )


@pytest.mark.parametrize(
    "pattern",
    [
        r"^v?\d+\.\d+\.\d+-rc\d*$",
        r"(?:\.\d+)*+$",
        r"nightly|beta|alpha",
        r"(ab){10}",
        r"[^/]+/[^/]+",
    ],
)
def test_bounded_patterns_are_accepted(pattern):
    check_pattern_shape(pattern)
    payload = ReleaseFeedIgnorePatternPayload.model_validate(
        {"match_type": "regex", "pattern": pattern}
    )
    assert payload.pattern == pattern


def test_a_stored_pattern_that_fails_the_checks_is_skipped_never_run():
    project = Project(id=1)
    project.release_rss_ignore_patterns = [
        {"match_type": "regex", "pattern": r"(a+)+$"},
        {"match_type": "regex", "pattern": r"-rc\d+$"},
    ]
    hostile = {"title": "a" * 40 + "!"}
    assert _release_feed_entry_is_ignored(project, hostile, "1.0.0") is False
    assert _release_feed_entry_is_ignored(project, {}, "1.0.0-rc1") is True


def test_ignore_patterns_read_a_bounded_window_of_feed_text():
    project = Project(id=1)
    project.release_rss_ignore_patterns = [{"match_type": "regex", "pattern": "tail$"}]
    entry = {"title": "x" * 2000 + "tail"}
    assert _release_feed_entry_is_ignored(project, entry, "") is False
    assert re.search("tail$", entry["title"])


# --- Address allowances group IPv6 networks ---------------------------------


def test_every_per_address_allowance_counts_one_ipv6_network(client, monkeypatch):
    from app.db.models import RateLimitEntry

    monkeypatch.setattr(settings, "local_auth_enabled", True)
    signed_in, _user = auth_client(role="viewer")
    for host in (1, 2, 3):
        from_address(client, f"2001:db8:5:6::{host}")
        from_address(signed_in, f"2001:db8:5:6::{host}")
        signed_in.post(
            "/v1/auth/change-password",
            json={
                "current_password": "wrong-password",
                "new_password": "New-password-2!",
                "confirm_password": "New-password-2!",
            },
            headers={"X-CSRF-Token": signed_in.cookies["ospmae_csrf"]},
        )
        client.get("/v1/auth/sso/nope/start")
        client.post(
            "/v1/auth/login", json={"username": "n", "password": "wrong-password"}
        )
    with SessionLocal() as db:
        keys = {
            key: db.query(RateLimitEntry).filter_by(identifier=key).count()
            for key in (
                "password_change:2001:db8:5:6::/64",
                "login:2001:db8:5:6::/64",
            )
        }
        stray = (
            db.query(RateLimitEntry)
            .filter(RateLimitEntry.identifier.like("%2001:db8:5:6::_"))
            .count()
        )
    assert keys == {
        "password_change:2001:db8:5:6::/64": 3,
        "login:2001:db8:5:6::/64": 3,
    }
    assert stray == 0
