"""Request limits, origin and CSRF checks, the audit trail allowance and
supplied-pattern checks: the hardening shared with KEEN."""

from __future__ import annotations

import asyncio
import json
import re
import time

import app.main as main_module
import pytest
from app.api.payloads import ReleaseFeedIgnorePatternPayload
from app.core.config import settings
from app.db.models import AuditLog, LoginThrottle, Project, User, UserShortcut
from app.db.models import Session as SessionRow
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
        "/v1/projects",
        json=big,
        headers={"X-CSRF-Token": c.cookies["__Host-ospmae_csrf"]},
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
            "X-CSRF-Token": c.cookies["__Host-ospmae_csrf"],
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
    make_user("origin-user", "Secret-passphrase-1!")
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
            json={"username": "origin-user", "password": "Secret-passphrase-1!"},
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
    make_user("base-user", "Secret-passphrase-1!")

    def attempt(origin):
        return client.post(
            "/v1/auth/login",
            json={"username": "base-user", "password": "Secret-passphrase-1!"},
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
            "X-CSRF-Token": c.cookies["__Host-ospmae_csrf"],
            "Origin": "https://evil.example",
        },
    )
    assert outcome(response) == ORIGIN_REFUSED
    with SessionLocal() as db:
        assert db.query(UserShortcut).filter_by(user_id=user.id).count() == 0


@pytest.fixture()
def header_signed_in(monkeypatch):
    monkeypatch.setattr(settings, "trust_remote_user", True)
    monkeypatch.setattr(settings, "remote_user_trusted_cidrs", "127.0.0.1/32")
    make_user("proxied", "Secret-passphrase-1!", role="admin")
    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    c.headers.update({"X-Test-Peer": "127.0.0.1", "REMOTE_USER": "proxied"})
    return c


def test_header_signed_in_writes_need_the_csrf_token(header_signed_in):
    c = header_signed_in
    me = c.get("/v1/me")
    assert me.status_code == 200
    # No sign-in response carried the token, so this one does.
    token = me.cookies.get("__Host-ospmae_csrf")
    assert token
    shortcut = {"name": "x", "url": "/projects.html"}
    c.cookies.clear()
    assert outcome(c.post("/v1/me/shortcuts", json=shortcut)) == CSRF_REFUSED
    c.cookies.set("__Host-ospmae_csrf", token, domain="testserver.local")
    response = c.post(
        "/v1/me/shortcuts", json=shortcut, headers={"X-CSRF-Token": token}
    )
    assert response.status_code == 200, response.text
    # A browser that already holds the token is not issued another.
    assert "__Host-ospmae_csrf" not in c.get("/v1/me").cookies


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
            "new_password": "New-passphrase-two-2!",
            "confirm_password": "New-passphrase-two-2!",
        },
        headers={"X-CSRF-Token": c.cookies["__Host-ospmae_csrf"]},
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
        # Bounded repeats nest exponentially too: each round of the outer
        # one can take the text in more than one way.
        r"(?:a{1,2}){1,512}!",
        r"(?:a{0,32}){0,32}!",
        r"(?:a|aa){1,512}!",
        r"(?:a?b?){1,40}c",
        r"(?:x\d*\d*){2,9}",
        r"(?:(?:a{1,3}|b)){1,300}!",
        r"(?:a*){2}!",
        r"(?:\d+\.?){1,9}x",
        # Repeats in a row over the same text multiply by its length each.
        r"a*a*a*!",
        r"a*a*a*a*a*a*!",
        r"a*aa*aa*a!",
        r".*.*.*=",
        r"\w*\d*[a-z]*x",
        r"(?:ab)*+a*(?:ab)?a*a*!",
        # The same shapes over characters far from ASCII: what two repeats
        # share is judged on the characters the pattern itself names.
        "(?:[^\\x00-\\u017f]{1,32}){1,32}$",
        "(?:\u044f{1,32}){1,32}$",
        "(?:[\u4e00-\u4e10]{1,9}){1,9}!",
        "[\u4e00-\u4e10]*[\u4e08-\u4e20]*\u4e09*!",
        "(?i)(?:\u03a9{1,9}[\u03c0-\u03cf]{1,9}){1,9}!",
        "(?:\\d{1,9}\u0663{1,9}){1,9}!",
        # A lookaround's repeats run over the same text as those around it.
        r"a*(?=a*a*x)a*$",
        r"a*(?=a*x)a*a*$",
        r"(?!a*b)a*(?<=a*)a*!",
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
        # Repeats kept apart by text neither can match, or two at most.
        r"^v?\d+\.\d+\.\d+-(?:rc|beta|alpha)\.?\d*$",
        r"\d+\.\d+(?:\.\d+)?(?:-\w+)?$",
        r"[a-z]+-[a-z]+-[a-z]+",
        r"a*b*c*",
        r"a*a*",
        r".*rc.*",
        r"\s*v\d+",
        # A fixed count inside a repeat, and rounds that cannot run together.
        r"(?:x{2}){1,5}",
        r"(?:\d{1,3}\.){2}\d+",
        r"(?:rc|beta){1,3}",
        # Possessive repeats commit, so they share nothing.
        r"a*+a*+a*+!",
        r"(?:a{1,2})++!",
        # Other scripts, kept apart as any repeats are.
        "\u044f+-\u044f+-\u044f+",
        "[\u0430-\u044f]+\\d+",
        "(?:[\u4e00-\u4e10]{1,9}-){1,9}!",
        # The usual way to say "not a pre-release".
        r"^(?!.*beta).*$",
        r"^v\d+(?=\.)",
    ],
)
def test_bounded_patterns_are_accepted(pattern):
    check_pattern_shape(pattern)
    payload = ReleaseFeedIgnorePatternPayload.model_validate(
        {"match_type": "regex", "pattern": pattern}
    )
    assert payload.pattern == pattern


def test_a_project_keeps_a_bounded_number_of_ignore_patterns():
    from app.api.payloads import ProjectUpdatePayload
    from app.security.regex_shape import MAX_IGNORE_PATTERNS
    from app.tasks import release_feed as rf

    rules = [{"match_type": "contains", "pattern": f"rc{n}"} for n in range(51)]
    kept = ProjectUpdatePayload.model_validate(
        {"release_rss_ignore_patterns": rules[:MAX_IGNORE_PATTERNS]}
    )
    assert len(kept.release_rss_ignore_patterns) == 50
    for too_many in (rules, "\n".join(f"rc{n}" for n in range(51))):
        with pytest.raises(ValidationError, match="at most 50 ignore patterns"):
            ProjectUpdatePayload.model_validate(
                {"release_rss_ignore_patterns": too_many}
            )
    # A longer list saved before the limit is read up to it.
    stored = Project(id=3, release_rss_ignore_patterns=[f"rc{n}" for n in range(80)])
    assert len(rf._normalised_release_ignore_patterns(stored)) == 50
    assert rf._release_feed_entry_is_ignored(stored, {"title": "v1-rc49"}, "v1") is True
    assert (
        rf._release_feed_entry_is_ignored(stored, {"title": "v1-rc50x"}, "v1") is True
    )
    assert rf._release_feed_entry_is_ignored(stored, {"title": "v1-rc7"}, "v1") is True
    assert rf._release_feed_entry_is_ignored(stored, {"title": "v1-rd"}, "v1") is False


def test_slow_rules_cost_a_project_a_fixed_budget_not_one_deadline_each(monkeypatch):
    """Rules that reach the deadline are counted: each is tried once in a
    run, and together they spend a budget after which no rule is tried."""
    import re

    from app.security import regex_shape
    from app.tasks import release_feed as rf

    searched: list[str] = []

    def timed_out(compiled, text, seconds=regex_shape.SEARCH_SECONDS):
        searched.append(compiled.pattern)
        return (
            None if compiled.pattern.startswith("slow") else bool(compiled.search(text))
        )

    monkeypatch.setattr(rf, "search_within", timed_out)
    monkeypatch.setattr(rf, "compile_supplied_pattern", lambda p, f: re.compile(p, f))
    monkeypatch.setattr(rf.log, "warning", lambda *a: None)
    rules = [{"match_type": "regex", "pattern": f"slow{n}"} for n in range(30)]
    rules.append({"match_type": "regex", "pattern": "nightly"})
    project = Project(id=9, release_rss_ignore_patterns=rules)
    budget = rf.MatchBudget(seconds=5 * regex_shape.SEARCH_SECONDS)

    entry = {"title": "v1.0.0-nightly", "link": "", "id": ""}
    # Five deadlines spend the budget; the rules after them, the good one
    # included, are not consulted, and the entry is taken.
    assert rf._release_feed_entry_is_ignored(project, entry, "v1.0.0", budget) is False
    assert searched == [f"slow{n}" for n in range(5)]
    assert budget.spent
    # Nothing more is searched for this project in this run.
    assert rf._release_feed_entry_is_ignored(project, entry, "v1.0.1", budget) is False
    assert len(searched) == 5

    # With room in the budget a slow rule is tried once, and the others
    # still decide.
    searched.clear()
    roomy = rf.MatchBudget()
    few = Project(id=9, release_rss_ignore_patterns=rules[:2] + rules[-1:])
    assert rf._release_feed_entry_is_ignored(few, entry, "v1.0.0", roomy) is True
    assert rf._release_feed_entry_is_ignored(few, entry, "v1.0.1", roomy) is True
    # Each slow rule once; the good rule against the label and then the
    # title of both entries.
    assert searched == ["slow0", "slow1"] + ["nightly"] * 4
    assert not roomy.spent


def test_a_deadline_that_fires_as_the_search_returns_is_still_a_stop():
    import re
    import signal

    from app.security import regex_shape

    class Slow:
        pattern = "x"

        def search(self, text):
            # The timer goes off after the search has its answer.
            signal.raise_signal(signal.SIGALRM)
            return re.match("x", "x")

    before = signal.getsignal(signal.SIGALRM)
    assert regex_shape.search_within(Slow(), "x") is None
    # The handler and the timer are as they were.
    assert signal.getsignal(signal.SIGALRM) is before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


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
                "new_password": "New-passphrase-two-2!",
                "confirm_password": "New-passphrase-two-2!",
            },
            headers={"X-CSRF-Token": signed_in.cookies["__Host-ospmae_csrf"]},
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


def test_every_accepted_pattern_searches_a_full_window_quickly():
    """The claim the shape check makes, measured: the patterns it accepts
    search the longest text a feed can offer, built to suit each of them, in
    far less than one search's allowance."""
    import re
    import time

    from app.security.regex_shape import SEARCH_SECONDS, compile_supplied_pattern

    accepted = [
        r"^v?\d+\.\d+\.\d+-(?:rc|beta|alpha)\.?\d*$",
        r"\d+\.\d+(?:\.\d+)?(?:-\w+)?$",
        r"[a-z]+-[a-z]+-[a-z]+",
        r"a*b*c*",
        r"a*a*",
        r".*rc.*",
        r"(?:x{2}){1,5}",
        r"(?:\d{1,3}\.){2}\d+",
        r"(?:\.\d+)*+$",
        r"[^/]+/[^/]+",
    ]
    texts = [
        unit * (1024 // len(unit))
        for unit in ("a", "1", "a1", "1.", "-a", "x", "r", "/a")
    ]
    for pattern in accepted:
        compiled = compile_supplied_pattern(pattern, re.IGNORECASE)
        started = time.perf_counter()
        for text in texts:
            compiled.search(text)
            compiled.search(text + "!")
        assert time.perf_counter() - started < SEARCH_SECONDS, pattern


def test_a_search_stops_at_its_allowance_and_leaves_no_timer_behind():
    import re
    import signal
    import threading
    import time

    from app.security.regex_shape import search_within

    slow = re.compile("(?:a|aa){1,512}!")
    handler_before = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()
    assert search_within(slow, "a" * 200, seconds=0.1) is None
    assert time.monotonic() - started < 2
    # The previous handler is back and no timer is pending.
    assert signal.getsignal(signal.SIGALRM) is handler_before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    assert search_within(slow, "aaa!") is True
    assert search_within(slow, "bbb") is False

    # Off the main thread there is no timer to set: the search just runs.
    found: list[bool | None] = []
    worker = threading.Thread(
        target=lambda: found.append(search_within(re.compile("b+"), "abba"))
    )
    worker.start()
    worker.join()
    assert found == [True]
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


# --- Open notification sockets -----------------------------------------------


def test_an_open_socket_ends_when_its_session_does(fresh_allowances, monkeypatch):
    """The socket is authenticated at its handshake; a sign-out afterwards
    ends it at its next check instead of leaving it to receive."""
    from app.realtime.notifications import hub
    from app.security.auth import session_cookie_name

    monkeypatch.setattr(main_module, "_WS_RECHECK_SECONDS", 0.05)
    client, user = auth_client(role="viewer")
    # The test client opens sockets over plain ws, where it withholds Secure
    # cookies; a browser's wss handshake carries them, as this header does.
    name = session_cookie_name()
    headers = {
        "X-Test-Peer": "127.0.0.1",
        "Origin": "https://testserver",
        "Cookie": f"{name}={client.cookies.get(name)}",
    }
    with client.websocket_connect("/ws/notifications", headers=headers) as ws:
        # Still signed in: checks pass and the socket stays registered.
        time.sleep(0.3)
        assert user.id in hub._connections
        with SessionLocal() as s:
            expiry_before = (
                s.query(SessionRow).filter_by(user_id=user.id).one().expires_at
            )
        time.sleep(0.2)
        with SessionLocal() as s:
            row = s.query(SessionRow).filter_by(user_id=user.id).one()
            # Asking extends nothing: an idle socket keeps no session alive.
            assert row.expires_at == expiry_before
            s.delete(row)
            s.commit()
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
        assert closed.value.code == 4401
    assert user.id not in hub._connections


def test_a_socket_that_keeps_talking_is_checked_as_often_as_a_quiet_one(
    fresh_allowances, monkeypatch
):
    """Frames from the client do not put the check off: a socket that sends
    one every few milliseconds still ends when its session does."""
    import threading

    from app.realtime.notifications import hub
    from app.security.auth import session_cookie_name

    monkeypatch.setattr(main_module, "_WS_RECHECK_SECONDS", 0.2)
    checks: list[float] = []
    real = main_module._socket_still_signed_in

    def counted(*args):
        checks.append(time.monotonic())
        return real(*args)

    monkeypatch.setattr(main_module, "_socket_still_signed_in", counted)
    client, user = auth_client(role="viewer")
    name = session_cookie_name()
    headers = {
        "X-Test-Peer": "127.0.0.1",
        "Origin": "https://testserver",
        "Cookie": f"{name}={client.cookies.get(name)}",
    }
    with client.websocket_connect("/ws/notifications", headers=headers) as ws:
        talking = threading.Event()

        def chatter():
            while not talking.is_set():
                try:
                    ws.send_text("still here")
                except Exception:
                    return
                time.sleep(0.01)

        thread = threading.Thread(target=chatter, daemon=True)
        thread.start()
        try:
            time.sleep(0.7)
            # Checked on the clock while frames kept arriving.
            assert len(checks) >= 2
            assert user.id in hub._connections
            with SessionLocal() as s:
                s.query(SessionRow).filter_by(user_id=user.id).delete()
                s.commit()
            with pytest.raises(WebSocketDisconnect) as closed:
                ws.receive_text()
            assert closed.value.code == 4401
        finally:
            talking.set()
            thread.join(timeout=2)
    assert user.id not in hub._connections


@pytest.mark.parametrize(
    "event", ["deactivated", "enrolment_moved_on", "other_account"]
)
def test_still_signed_in_follows_the_account_and_the_session(event):
    from app.security.auth import session_cookie_name, still_signed_in

    client, user = auth_client(role="viewer")
    cookies = {session_cookie_name(): client.cookies.get(session_cookie_name())}
    with SessionLocal() as s:
        assert still_signed_in({}, cookies, s, user.id) is True
        assert still_signed_in({}, {}, s, user.id) is False
        assert (
            still_signed_in({}, {session_cookie_name(): "x" * 43}, s, user.id) is False
        )
        account = s.get(User, user.id)
        if event == "deactivated":
            account.is_active = False
        elif event == "enrolment_moved_on":
            account.mfa_version = account.mfa_version + 1
        s.commit()
        asked_for = user.id + 1 if event == "other_account" else user.id
        assert still_signed_in({}, cookies, s, asked_for) is False
