"""What a browser holds and what the server stores for it: host-bound
cookies, session identifiers kept as digests, CSRF tokens that belong to one
session, and identity headers believed only from the proxies named for them.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
from app.core.config import Settings, settings
from app.db.models import Session as SessionRow
from app.db.session import SessionLocal
from app.security import auth, csrf
from app.security.client_addr import request_client_address
from app.security.sessions import csrf_token_for, session_row, stored_session_id
from fastapi import Response
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.requests import Request

from tests.conftest import auth_client, login, make_user, peer_wrapper

PASSWORD = "Test-passphrase-1!"
CSRF_REFUSED = (403, {"detail": "CSRF token missing or invalid"})
SESSION = "__Host-ospmae_session"
CSRF = "__Host-ospmae_csrf"
SHORTCUT = {"name": "x", "url": "/projects.html"}


def outcome(response):
    return response.status_code, response.json()


def write(client, token, **cookies):
    """One signed-in write carrying ``token`` in the header."""
    headers = {"X-CSRF-Token": token} if token is not None else {}
    return client.post("/v1/me/shortcuts", json=SHORTCUT, headers=headers)


def replace_cookie(client, name, value):
    client.cookies.delete(name)
    client.cookies.set(name, value, domain="testserver.local")


# -- cookie names -------------------------------------------------------------------


@pytest.mark.parametrize(
    "secure,domain,configured,name",
    [
        (True, "", "ospmae_csrf", "__Host-ospmae_csrf"),
        (True, "", "custom", "__Host-custom"),
        # A browser refuses a __Host- cookie that names a Domain or lacks Secure.
        (True, "example.org", "ospmae_csrf", "ospmae_csrf"),
        (False, "", "ospmae_csrf", "ospmae_csrf"),
        # A configured prefix is kept as it is.
        (True, "", "__Host-own", "__Host-own"),
        (True, "", "__Secure-own", "__Secure-own"),
    ],
)
def test_cookies_are_host_bound_only_when_they_can_be(
    monkeypatch, secure, domain, configured, name
):
    monkeypatch.setattr(settings, "cookie_secure", secure)
    monkeypatch.setattr(settings, "cookie_domain", domain)
    monkeypatch.setattr(settings, "csrf_cookie_name", configured)
    monkeypatch.setattr(settings, "session_cookie_name", configured)
    assert csrf.csrf_cookie_name() == name
    assert auth.session_cookie_name() == name

    for set_cookie, clear_cookie, http_only in (
        (csrf.set_csrf_cookie, csrf.clear_csrf_cookie, False),
        (auth.set_session_cookie, auth.clear_session_cookie, True),
    ):
        response = Response()
        set_cookie(response, "value")
        cookie = response.headers["set-cookie"]
        assert cookie.startswith(f"{name}=value;") and "Path=/" in cookie
        assert ("Secure" in cookie) is secure
        assert ("Domain=example.org" in cookie) is bool(domain)
        assert ("HttpOnly" in cookie) is http_only
        # An expiring cookie carries Secure too, or a browser ignores it and
        # the cookie outlives sign-out.
        response = Response()
        clear_cookie(response)
        cleared = response.headers["set-cookie"]
        assert cleared.startswith(f'{name}="";') and "Max-Age=0" in cleared
        assert ("Secure" in cleared) is secure


def test_sign_in_sets_and_sign_out_clears_the_host_bound_cookies():
    make_user("cookies", PASSWORD, role="viewer")
    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    signed_in = login(c, "cookies", PASSWORD)
    assert signed_in.status_code == 200
    cookies = {
        line.split("=", 1)[0]: [part.strip().lower() for part in line.split(";")[1:]]
        for line in signed_in.headers.get_list("set-cookie")
    }
    assert set(cookies) == {SESSION, CSRF, "__Host-ospmae_device"}
    for name, attributes in cookies.items():
        assert "secure" in attributes and "path=/" in attributes, name
        assert not any(a.startswith("domain") for a in attributes), name
    assert "httponly" in cookies[SESSION] and "httponly" not in cookies[CSRF]

    signed_out = c.post(
        "/v1/auth/logout", headers={"X-CSRF-Token": c.cookies.get(CSRF)}
    )
    assert signed_out.status_code == 204
    cleared = {
        line.split("=", 1)[0]: line.lower()
        for line in signed_out.headers.get_list("set-cookie")
    }
    for name in (SESSION, CSRF):
        assert "max-age=0" in cleared[name] and "secure" in cleared[name]
    assert c.get("/v1/me").status_code == 401


# -- session identifiers ---------------------------------------------------------------


def test_the_database_holds_no_session_identifier_a_browser_could_present():
    c, user = auth_client(role="viewer")
    sid = c.cookies.get(SESSION)
    with SessionLocal() as db:
        [stored] = [row.session_id for row in db.query(SessionRow).all()]
        assert (
            stored == hashlib.sha256(sid.encode()).hexdigest() == stored_session_id(sid)
        )
        assert sid not in stored
        assert session_row(db, sid).user_id == user.id
        assert session_row(db, stored) is None

    # Someone who reads the table cannot sign in with what they read.
    from app.main import app

    thief = TestClient(peer_wrapper(app), base_url="https://testserver")
    thief.cookies.set(SESSION, stored, domain="testserver.local")
    assert thief.get("/v1/me").status_code == 401
    assert c.get("/v1/me").status_code == 200


def test_every_lookup_of_a_presented_session_goes_through_one_helper():
    """A second copy of the lookup would compare the stored digest with the
    identifier a browser presents and never match, or store one unhashed."""
    app_root = Path(__file__).resolve().parents[1] / "app"
    pattern = re.compile(r"SessionRow\.session_id\s*==|session_id\s*=\s*sid\b")

    def offenders(sources: dict[str, str]) -> list[str]:
        return sorted(
            name
            for name, text in sources.items()
            if name != "security/sessions.py" and pattern.search(text)
        )

    sources = {
        str(path.relative_to(app_root)): path.read_text()
        for path in app_root.rglob("*.py")
    }
    assert offenders(sources) == []
    # The check finds the copies it guards against.
    copy = "row = db.query(SessionRow).filter(SessionRow.session_id == sid).first()"
    assert offenders({"api/routes/example.py": copy}) == ["api/routes/example.py"]
    assert offenders({"security/sessions.py": copy}) == []


def test_cookie_names_are_read_through_their_helpers():
    """The configured names are not the names browsers hold: a module that
    reads a cookie by the bare setting misses the host-bound one."""
    app_root = Path(__file__).resolve().parents[1] / "app"
    pattern = re.compile(r"settings\.(session|csrf)_cookie_name")
    homes = {"security/auth.py", "security/csrf.py"}

    def offenders(sources: dict[str, str]) -> list[str]:
        return sorted(
            name
            for name, text in sources.items()
            if name not in homes and pattern.search(text)
        )

    sources = {
        str(path.relative_to(app_root)): path.read_text()
        for path in app_root.rglob("*.py")
    }
    assert offenders(sources) == []
    copy = "sid = request.cookies.get(settings.session_cookie_name)"
    assert offenders({"api/routes/example.py": copy}) == ["api/routes/example.py"]


# -- CSRF tokens -----------------------------------------------------------------------


def test_a_session_has_its_own_csrf_token():
    c, _ = auth_client(role="viewer")
    token = c.cookies.get(CSRF)
    assert token == csrf_token_for(c.cookies.get(SESSION))
    assert c.get("/v1/me").json()["csrf_token"] == token
    assert write(c, token).status_code == 200

    # A browser that lost the cookie is given the same token again.
    c.cookies.delete(CSRF)
    assert c.get("/v1/me").cookies.get(CSRF) == token


def test_a_csrf_token_the_session_did_not_issue_proves_nothing():
    """Repeating the cookie in the header is no proof by itself: the token
    must belong to the session, whatever wrote the cookie."""
    c, _ = auth_client(role="viewer")
    issued = c.cookies.get(CSRF)
    other, _ = auth_client(role="viewer")
    borrowed = other.cookies.get(CSRF)

    for token in ("written-by-something-else", borrowed, issued[:-1], issued + "x"):
        replace_cookie(c, CSRF, token)
        assert outcome(write(c, token)) == CSRF_REFUSED
    with SessionLocal() as db:
        from app.db.models import UserShortcut

        assert db.query(UserShortcut).count() == 0

    replace_cookie(c, CSRF, issued)
    assert write(c, issued).status_code == 200


def test_only_the_host_bound_csrf_cookie_is_read():
    """A site on a sibling subdomain can set ``ospmae_csrf`` for the parent
    domain and knows its value; a browser lets only this host set
    ``__Host-ospmae_csrf``."""
    c, _ = auth_client(role="viewer")
    issued = c.cookies.get(CSRF)
    c.cookies.delete(CSRF)
    c.cookies.set("ospmae_csrf", issued, domain="testserver.local")
    assert outcome(write(c, issued)) == CSRF_REFUSED


@pytest.mark.parametrize("token", ["é", "ÿ" * 43, "ünïcödé-tökén"])
def test_a_token_with_other_characters_is_a_wrong_token(token):
    """Refused as any wrong token is, in the header and in the sign-out link,
    and never an error."""
    c, _ = auth_client(role="viewer")
    refused = c.post(
        "/v1/me/shortcuts",
        json=SHORTCUT,
        headers={"X-CSRF-Token": token.encode("latin-1", "replace")},
    )
    assert outcome(refused) == CSRF_REFUSED
    link = c.get("/v1/auth/logout", params={"csrf": token}, follow_redirects=False)
    assert (link.status_code, link.headers["location"]) == (302, "/index.html")
    assert c.get("/v1/me").status_code == 200


def test_the_sign_out_link_needs_the_sessions_own_token():
    c, _ = auth_client(role="viewer")
    issued = c.cookies.get(CSRF)
    other, _ = auth_client(role="viewer")
    borrowed = other.cookies.get(CSRF)

    # A token that repeats a cookie this session never issued leaves it alone.
    replace_cookie(c, CSRF, borrowed)
    kept = c.get("/v1/auth/logout", params={"csrf": borrowed}, follow_redirects=False)
    assert kept.headers["location"] == "/index.html"
    assert c.get("/v1/me").status_code == 200

    replace_cookie(c, CSRF, issued)
    ended = c.get("/v1/auth/logout", params={"csrf": issued}, follow_redirects=False)
    assert ended.headers["location"] == "/login.html"
    assert c.get("/v1/me").status_code == 401


# -- identity headers --------------------------------------------------------------------


def header_client(peer: str, **headers) -> TestClient:
    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    c.headers.update({"X-Test-Peer": peer, "REMOTE_USER": "proxied", **headers})
    return c


def test_a_proxy_trusted_for_addresses_cannot_name_the_signed_in_account(monkeypatch):
    """The Compose default trusts the network gateway to forward client
    addresses, and every process on the Docker host connects through the
    gateway. Naming the account is a separate trust with its own list."""
    make_user("proxied", PASSWORD, role="admin")
    monkeypatch.setattr(settings, "trust_remote_user", True)
    monkeypatch.setattr(
        settings, "trusted_proxy_cidrs", "172.30.66.10/32,172.30.66.1/32"
    )
    monkeypatch.setattr(settings, "remote_user_trusted_cidrs", "172.30.66.10/32")

    # The gateway forwards addresses and is believed about them only.
    gateway = header_client("172.30.66.1", **{"X-Forwarded-For": "203.0.113.9"})
    assert gateway.get("/v1/me").status_code == 401
    # The authenticating proxy is believed about the account.
    proxy = header_client("172.30.66.10")
    assert proxy.get("/v1/me").json()["username"] == "proxied"
    # With no list at all, nobody's header is believed.
    monkeypatch.setattr(settings, "remote_user_trusted_cidrs", "")
    assert proxy.get("/v1/me").status_code == 401
    assert header_client("127.0.0.1").get("/v1/me").status_code == 401


@pytest.mark.parametrize(
    "values,accepted",
    [
        ({}, True),
        ({"trust_remote_user": True, "remote_user_trusted_cidrs": "10.1.2.3/32"}, True),
        (
            {"trust_remote_user": True, "remote_user_trusted_cidrs": "10.1.2.3,::1"},
            True,
        ),
        ({"trust_remote_user": True}, False),
        ({"trust_remote_user": True, "remote_user_trusted_cidrs": " , "}, False),
        ({"remote_user_trusted_cidrs": "not-an-address"}, False),
    ],
)
def test_trusting_an_identity_header_needs_its_proxies_named(values, accepted):
    if accepted:
        assert Settings(_env_file=None, **values).trust_remote_user is values.get(
            "trust_remote_user", False
        )
        return
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_a_header_signed_in_browser_proves_writes_with_the_host_bound_cookie(
    monkeypatch,
):
    """Without a session there is no session token, so the cookie's name is
    what keeps a planted token out."""
    make_user("proxied", PASSWORD, role="admin")
    monkeypatch.setattr(settings, "trust_remote_user", True)
    monkeypatch.setattr(settings, "remote_user_trusted_cidrs", "127.0.0.1/32")
    c = header_client("127.0.0.1")
    token = c.get("/v1/me").cookies.get(CSRF)
    assert token

    c.cookies.clear()
    c.cookies.set("ospmae_csrf", "planted", domain="testserver.local")
    assert outcome(write(c, "planted")) == CSRF_REFUSED
    c.cookies.set(CSRF, token, domain="testserver.local")
    assert write(c, token).status_code == 200


# -- forwarded addresses -------------------------------------------------------------------


def _request(peer: str, *forwarded: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", line.encode()) for line in forwarded],
            "client": (peer, 50000),
        }
    )


def test_forwarded_address_lines_are_read_as_one_list(monkeypatch):
    """A proxy may append its own X-Forwarded-For line after the client's
    (RFC 9110 section 5.3). Reading the first line alone would take the
    client's word for its address."""
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "10.0.0.1/32")
    assert request_client_address(_request("10.0.0.1", "1.2.3.4", "203.0.113.9")) == (
        "203.0.113.9"
    )
    assert request_client_address(_request("10.0.0.1", "1.2.3.4, 203.0.113.9")) == (
        "203.0.113.9"
    )
    assert request_client_address(_request("10.0.0.1")) == "10.0.0.1"
    # An untrusted peer's lines count for nothing.
    assert request_client_address(_request("198.51.100.7", "1.2.3.4", "5.6.7.8")) == (
        "198.51.100.7"
    )


# -- what the API serves to anyone ------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"]
)
def test_the_api_serves_no_schema_or_interactive_pages(path):
    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    assert c.get(path).status_code == 404
    signed_in, _ = auth_client(role="admin")
    assert signed_in.get(path).status_code == 404


# -- the example environment ---------------------------------------------------------------------


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
    # The check finds what the example used to ship.
    assert shipped({"POSTGRES_PASSWORD": "<GENERATE_STRONG_PASSWORD>"}) == [
        "POSTGRES_PASSWORD"
    ]
