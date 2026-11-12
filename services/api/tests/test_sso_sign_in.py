"""Single sign-on through the assembled application, with tokens signed by a
provider key: the browser binding, the checks on what the provider returns,
the allowance on starts and the provider's key rotation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import app.security.oidc as oidc
import pytest
from app.api.routes import auth as auth_routes
from app.core.config import settings
from app.db.models import AuditLog, OidcLoginState, UserIdentity
from app.db.models import Session as SessionRow
from app.db.session import SessionLocal
from app.security.sessions import csrf_token_for
from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from tests.conftest import make_user, peer_wrapper

ISSUER = "https://idp.example.com"
BINDING_REFUSED = (
    400,
    {"detail": "SSO browser verification failed; start sign-in again"},
)
UNVERIFIED = (400, {"detail": "SSO sign-in could not be verified"})


def _key(kid: str):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk = JsonWebKey.import_key(public, {"kty": "RSA", "kid": kid, "use": "sig"})
    return pem, public, jwk.as_dict()


PRIVATE, PUBLIC, JWK = _key("k1")
OTHER_PRIVATE, _OTHER_PUBLIC, OTHER_JWK = _key("k2")


@pytest.fixture(autouse=True)
def provider(monkeypatch):
    """A configured OpenID Connect provider whose key set holds JWK."""
    for name, value in {
        "oidc_sso_enabled": True,
        "oidc_client_id": "client",
        "oidc_client_secret": "secret",
        "oidc_authorization_endpoint": ISSUER + "/auth",
        "oidc_token_endpoint": ISSUER + "/token",
        "oidc_redirect_uri": "https://testserver/v1/auth/sso/oidc/callback",
        "oidc_jwks_uri": ISSUER + "/jwks",
        "oidc_issuer": ISSUER,
    }.items():
        monkeypatch.setattr(settings, name, value)

    async def key_set(uri, kid=None):
        return {"keys": [JWK]}

    monkeypatch.setattr(oidc, "_get_jwks", key_set)
    oidc._JWKS_CACHE.clear()


def browser(address: str = "9.9.9.9") -> TestClient:
    from app.main import app

    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    c.headers["X-Test-Peer"] = "127.0.0.1"
    c.headers["X-Forwarded-For"] = address
    return c


def start(c: TestClient, provider_key: str = "oidc"):
    """Start a sign-in; returns its state and the nonce stored for it."""
    response = c.get(f"/v1/auth/sso/{provider_key}/start", follow_redirects=False)
    assert response.status_code == 302, response.text
    state = response.headers["location"].split("state=")[-1].split("&")[0]
    with SessionLocal() as db:
        nonce = db.query(OidcLoginState).filter_by(state=state).one().nonce
    return state, nonce, response


def claims(nonce: str, **changes) -> dict:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "aud": "client",
        "sub": "subject-1",
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
    } | changes


def signed(nonce: str, *, key=PRIVATE, kid: str = "k1", **changes) -> str:
    return jwt.encode(
        {"alg": "RS256", "kid": kid}, claims(nonce, **changes), key
    ).decode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unsigned(nonce: str) -> str:
    header = _b64(json.dumps({"alg": "none", "kid": "k1"}).encode())
    return header + "." + _b64(json.dumps(claims(nonce)).encode()) + "."


def keyed_with_the_public_key(nonce: str) -> str:
    """An HS256 token whose secret is the provider's public key."""
    header = _b64(json.dumps({"alg": "HS256", "kid": "k1"}).encode())
    body = _b64(json.dumps(claims(nonce)).encode())
    mac = hmac.new(PUBLIC, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64(mac)}"


def linked(username: str = "linked", subject: str = "subject-1"):
    user = make_user(username, "Synthetic-passphrase-1!", role="viewer")
    with SessionLocal() as db:
        db.add(
            UserIdentity(
                user_id=user.id,
                provider="oidc",
                issuer=ISSUER,
                subject=subject,
                claims={},
            )
        )
        db.commit()
    return user


def callback(c: TestClient, state: str, token: str, monkeypatch, provider_key="oidc"):
    async def exchange(self, endpoint, **_kwargs):
        return {"access_token": "at", "id_token": token}

    monkeypatch.setattr(oidc.AsyncOAuth2Client, "fetch_token", exchange)
    return c.get(
        f"/v1/auth/sso/{provider_key}/callback?state={state}&code=x",
        follow_redirects=False,
    )


def outcome(response):
    return response.status_code, response.json()


def sessions() -> int:
    with SessionLocal() as db:
        return db.query(SessionRow).count()


def sign_in_rows() -> list[tuple[str | None, str]]:
    with SessionLocal() as db:
        rows = db.query(AuditLog).filter_by(path="/action/sign-in").all()
        return [(row.username, row.query_string) for row in rows]


# -- the browser binding ---------------------------------------------------------


def test_the_browser_that_starts_a_sign_in_finishes_it(monkeypatch):
    user = linked()
    c = browser()
    state, nonce, started = start(c)

    # The state is a digest: it names this provider and the secret this
    # browser alone was given, in a host-bound, script-proof cookie.
    [cookie] = started.headers.get_list("set-cookie")
    secret = c.cookies.get("__Host-ospmae_sso")
    assert state == hashlib.sha256(f"oidc\0{secret}".encode()).hexdigest()
    attributes = [part.strip().lower() for part in cookie.split(";")]
    assert cookie.startswith("__Host-ospmae_sso=")
    assert {"httponly", "secure", "path=/", "samesite=lax", "max-age=600"} <= set(
        attributes
    )
    assert not any(part.startswith("domain") for part in attributes)
    assert started.headers["cache-control"] == "no-store"

    finished = callback(c, state, signed(nonce), monkeypatch)
    assert (finished.status_code, finished.headers["location"]) == (302, "/index.html")
    assert c.get("/v1/me").json()["username"] == user.username
    # The binding is spent with the sign-in, and the session's own CSRF token
    # came with it.
    assert c.cookies.get("__Host-ospmae_sso") is None
    assert c.cookies.get("__Host-ospmae_csrf") == csrf_token_for(
        c.cookies.get("__Host-ospmae_session")
    )
    assert sign_in_rows() == [(user.username, "method=oidc&outcome=success")]


def test_the_older_sign_in_addresses_are_bound_to_the_browser_too(monkeypatch):
    """/v1/auth/oidc/start and /callback are the same sign-in under its
    earlier address."""
    linked()
    c = browser()
    started = c.get("/v1/auth/oidc/start", follow_redirects=False)
    assert started.status_code == 302 and c.cookies.get("__Host-ospmae_sso")
    state = started.headers["location"].split("state=")[-1].split("&")[0]
    with SessionLocal() as db:
        nonce = db.query(OidcLoginState).filter_by(state=state).one().nonce
    token = signed(nonce)

    async def exchange(self, endpoint, **_kwargs):
        return {"access_token": "at", "id_token": token}

    monkeypatch.setattr(oidc.AsyncOAuth2Client, "fetch_token", exchange)
    address = f"/v1/auth/oidc/callback?state={state}&code=x"
    assert outcome(browser("9.9.9.11").get(address)) == BINDING_REFUSED
    assert c.get(address, follow_redirects=False).status_code == 302
    assert c.get("/v1/me").json()["username"] == "linked"


def test_a_callback_signs_in_only_the_browser_that_started_it(monkeypatch):
    """Login CSRF: someone signs in at the provider as themselves, keeps the
    callback link unvisited and sends it to another person, whose browser
    would otherwise be signed in to the sender's account."""
    linked("sender")
    sender = browser()
    state, nonce, _ = start(sender)
    token = signed(nonce)

    victim = browser("9.9.9.10")
    assert outcome(callback(victim, state, token, monkeypatch)) == BINDING_REFUSED
    assert victim.get("/v1/me").status_code == 401
    # A browser holding some other sign-in's secret is no better placed.
    start(victim)
    assert outcome(callback(victim, state, token, monkeypatch)) == BINDING_REFUSED
    assert sessions() == 0

    # The refusals consumed nothing: the browser that started still finishes.
    assert callback(sender, state, token, monkeypatch).status_code == 302
    assert sender.get("/v1/me").json()["username"] == "sender"


@pytest.mark.parametrize(
    "state",
    ["", "short", "g" * 64, "é" * 64, "0" * 63, "0" * 65],
    ids=["missing", "short", "unknown", "non-ascii", "one-short", "one-long"],
)
def test_a_state_this_browser_was_not_given_is_refused(state, monkeypatch):
    linked()
    c = browser()
    _state, nonce, _ = start(c)
    assert outcome(callback(c, state, signed(nonce), monkeypatch)) == BINDING_REFUSED
    assert sessions() == 0


def test_a_sign_in_finishes_at_the_provider_it_started_with(monkeypatch):
    """A state begun with one provider is refused at another's callback, so
    one provider cannot be handed a code or a state meant for another."""
    for name, value in {
        "google_sso_enabled": True,
        "google_client_id": "client",
        "google_client_secret": "secret",
        "google_redirect_uri": "https://testserver/v1/auth/sso/google/callback",
    }.items():
        monkeypatch.setattr(settings, name, value)
    linked()
    c = browser()
    state, nonce, _ = start(c, "google")
    refused = callback(c, state, signed(nonce), monkeypatch, provider_key="oidc")
    assert outcome(refused) == BINDING_REFUSED
    assert sessions() == 0
    with SessionLocal() as db:
        assert db.query(OidcLoginState).filter_by(state=state).count() == 1


def test_a_state_is_used_once(monkeypatch):
    linked()
    c = browser()
    state, nonce, _ = start(c)
    secret = c.cookies.get("__Host-ospmae_sso")
    assert callback(c, state, signed(nonce), monkeypatch).status_code == 302
    c.cookies.set("__Host-ospmae_sso", secret, domain="testserver.local")
    again = callback(c, state, signed(nonce), monkeypatch)
    assert outcome(again) == (400, {"detail": "SSO state missing or expired"})


def test_callbacks_sent_together_redeem_a_sign_in_once(monkeypatch):
    linked()
    c = browser()
    state, nonce, _ = start(c)
    secret = c.cookies.get("__Host-ospmae_sso")
    token = signed(nonce)

    async def exchange(self, endpoint, **_kwargs):
        return {"access_token": "at", "id_token": token}

    monkeypatch.setattr(oidc.AsyncOAuth2Client, "fetch_token", exchange)
    gate = threading.Barrier(8)

    def redeem(_n):
        attempt = browser()
        attempt.cookies.set("__Host-ospmae_sso", secret, domain="testserver.local")
        gate.wait()
        return attempt.get(
            f"/v1/auth/sso/oidc/callback?state={state}&code=x", follow_redirects=False
        ).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = sorted(pool.map(redeem, range(8)))
    assert answers == [302] + [400] * 7


def test_an_expired_sign_in_is_refused_and_forgotten(monkeypatch):
    linked()
    c = browser()
    state, nonce, _ = start(c)
    with SessionLocal() as db:
        db.query(OidcLoginState).update(
            {OidcLoginState.expires_at: datetime.utcnow() - timedelta(seconds=1)}
        )
        db.commit()
    refused = callback(c, state, signed(nonce), monkeypatch)
    assert outcome(refused) == (400, {"detail": "SSO state missing or expired"})
    with SessionLocal() as db:
        assert db.query(OidcLoginState).count() == 0
    assert sessions() == 0


# -- what the provider returns -----------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        lambda nonce: unsigned(nonce),
        lambda nonce: keyed_with_the_public_key(nonce),
        lambda nonce: signed(nonce, key=OTHER_PRIVATE),
        lambda nonce: signed("another-nonce"),
        lambda nonce: jwt.encode(
            {"alg": "RS256", "kid": "k1"},
            {k: v for k, v in claims(nonce).items() if k != "nonce"},
            PRIVATE,
        ).decode(),
        lambda nonce: signed(nonce, aud="someone-else"),
        lambda nonce: signed(nonce, iss="https://other-idp.example.com"),
        lambda nonce: signed(
            nonce, exp=int(time.time()) - 3600, iat=int(time.time()) - 7200
        ),
        lambda nonce: "not-a-token",
    ],
    ids=[
        "unsigned",
        "public-key-as-secret",
        "another-key",
        "another-nonce",
        "no-nonce",
        "another-audience",
        "another-issuer",
        "expired",
        "malformed",
    ],
)
def test_a_token_the_provider_does_not_vouch_for_signs_no_one_in(token, monkeypatch):
    linked()
    c = browser()
    state, nonce, _ = start(c)

    refused = callback(c, state, token(nonce), monkeypatch)

    # A refusal, never an unhandled error, and the attempt is on record.
    assert outcome(refused) == UNVERIFIED
    assert c.get("/v1/me").status_code == 401
    assert sessions() == 0
    assert sign_in_rows() == [(None, "method=oidc&outcome=failed")]


def test_a_failed_code_exchange_is_a_refused_sign_in(monkeypatch):
    linked()
    c = browser()
    state, _nonce, _ = start(c)

    async def unreachable(self, endpoint, **_kwargs):
        raise oidc.httpx.ConnectError("synthetic outage")

    monkeypatch.setattr(oidc.AsyncOAuth2Client, "fetch_token", unreachable)
    refused = c.get(f"/v1/auth/sso/oidc/callback?state={state}&code=x")
    assert outcome(refused) == UNVERIFIED
    assert sessions() == 0


# -- provider addresses --------------------------------------------------------------


@pytest.mark.parametrize(
    "setting,named",
    [
        ("oidc_authorization_endpoint", "authorisation endpoint"),
        ("oidc_token_endpoint", "token endpoint"),
        ("oidc_jwks_uri", "key set"),
        ("oidc_redirect_uri", "redirect URI"),
    ],
)
def test_a_provider_address_without_tls_starts_no_sign_in(setting, named, monkeypatch):
    monkeypatch.setattr(settings, setting, "http://idp.example.com/endpoint")
    refused = browser().get("/v1/auth/sso/oidc/start", follow_redirects=False)
    assert outcome(refused) == (
        500,
        {"detail": f"OpenID Connect SSO requires HTTPS addresses: {named}"},
    )
    with SessionLocal() as db:
        assert db.query(OidcLoginState).count() == 0
    # The sign-in page does not offer a provider that cannot be used.
    assert browser().get("/v1/auth/methods").json()["sso_providers"] == []


def test_a_provider_on_this_machine_may_use_plain_http_for_testing(monkeypatch):
    monkeypatch.setattr(settings, "oidc_token_endpoint", "http://localhost:8081/token")
    monkeypatch.setattr(settings, "oidc_jwks_uri", "http://127.0.0.1:8081/jwks")
    assert (
        browser().get("/v1/auth/sso/oidc/start", follow_redirects=False).status_code
        == 302
    )


# -- the allowance on starts -----------------------------------------------------------


def test_each_address_starts_a_bounded_number_of_sign_ins():
    """Each start stores a row, so an address is allowed so many in a window
    and the rest are refused without storing anything."""
    c = browser("9.9.8.1")
    answers = [
        c.get("/v1/auth/sso/oidc/start", follow_redirects=False).status_code
        for _ in range(auth_routes.SSO_STARTS_PER_ADDRESS + 5)
    ]
    assert answers == [302] * auth_routes.SSO_STARTS_PER_ADDRESS + [429] * 5
    with SessionLocal() as db:
        assert db.query(OidcLoginState).count() == auth_routes.SSO_STARTS_PER_ADDRESS
    # Another address is unaffected.
    assert (
        browser("9.9.8.2")
        .get("/v1/auth/sso/oidc/start", follow_redirects=False)
        .status_code
        == 302
    )


# -- the provider's key rotation ---------------------------------------------------------


class _KeySets:
    """The provider's key-set address: serves ``keys`` and counts its reads."""

    def __init__(self, keys):
        self.keys = keys
        self.reads = 0

    def client(self, **_kwargs):
        sets = self

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

            async def get(self, _uri):
                sets.reads += 1
                return oidc.httpx.Response(
                    200,
                    json={"keys": sets.keys},
                    request=oidc.httpx.Request("GET", _uri),
                )

        return Client()


@pytest.fixture()
def key_sets(monkeypatch):
    sets = _KeySets([JWK])
    monkeypatch.undo()  # the real key-set reader, with only its transport replaced
    for name, value in {
        "oidc_sso_enabled": True,
        "oidc_client_id": "client",
        "oidc_client_secret": "secret",
        "oidc_authorization_endpoint": ISSUER + "/auth",
        "oidc_token_endpoint": ISSUER + "/token",
        "oidc_redirect_uri": "https://testserver/v1/auth/sso/oidc/callback",
        "oidc_jwks_uri": ISSUER + "/jwks",
        "oidc_issuer": ISSUER,
    }.items():
        monkeypatch.setattr(settings, name, value)
    monkeypatch.setattr(oidc.httpx, "AsyncClient", sets.client)
    oidc._JWKS_CACHE.clear()
    yield sets
    oidc._JWKS_CACHE.clear()


def _complete(monkeypatch, **token) -> int:
    c = browser()
    state, nonce, _ = start(c)
    return callback(c, state, signed(nonce, **token), monkeypatch).status_code


def test_a_rotated_provider_key_is_read_without_waiting_for_the_cache(
    key_sets, monkeypatch
):
    linked()
    assert _complete(monkeypatch) == 302
    assert _complete(monkeypatch) == 302
    assert key_sets.reads == 1

    # The provider starts signing with a new key. Inside the first minute the
    # cached set is still trusted, so the sign-in is refused without a read.
    key_sets.keys = [OTHER_JWK]
    assert _complete(monkeypatch, key=OTHER_PRIVATE, kid="k2") == 400
    assert key_sets.reads == 1

    # Once the cached set is a minute old, an unknown key is worth one read.
    cached, expires = oidc._JWKS_CACHE[ISSUER + "/jwks"]
    oidc._JWKS_CACHE[ISSUER + "/jwks"] = (cached, expires - timedelta(minutes=2))
    assert _complete(monkeypatch, key=OTHER_PRIVATE, kid="k2") == 302
    assert key_sets.reads == 2


def test_tokens_naming_unknown_keys_cannot_make_the_key_set_be_read_each_time(
    key_sets, monkeypatch
):
    linked()
    assert _complete(monkeypatch) == 302
    cached, expires = oidc._JWKS_CACHE[ISSUER + "/jwks"]
    oidc._JWKS_CACHE[ISSUER + "/jwks"] = (cached, expires - timedelta(minutes=2))
    for attempt in range(5):
        assert (
            _complete(monkeypatch, key=OTHER_PRIVATE, kid=f"unknown-{attempt}") == 400
        )
    # One re-read for the first unknown key; the fresh set then stands a minute.
    assert key_sets.reads == 2
