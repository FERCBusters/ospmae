"""Single sign-on reaches existing accounts only, as in KEEN.

A linked identity signs in to its account while the provider's verified
email stays in the allowed domains; a new identity links to the one active
account that has proved, by mailbox, the address the provider reports as
verified. No sign-in creates an account, and no trusted header does either.
"""

from __future__ import annotations

import pytest
from app.core.config import settings
from app.db.models import AuditLog, User, UserIdentity, UserSsoEmail
from app.db.session import SessionLocal
from app.security import oidc
from fastapi import HTTPException
from fastapi.testclient import TestClient

from tests.conftest import make_user, peer_wrapper


def _provider(**overrides) -> oidc.SsoProvider:
    fields = dict(
        key="oidc",
        kind="oidc",
        label="Company SSO",
        enabled=True,
        client_id="client",
        client_secret="secret",
        authorization_endpoint="https://idp.x.test/auth",
        token_endpoint="https://idp.x.test/token",
        scopes="openid email",
        issuer="https://idp.x.test",
    )
    fields.update(overrides)
    return oidc.SsoProvider(**fields)


def _claims(email: str = "person@corp.test", verified: bool = True) -> dict:
    return {"email": email, "email_verified": verified, "preferred_username": "admin"}


def _sign_in(provider, subject: str = "subject-1", claims: dict | None = None):
    with SessionLocal() as s:
        user = oidc._get_or_create_user_for_identity(
            s, provider=provider, subject=subject, claims=claims or _claims()
        )
        return user.username


def _with_linking_address(username: str, email: str = "person@corp.test") -> User:
    user = make_user(username, "Linked-pass-1!", role="viewer")
    with SessionLocal() as s:
        s.add(UserSsoEmail(email=email, user_id=user.id))
        s.commit()
    return user


def test_a_proved_address_links_the_identity_once(client):
    _with_linking_address("person")

    assert _sign_in(_provider()) == "person"
    with SessionLocal() as s:
        [identity] = s.query(UserIdentity).all()
        assert identity.email == "person@corp.test"
    # Later sign-ins use the link, whatever the address does next.
    with SessionLocal() as s:
        s.query(UserSsoEmail).delete()
        s.commit()
    assert _sign_in(_provider()) == "person"


@pytest.mark.parametrize(
    "claims, detail",
    [
        # The provider must call the address verified.
        (_claims(verified=False), "No active OSPMAE account matches"),
        # A username claim never links, even one naming an account.
        ({"preferred_username": "person"}, "No active OSPMAE account matches"),
    ],
)
def test_linking_needs_both_proofs(client, claims, detail):
    _with_linking_address("person")
    with pytest.raises(HTTPException) as refused:
        _sign_in(_provider(), claims=claims)
    assert refused.value.status_code == 403
    assert detail in refused.value.detail


def test_the_account_email_alone_does_not_link(client):
    """Only addresses proved by mailbox link; an administrator-set account
    email does not, as in KEEN."""
    make_user("emailed", "Emailed-pass-1!", role="viewer", email="person@corp.test")
    with pytest.raises(HTTPException) as refused:
        _sign_in(_provider())
    assert "No active OSPMAE account matches" in refused.value.detail


def test_no_sign_in_creates_an_account(client):
    with pytest.raises(HTTPException) as refused:
        _sign_in(_provider(), claims=_claims("stranger@corp.test"))
    assert refused.value.status_code == 403
    with SessionLocal() as s:
        assert s.query(User).count() == 0
        assert s.query(UserIdentity).count() == 0


def test_an_inactive_account_does_not_link(client):
    user = _with_linking_address("dormant")
    with SessionLocal() as s:
        s.get(User, user.id).is_active = False
        s.commit()
    with pytest.raises(HTTPException) as refused:
        _sign_in(_provider())
    assert "No active OSPMAE account matches" in refused.value.detail


def test_linking_can_be_switched_off(client):
    _with_linking_address("person")
    with pytest.raises(HTTPException) as refused:
        _sign_in(_provider(auto_link_existing=False))
    assert refused.value.detail == "No local account linked to this identity"


def test_allowed_domains_govern_every_sign_in(client):
    _with_linking_address("person")
    provider = _provider(allowed_email_domains="corp.test")
    assert _sign_in(provider) == "person"

    # The linked identity stops signing in once its address leaves the list,
    # and the refusal names the account it reached.
    with pytest.raises(oidc.LinkedAccountRefused) as refused:
        _sign_in(provider, claims=_claims("person@elsewhere.test"))
    assert refused.value.detail == "Email domain is not allowed"
    assert oidc.linked_account(refused.value).username == "person"
    # An unverified address in the list is no better.
    with pytest.raises(oidc.LinkedAccountRefused):
        _sign_in(provider, claims=_claims(verified=False))


def test_a_deactivated_linked_account_is_refused(client):
    user = _with_linking_address("person")
    _sign_in(_provider())
    with SessionLocal() as s:
        s.get(User, user.id).is_active = False
        s.commit()
    with pytest.raises(oidc.LinkedAccountRefused) as refused:
        _sign_in(_provider())
    assert refused.value.detail == "User is inactive"


def test_a_refused_sso_sign_in_is_audited_against_its_account(client, monkeypatch):
    import app.api.routes.auth as auth_routes

    user = make_user("refused-person", "Refused-pass-1!", role="viewer")

    async def refuse(request, db, *, provider_key):
        request.state.sso_provider = provider_key
        raise oidc.LinkedAccountRefused(
            db.get(User, user.id), "Email domain is not allowed"
        )

    monkeypatch.setattr(auth_routes, "handle_callback", refuse)
    response = client.get("/v1/auth/sso/oidc/callback?state=s&code=c")
    assert response.status_code == 403
    with SessionLocal() as s:
        [row] = s.query(AuditLog).filter_by(path="/action/sign-in").all()
    assert row.username == "refused-person"
    assert row.query_string == "method=oidc&outcome=failed"


def test_a_trusted_header_names_an_existing_account_only(monkeypatch):
    from app.main import app

    monkeypatch.setattr(settings, "trust_remote_user", True)
    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    c.headers.update({"X-Test-Peer": "127.0.0.1", "REMOTE_USER": "newcomer"})

    assert c.get("/v1/me").status_code == 401
    with SessionLocal() as s:
        assert s.query(User).count() == 0

    make_user("newcomer", "Newcomer-pass-1!", role="viewer")
    assert c.get("/v1/me").json()["username"] == "newcomer"
