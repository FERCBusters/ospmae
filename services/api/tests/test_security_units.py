"""Unit sweep over the security helpers that are not route-bound."""

from __future__ import annotations

import pytest
from app.core.config import settings
from app.db.session import SessionLocal
from app.security.client_addr import allowance_address, public_client_address
from app.security.oidc import (
    _allowed_by_domain,
    _canonical_issuer,
    _claim_email,
    _email_is_verified,
    _normalize_next,
    _split_csv,
    create_login_state,
    get_sso_provider,
    pop_login_state,
)
from app.security.roles import attach_effective_role, canonicalize_role
from app.security.url_safety import (
    _is_private_ip,
    _resolve_host_ips,
    validate_public_http_url,
    validate_safe_href,
)

from tests.conftest import db as db_fixture  # noqa: F401


def test_split_csv():
    assert _split_csv("a, b,,c") == ["a", "b", "c"]
    assert _split_csv("") == []


def test_canonical_issuer_picks_first_of_csv():
    from app.security.oidc import SsoProvider

    p = SsoProvider(
        key="oidc",
        kind="oidc",
        label="x",
        enabled=True,
        client_id="c",
        client_secret="s",
        authorization_endpoint="a",
        token_endpoint="t",
        issuer="https://a.example,https://b.example",
        scopes="openid",
    )
    assert _canonical_issuer(p) == "https://a.example"


def test_claim_email_and_verified_flags():
    assert _claim_email({"email": " A@b.example "}) == "a@b.example"
    # A claimed address is one mailbox or nothing.
    assert _claim_email({"email": "a@b.example, c@d.example"}) is None
    oidc = type("P", (), {"key": "oidc"})()
    assert _email_is_verified(oidc, {"email_verified": True})
    assert not _email_is_verified(oidc, {"email_verified": False})
    # As in KEEN, only a JSON true verifies; GitHub's callback synthesises
    # one from /user/emails, so a bare email or a string never does.
    assert not _email_is_verified(oidc, {"email_verified": "true"})
    github = type("P", (), {"key": "github"})()
    assert not _email_is_verified(github, {"email": "a@b.example"})


def test_allowed_by_domain_needs_a_verified_address_in_the_list():
    provider = type("P", (), {"allowed_email_domains": "corp.example"})()
    verified = {"email_verified": True}
    assert _allowed_by_domain(provider, {"email": "u@corp.example", **verified})
    assert not _allowed_by_domain(
        provider, {"email": "u@evil-corp.example", **verified}
    )
    assert not _allowed_by_domain(provider, {"email": "u@corp.example"})
    assert not _allowed_by_domain(provider, {})
    anyone = type("P", (), {"allowed_email_domains": ""})()
    assert _allowed_by_domain(anyone, {})


def test_normalize_next_helper():
    assert _normalize_next("/x") == "/x"
    assert _normalize_next("/\\evil") is None
    assert _normalize_next(None) is None


def test_pop_login_state_single_use(db):
    s = SessionLocal()
    try:
        row = create_login_state(s, next_url="/index.html", state="s" * 64)
        first = pop_login_state(s, state=row.state)
        assert first is not None
        assert pop_login_state(s, state=row.state) is None
        assert pop_login_state(s, state="") is None
    finally:
        s.close()


def test_expired_login_state_refused(db):
    from datetime import datetime, timedelta

    from app.db.models import OidcLoginState

    s = SessionLocal()
    try:
        row = OidcLoginState(
            state="stale-state",
            nonce="n",
            code_verifier="v",
            expires_at=datetime.utcnow() - timedelta(minutes=1),
        )
        s.add(row)
        s.commit()
        assert pop_login_state(s, state="stale-state") is None
        assert s.query(OidcLoginState).count() == 0
    finally:
        s.close()


def test_provider_lookup():
    assert get_sso_provider("github").key == "github"
    assert get_sso_provider("nope") is None
    assert get_sso_provider(None).key == "oidc"


def test_roles_and_canonicalization(db):
    from app.security.roles import ROLE_ADMIN, ROLE_VIEWER

    s = SessionLocal()
    try:
        from app.security.auth import create_user

        u = create_user(
            s, username="RoleU", password="Test-passphrase-1!", role="admin"
        )
        assert attach_effective_role(s, u) == ROLE_ADMIN
        u.role = "inherit"
        assert attach_effective_role(s, u) == ROLE_VIEWER
        assert canonicalize_role("MAINTAINER") == "maintainer"
        assert canonicalize_role("bogus") is None
    finally:
        s.close()


def test_validate_safe_href_blocklist():
    validate_safe_href("https://example.com")
    validate_safe_href("/relative/path")
    with pytest.raises(ValueError):
        validate_safe_href("javascript:alert(1)")
    with pytest.raises(ValueError):
        validate_safe_href("//evil.example")
    with pytest.raises(ValueError):
        validate_safe_href("ftp://example.com")
    with pytest.raises(ValueError):
        validate_safe_href("https://a:b@example.com")
    with pytest.raises(ValueError):
        validate_safe_href("x" * 2049)
    assert validate_safe_href("") == ""


def test_validate_public_http_url_blocks_private():
    validate_public_http_url("https://example.com/x")
    with pytest.raises(ValueError):
        validate_public_http_url("http://localhost:8080")
    with pytest.raises(ValueError):
        validate_public_http_url("http://127.0.0.1")
    with pytest.raises(ValueError):
        validate_public_http_url("http://10.1.2.3")


def test_private_ip_check():
    assert _is_private_ip("10.0.0.1")
    assert _is_private_ip("::1")
    assert not _is_private_ip("8.8.8.8")
    with pytest.raises(ValueError):
        _resolve_host_ips("nonexistent-host-ospmae.invalid")


def test_client_addr_walk():
    default = "127.0.0.1,::1"
    settings.trusted_proxy_cidrs = default
    try:
        # Untrusted peer: header ignored entirely.
        assert public_client_address("203.0.113.5", "8.8.8.8") == "203.0.113.5"
        # Trusted peer consumes the rightmost entry only.
        assert public_client_address("127.0.0.1", "5.5.5.5, 8.8.8.8") == "8.8.8.8"
        # Unparseable hop stops the walk at the last trusted hop.
        assert public_client_address("127.0.0.1", "5.5.5.5, not-an-ip") == "127.0.0.1"
        # Direct connection: exactly the socket peer, never the header.
        assert public_client_address("127.0.0.1", None) == "127.0.0.1"
    finally:
        settings.trusted_proxy_cidrs = default


def test_allowance_address_v6():
    assert allowance_address("2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff") == (
        "2001:db8:aaaa:bbbb::/64"
    )
    assert allowance_address("8.8.8.8") == "8.8.8.8"
    assert allowance_address("::ffff:8.8.8.8") == "8.8.8.8"
    assert allowance_address(None) is None
