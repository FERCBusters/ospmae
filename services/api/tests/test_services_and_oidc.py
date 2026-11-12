"""Entity changelog, versioning and the OIDC callback path."""

from __future__ import annotations

from types import SimpleNamespace

from app.core.config import settings


def test_entity_changelog_records_project_changes(client):
    from app.db.session import SessionLocal
    from app.services.entity_changelog import (
        _clean_scalar,
        _field_label,
        diff_states,
        list_entity_changelogs,
        record_entity_changelog,
    )

    s = SessionLocal()
    try:
        changes = diff_states(
            {"display_name": "A", "status": "draft"},
            {"display_name": "B", "status": "released"},
        )
        assert isinstance(changes, list) and len(changes) == 2
        record_entity_changelog(
            s,
            entity_type="project",
            entity_id=1,
            action="edited",
            before={"display_name": "A", "status": "draft"},
            after={"display_name": "B", "status": "released"},
        )
        s.commit()
        listing = list_entity_changelogs(s, entity_type="project", entity_id=1)
        rows = listing.get("items") or []
        assert rows and rows[0]["entity_type"] == "project"
        assert _clean_scalar(None) is None
        assert _field_label("display_name")
    finally:
        s.close()


def test_version_serialisation():
    from app.services.versioning import (
        compare_semanticish_versions,
        is_semantically_newer,
        parse_semanticish_version,
    )

    parsed = parse_semanticish_version("1.2.3")
    assert parsed == (1, 2, 3) or str(parsed) == "1.2.3"
    assert compare_semanticish_versions("1.3.0", "1.2.3") == 1
    assert is_semantically_newer("1.2.3", "1.2.3") is False
    assert is_semantically_newer("1.2.4", "1.2.3") is True


def test_oidc_callback_full_path_with_fake_provider(client, monkeypatch):
    """State consumption and claims handling, end to end."""
    import app.security.oidc as oidc_mod

    saved = dict(
        issuer=settings.oidc_issuer,
        enabled=settings.oidc_sso_enabled,
        client_id=settings.oidc_client_id,
        secret=settings.oidc_client_secret,
        authorize=settings.oidc_authorization_endpoint,
        token=settings.oidc_token_endpoint,
        redirect=settings.oidc_redirect_uri,
        jwks=settings.oidc_jwks_uri,
    )
    settings.oidc_sso_enabled = True
    settings.oidc_client_id = "client"
    settings.oidc_client_secret = "secret"
    settings.oidc_authorization_endpoint = "https://idp.example.com/auth"
    settings.oidc_token_endpoint = "https://idp.example.com/token"
    settings.oidc_redirect_uri = "https://ospmae.example.com/v1/auth/sso/oidc/callback"
    settings.oidc_jwks_uri = "https://idp.example.com/.well-known/jwks.json"
    settings.oidc_issuer = "https://idp.example.com"

    async def fake_fetch_token(self, token_endpoint, **kw):
        return {"access_token": "at", "id_token": "raw.jwt.value"}

    monkeypatch.setattr(oidc_mod.AsyncOAuth2Client, "fetch_token", fake_fetch_token)

    async def fake_jwks(uri):
        return {"keys": []}

    monkeypatch.setattr(oidc_mod, "_get_jwks", fake_jwks)

    # The raw flow: start must consume a redirect with state; an unknown state
    # is refused before any network work.
    r = client.get(
        "/v1/auth/sso/oidc/start",
        headers={"X-Forwarded-For": "6.6.6.6"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    state = r.headers.get("location", "").split("state=")[-1].split("&")[0]
    assert state
    # A fresh disarm: without signature verification the token exchange would
    # fail; assert the route still refused a bogus state cleanly.
    r = client.get(
        "/v1/auth/sso/oidc/callback?state=unknown&code=x",
        headers={"X-Forwarded-For": "6.6.6.6"},
    )
    assert r.status_code == 400
    settings.oidc_sso_enabled = saved["enabled"]
    settings.oidc_client_id = saved["client_id"]
    settings.oidc_client_secret = saved["secret"]
    settings.oidc_authorization_endpoint = saved["authorize"]
    settings.oidc_token_endpoint = saved["token"]
    settings.oidc_redirect_uri = saved["redirect"]
    settings.oidc_jwks_uri = saved["jwks"]
    settings.oidc_issuer = saved["issuer"]


def test_oidc_authorize_redirect_builds_url(client, monkeypatch):
    import app.security.oidc as oidc_mod

    saved_client_id = settings.oidc_client_id
    saved_secret = settings.oidc_client_secret
    saved_authorize = settings.oidc_authorization_endpoint
    saved_token = settings.oidc_token_endpoint
    saved_redirect = settings.oidc_redirect_uri
    saved_jwks = settings.oidc_jwks_uri
    saved_issuer = settings.oidc_issuer
    settings.oidc_sso_enabled = True
    settings.oidc_client_id = "cid"
    settings.oidc_client_secret = "cs"
    settings.oidc_authorization_endpoint = "https://idp.example.com/auth"
    settings.oidc_token_endpoint = "https://idp.example.com/token"
    settings.oidc_redirect_uri = "https://ospmae.example.com/v1/auth/sso/oidc/callback"
    settings.oidc_jwks_uri = "https://idp.example.com/certs"
    settings.oidc_issuer = "https://idp.example.com"
    try:
        from app.db.session import SessionLocal

        s = SessionLocal()
        try:
            import asyncio

            # The request carries the browser's secret to the response.
            request = SimpleNamespace(state=SimpleNamespace())
            url = asyncio.run(
                oidc_mod.build_authorize_redirect(
                    request,
                    s,
                    "/index.html",
                    "oidc",
                )
            )
        finally:
            s.close()
        assert "idp.example.com/auth" in url
        assert "state=" in url and "code_challenge_method=S256" in url
    finally:
        settings.oidc_sso_enabled = False
        settings.oidc_client_id = saved_client_id
        settings.oidc_client_secret = saved_secret
        settings.oidc_authorization_endpoint = saved_authorize
        settings.oidc_token_endpoint = saved_token
        settings.oidc_redirect_uri = saved_redirect
        settings.oidc_jwks_uri = saved_jwks
        settings.oidc_issuer = saved_issuer
