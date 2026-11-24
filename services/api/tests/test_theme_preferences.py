"""Theme preference: account-scoped palette selection on /v1/me/preferences."""

from __future__ import annotations

import pytest

from tests.conftest import auth_client, login, make_user


def _signed_in(client, username: str, role: str = "viewer"):
    make_user(username, "Test-passphrase-1!", role=role)
    r = login(client, username, "Test-passphrase-1!")
    assert r.status_code == 200
    return client.cookies.get("__Host-ospmae_csrf") or ""


def test_me_payload_names_available_themes(client):
    make_user("ThemeMe", "Test-passphrase-1!", role="viewer")
    login(client, "ThemeMe", "Test-passphrase-1!")
    body = client.get("/v1/me").json()
    themes = body.get("available_themes")
    assert themes and themes[0] == {"id": "ink", "name": "Ink"}
    ids = {t["id"] for t in themes}
    assert "ocean" in ids and "ink-dark" in ids


def test_theme_preference_round_trip(client):
    csrf = _signed_in(client, "ThemeRT")
    r = client.put(
        "/v1/me/preferences",
        json={"theme": "forest"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
    assert r.json()["theme"] == "forest"

    r = client.get("/v1/me/preferences")
    assert r.json()["theme"] == "forest"


def test_unknown_theme_is_refused(client):
    csrf = _signed_in(client, "ThemeBad")
    r = client.put(
        "/v1/me/preferences",
        json={"theme": "ultraviolet"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400


def test_theme_defaults_to_the_application_palette(client):
    csrf = _signed_in(client, "ThemeDef")
    r = client.put(
        "/v1/me/preferences",
        json={"sticky_enabled": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
    assert r.json()["theme"] == "ink"

    # An empty value keeps the default rather than blanking the attribute.
    r = client.put(
        "/v1/me/preferences",
        json={"theme": ""},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
    assert r.json()["theme"] == "ink"


@pytest.mark.parametrize(
    ("role", "extra"),
    [
        ("viewer", set()),
        ("framework_admin", {"/framework-manage.html"}),
        ("admin", {"/framework-manage.html", "/admin.html"}),
    ],
)
def test_start_pages_follow_the_page_layout(role, extra):
    """The catalogue, manifests and account pages are everyone's start
    pages; framework management needs framework.write and the admin page the
    admin role. Anything else becomes the catalogue instead of a dead link."""
    client, _ = auth_client(username=f"start-{role}", role=role)
    csrf = client.cookies.get("__Host-ospmae_csrf") or ""

    def _save(page):
        r = client.put(
            "/v1/me/preferences",
            json={"default_start_page": page},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        return r.json()["default_start_page"]

    everyone = {"/index.html", "/manifests.html", "/account.html"}
    for page in everyone | extra:
        assert _save(page) == page
    for refused in ({"/framework-manage.html", "/admin.html"} - extra) | {
        "/dependencies.html",
        "/login.html",
        "//evil.example/",
        "javascript:alert(1)",
    }:
        assert _save(refused) == "/index.html", refused
