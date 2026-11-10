"""Theme preference: account-scoped palette selection on /v1/me/preferences."""

from __future__ import annotations

from tests.conftest import login, make_user


def _signed_in(client, username: str, role: str = "viewer"):
    make_user(username, "Password1!", role=role)
    r = login(client, username, "Password1!")
    assert r.status_code == 200
    return client.cookies.get("ospmae_csrf") or ""


def test_me_payload_names_available_themes(client):
    make_user("ThemeMe", "Password1!", role="viewer")
    login(client, "ThemeMe", "Password1!")
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
