"""The signed-in account's own records: its profile, mail, groups,
preferences and shortcuts."""

from __future__ import annotations

from app.db.models import Notification
from app.db.session import SessionLocal

from tests.support import csrf, make_group, ok, signed_in


def test_the_profile_names_permissions_and_how_to_sign_out():
    normal, _ = signed_in("contributor")
    profile = ok(normal.get("/v1/me"))
    assert profile["permissions"] == [
        "project.answer",
        "project.diff",
    ]
    assert (profile["auth_method"], profile["logout_url"]) == (
        "local",
        "/api/v1/auth/logout",
    )
    assert profile["logout_redirect"] == "/login.html"
    # An administrator holds every permission.
    admin, _ = signed_in("admin")
    assert ok(admin.get("/v1/me"))["permissions"] == ["*"]


def test_signing_out_through_the_profiles_address_ends_the_session():
    client, _ = signed_in("viewer")
    url = ok(client.get("/v1/me"))["logout_url"]
    # The browser's address, under nginx's /api/; the API serves /v1/.
    assert url.startswith("/api/")
    response = client.post(url.removeprefix("/api"), json={}, headers=csrf(client))
    assert response.status_code == 204
    assert client.get("/v1/me").status_code == 401


def test_the_account_sees_its_own_mail_and_groups_only():
    client, user_id = signed_in("viewer")
    _, other_id = signed_in("viewer")
    with SessionLocal() as db:
        for owner, subject in ((user_id, "Mine"), (other_id, "Theirs")):
            db.add(
                Notification(
                    user_id=owner, recipient="x@x.test", subject=subject, body=""
                )
            )
        db.commit()
    mail = ok(client.get("/v1/me/notifications", params={"limit": 5}))
    assert [row["subject"] for row in mail] == ["Mine"]
    assert "body" not in mail[0]

    make_group("Reviewers", role="normal", members=[user_id])
    make_group("Others", role="normal", members=[other_id])
    assert [g["name"] for g in ok(client.get("/v1/me/groups"))["items"]] == [
        "Reviewers"
    ]


def test_node_colours_keep_only_valid_entries_in_either_form():
    client, _ = signed_in("viewer")
    saved = ok(
        client.put(
            "/v1/me/preferences",
            json={
                "node_colors": {
                    "uwra:channel_tier": "#AABBCC",
                    "legacy_node": "112233",
                    "frameworks:": "#000000",
                    "bad:colour": "#12345",
                    "worse:colour": "#gggggg",
                    "empty:colour": None,
                    "": "#ffffff",
                    "nested": {"one": "#010203", "": "#ffffff", "two": "nope"},
                    "  ": {"x": "#010203"},
                    "number": 7,
                },
                "sticky_enabled": True,
                "auto_apply_enabled": False,
            },
            headers=csrf(client),
        )
    )
    assert saved["node_colors"] == {
        "uwra:channel_tier": "#aabbcc",
        "uwra:legacy_node": "#112233",
        "nested:one": "#010203",
    }
    assert (saved["sticky_enabled"], saved["auto_apply_enabled"]) == (True, False)
    assert ok(client.get("/v1/me/preferences"))["node_colors"] == saved["node_colors"]


def test_a_start_page_outside_the_accounts_reach_falls_back_to_the_index():
    client, _ = signed_in("viewer")
    for asked, kept in (
        ("admin.html", "/index.html"),
        ("manifests.html", "/manifests.html"),
        # Framework management needs framework.write, which a viewer lacks.
        ("/framework-manage.html", "/index.html"),
        ("/preferences.html", "/account.html"),
        ("", "/index.html"),
    ):
        saved = ok(
            client.put(
                "/v1/me/preferences",
                json={"default_start_page": asked},
                headers=csrf(client),
            )
        )
        assert saved["default_start_page"] == kept, asked
    admin, _ = signed_in("admin")
    saved = ok(
        admin.put(
            "/v1/me/preferences",
            json={"default_start_page": "/admin.html"},
            headers=csrf(admin),
        )
    )
    assert saved["default_start_page"] == "/admin.html"


SCHEME = "url must not contain a scheme"
ELSEWHERE = "url must be a same-origin path"


def test_a_shortcut_of_the_same_name_is_replaced_and_removed_by_its_owner():
    client, _ = signed_in("viewer")
    other, _ = signed_in("viewer")
    first = ok(
        client.post(
            "/v1/me/shortcuts",
            json={"name": "Mine", "url": "/index.html?q=a"},
            headers=csrf(client),
        )
    )
    assert first["url"] == "/index.html?q=a"
    second = ok(
        client.post(
            "/v1/me/shortcuts",
            json={"name": "Mine", "url": "/manifests.html"},
            headers=csrf(client),
        )
    )
    assert (second["id"], second["url"]) == (first["id"], "/manifests.html")
    assert [s["url"] for s in ok(client.get("/v1/me/shortcuts"))] == ["/manifests.html"]

    for body, detail in (
        ({"name": " ", "url": "/x"}, "name is required"),
        ({"name": "Scheme", "url": "/javascript:alert(1)"}, SCHEME),
        ({"name": "Away", "url": "https://example.org/"}, ELSEWHERE),
        ({"name": "Empty", "url": " "}, None),
    ):
        refused = client.post("/v1/me/shortcuts", json=body, headers=csrf(client))
        assert refused.status_code in (400, 422), body
        if detail:
            assert refused.json() == {"detail": detail}

    url = f"/v1/me/shortcuts/{first['id']}"
    assert other.delete(url, headers=csrf(other)).status_code == 404
    assert ok(client.delete(url, headers=csrf(client))) == {"ok": True}
    assert client.delete(url, headers=csrf(client)).status_code == 404
