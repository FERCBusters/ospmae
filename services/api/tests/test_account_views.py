"""What an account sees and keeps for itself: preferences, shortcuts, groups,
subscriptions and its mail history."""

from __future__ import annotations

import pytest
from app.api.routes import me
from app.db.models import UserPreference, UserShortcut
from app.db.session import SessionLocal
from fastapi import HTTPException
from starlette.requests import Request

from tests.support import csrf, make_group, make_project, ok, signed_in


def test_preferences_default_then_keep_what_is_valid():
    client, user_id = signed_in("viewer")
    assert ok(client.get("/v1/me/preferences")) == {
        "theme": "ink",
        "node_colors": {},
        "default_start_page": "/index.html",
        "sticky_enabled": False,
        "auto_apply_enabled": True,
    }

    saved = ok(
        client.put(
            "/v1/me/preferences",
            json={
                "node_colors": {
                    "tax:wallet": "#AABBCC",
                    "channel_tier": "112233",  # no framework prefix: assumed UWRA
                    "tax:bad": "red",
                    "tax:short": "#abc",
                    "tax:none": None,
                    " ": "#000000",
                    ":nokey": "#000000",
                    "Other": {"issuer": "#00ff00", "": "#111111", "x": "nope"},
                    "": {"y": "#222222"},
                    "list": ["#333333"],
                },
                "default_start_page": "manifests.html",
                "sticky_enabled": True,
                "auto_apply_enabled": False,
                "theme": "ocean-dark",
            },
            headers=csrf(client),
        )
    )
    assert saved == {
        "theme": "ocean-dark",
        "node_colors": {
            "tax:wallet": "#aabbcc",
            "uwra:channel_tier": "#112233",
            "other:issuer": "#00ff00",
        },
        "default_start_page": "/manifests.html",
        "sticky_enabled": True,
        "auto_apply_enabled": False,
    }
    assert ok(client.get("/v1/me/preferences")) == saved
    assert ok(client.get("/v1/me"))["preferences"]["theme"] == "ocean-dark"

    # A partial update leaves the rest; an empty theme returns to the default.
    partial = ok(
        client.put("/v1/me/preferences", json={"theme": ""}, headers=csrf(client))
    )
    assert (partial["theme"], partial["sticky_enabled"]) == ("ink", True)
    refused = client.put(
        "/v1/me/preferences", json={"theme": "neon"}, headers=csrf(client)
    )
    assert refused.status_code == 400
    with SessionLocal() as s:
        assert s.query(UserPreference).filter_by(user_id=user_id).one().theme == ""


def test_the_start_page_is_limited_to_pages_the_role_can_open():
    viewer, _ = signed_in("viewer")
    admin, _ = signed_in("admin")
    fw_admin, _ = signed_in("framework_admin")

    def start(client, page):
        body = ok(
            client.put(
                "/v1/me/preferences",
                json={"default_start_page": page},
                headers=csrf(client),
            )
        )
        return body["default_start_page"]

    assert start(viewer, "/admin.html") == "/index.html"
    assert start(viewer, "/framework-manage.html") == "/index.html"
    assert start(viewer, "https://evil.example/") == "/index.html"
    assert start(viewer, "/preferences.html") == "/account.html"  # the page's old name
    assert start(viewer, "") == "/index.html"
    assert start(admin, "/admin.html") == "/admin.html"
    assert start(fw_admin, "/framework-manage.html") == "/framework-manage.html"
    assert start(fw_admin, "/admin.html") == "/index.html"

    # A stored page the account has since lost access to is not served back.
    with SessionLocal() as s:
        s.query(UserPreference).update(
            {UserPreference.default_start_page: "/admin.html"}
        )
        s.commit()
    assert ok(viewer.get("/v1/me/preferences"))["default_start_page"] == "/index.html"
    assert ok(admin.get("/v1/me/preferences"))["default_start_page"] == "/admin.html"


def test_shortcuts_are_same_origin_named_and_private():
    client, user_id = signed_in("viewer")
    other, _ = signed_in("viewer")

    def save(c, **body):
        return c.post("/v1/me/shortcuts", json=body, headers=csrf(c))

    first = ok(save(client, name=" Wallets ", url=" /manifests.html?q=wallet "))
    assert (first["name"], first["url"]) == ("Wallets", "/manifests.html?q=wallet")
    # Saving the same name again replaces the address.
    again = ok(save(client, name="Wallets", url="/index.html"))
    assert (again["id"], again["url"]) == (first["id"], "/index.html")
    second = ok(save(client, name="Second", url="/account.html"))
    assert [s["name"] for s in ok(client.get("/v1/me/shortcuts"))] == [
        "Second",
        "Wallets",
    ]
    assert ok(other.get("/v1/me/shortcuts")) == []

    for url in (
        "",
        "//evil.example/x",
        "https://evil.example/x",
        "/a\\b",
        "/a\nb",
        "javascript:alert(1)",
        "/" + "a" * 4001,
    ):
        assert save(client, name="bad", url=url).status_code in (400, 422), url
    assert save(client, name="   ", url="/index.html").status_code in (400, 422)
    assert save(client, name="n" * 201, url="/index.html").status_code in (400, 422)
    with SessionLocal() as s:
        assert s.query(UserShortcut).filter_by(user_id=user_id).count() == 2

    # Another account cannot remove it.
    assert (
        other.delete(
            f"/v1/me/shortcuts/{second['id']}", headers=csrf(other)
        ).status_code
        == 404
    )
    assert ok(
        client.delete(f"/v1/me/shortcuts/{second['id']}", headers=csrf(client))
    ) == {"ok": True}
    assert (
        client.delete(
            f"/v1/me/shortcuts/{second['id']}", headers=csrf(client)
        ).status_code
        == 404
    )


def test_an_account_lists_its_groups_subscriptions_and_mail(outbox):
    admin, _ = signed_in("admin")
    reader, reader_id = signed_in("viewer", email="reader@x.test")
    make_group("Zebra", members=[reader_id])
    make_group("Alpha", members=[reader_id])
    make_group("Elsewhere")
    assert [g["name"] for g in ok(reader.get("/v1/me/groups"))["items"]] == [
        "Alpha",
        "Zebra",
    ]

    assert ok(reader.get("/v1/me/subscriptions")) == {"items": []}
    beta = make_project(admin, "beta", organisation="Acme", project_type="library")
    alpha = make_project(admin, "alpha")
    ok(reader.post(f"/v1/projects/{beta['id']}/subscription", headers=csrf(reader)))
    ok(
        reader.post(
            f"/v1/projects/{alpha['id']}/subscription",
            json={"notify_new_versions": False, "notify_questions": True},
            headers=csrf(reader),
        )
    )
    assert ok(reader.get("/v1/me/subscriptions"))["items"] == [
        {
            "project_id": alpha["id"],
            "project_name": "Alpha",
            "project_machine_name": "alpha",
            "organisation": None,
            "project_type": None,
            "notify_new_versions": False,
            "notify_questions": True,
        },
        {
            "project_id": beta["id"],
            "project_name": "Beta",
            "project_machine_name": "beta",
            "organisation": "Acme",
            "project_type": "library",
            "notify_new_versions": True,
            "notify_questions": False,
        },
    ]


def test_an_account_sees_what_was_mailed_to_it_without_the_bodies(outbox):
    owner, owner_id = signed_in("architect")
    peer, peer_id = signed_in("architect", email="peer@x.test")
    team = make_group("Team", members=[owner_id, peer_id])
    saved = ok(
        owner.post("/v1/manifests", json={"name": "Board pack"}, headers=csrf(owner))
    )
    ok(
        owner.patch(
            f"/v1/manifests/{saved['id']}/sharing",
            json={"owner_group_id": team},
            headers=csrf(owner),
        )
    )
    (entry,) = ok(peer.get("/v1/me/notifications", params={"limit": 500}))
    assert entry["recipient"] == "peer@x.test"
    assert "Board pack" in entry["subject"]
    assert (entry["status"], entry["sent_at"]) == ("pending", None)
    assert "body" not in entry
    # The sharer was mailed nothing, and a zero limit still means one page.
    assert ok(owner.get("/v1/me/notifications", params={"limit": 0})) == []


@pytest.mark.parametrize(
    "handler",
    [
        me.my_notifications,
        me.my_groups,
        me.list_my_subscriptions,
        me.get_my_preferences,
        me.list_my_shortcuts,
    ],
)
def test_account_routes_refuse_a_request_the_middleware_did_not_authenticate(
    db, handler
):
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    with pytest.raises(HTTPException) as refused:
        handler(request=request, db=db)
    assert refused.value.status_code == 401
