"""Administration of groups and access: typed bodies, integrity, effects."""

from __future__ import annotations

import pytest
from app.db.models import Group, GroupPermission, Permission, UserGroup, UserPermission
from app.db.session import SessionLocal

from tests.conftest import auth_client, make_user


def _h(c):
    return {"X-CSRF-Token": c.cookies.get("ospmae_csrf") or ""}


@pytest.fixture()
def admin():
    c, _ = auth_client(role="admin")
    return c


def _group(c, name="Editors", **extra):
    r = c.post("/v1/admin/groups", json={"name": name, **extra}, headers=_h(c))
    assert r.status_code == 200, r.text
    return r.json()


def _permission_ids():
    with SessionLocal() as db:
        rows = [Permission(code="test.first"), Permission(code="test.second")]
        db.add_all(rows)
        db.commit()
        return [row.id for row in rows]


def test_groups_are_created_renamed_and_deleted(admin):
    g = _group(admin, " Editors ", description=" Edit things ", role="viewer")
    assert (g["name"], g["description"], g["role"]) == (
        "Editors",
        "Edit things",
        "viewer",
    )
    assert (
        admin.post(
            "/v1/admin/groups", json={"name": "Editors"}, headers=_h(admin)
        ).status_code
        == 409
    )
    assert (
        admin.post(
            "/v1/admin/groups", json={"name": " "}, headers=_h(admin)
        ).status_code
        == 400
    )
    assert (
        admin.post(
            "/v1/admin/groups", json={"name": "X", "role": "emperor"}, headers=_h(admin)
        ).status_code
        == 400
    )
    _group(admin, "Other")
    url = f"/v1/admin/groups/{g['id']}"
    assert (
        admin.patch(url, json={"name": "Other"}, headers=_h(admin)).status_code == 409
    )
    assert admin.patch(url, json={"name": ""}, headers=_h(admin)).status_code == 400
    renamed = admin.patch(
        url,
        json={"name": "Writers", "description": "", "role": None},
        headers=_h(admin),
    ).json()
    assert (renamed["name"], renamed["description"], renamed["role"]) == (
        "Writers",
        None,
        None,
    )
    # Fields left out are left alone.
    assert admin.patch(url, json={}, headers=_h(admin)).json()["name"] == "Writers"
    assert admin.delete(url, headers=_h(admin)).json() == {
        "status": "ok",
        "deleted_group_id": g["id"],
    }
    assert admin.patch(url, json={}, headers=_h(admin)).status_code == 404
    names = [x["name"] for x in admin.get("/v1/admin/groups").json()["items"]]
    assert names == ["Other"]


@pytest.mark.parametrize(
    "body",
    [
        {"name": 5},
        {"name": ["Editors"]},
        {"name": "x" * 201},
        {"name": "ok", "description": {"a": 1}},
    ],
)
def test_group_bodies_are_typed(admin, body):
    response = admin.post("/v1/admin/groups", json=body, headers=_h(admin))
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.query(Group).count() == 0


def test_user_access_is_replaced_as_a_whole(admin):
    user = make_user("accessed", "Secret-pass-1!", role="viewer")
    g1, g2 = _group(admin, "One"), _group(admin, "Two")
    p1, p2 = _permission_ids()
    url = f"/v1/admin/users/{user.id}/access"
    r = admin.put(
        url,
        json={"group_ids": [g2["id"], g1["id"], g1["id"]], "permission_ids": [p1]},
        headers=_h(admin),
    )
    assert r.json() == {
        "status": "ok",
        "user_id": user.id,
        "group_ids": sorted([g1["id"], g2["id"]]),
        "permission_ids": [p1],
    }
    admin.put(
        url, json={"group_ids": [g2["id"]], "permission_ids": [p2]}, headers=_h(admin)
    )
    with SessionLocal() as db:
        assert [m.group_id for m in db.query(UserGroup).filter_by(user_id=user.id)] == [
            g2["id"]
        ]
        assert [
            m.permission_id for m in db.query(UserPermission).filter_by(user_id=user.id)
        ] == [p2]
    shown = admin.get(url).json()
    assert (shown["group_ids"], shown["permission_ids"]) == ([g2["id"]], [p2])


@pytest.mark.parametrize(
    "body",
    [
        # A string must never be read character by character as identifiers.
        {"group_ids": "12"},
        {"group_ids": ["1"]},
        {"permission_ids": [1.5]},
        {"permission_ids": [True]},
        {"group_ids": list(range(501))},
    ],
)
def test_user_access_bodies_hold_integer_lists(admin, body):
    user = make_user("typed", "Secret-pass-1!", role="viewer")
    _group(admin, "One")
    response = admin.put(
        f"/v1/admin/users/{user.id}/access", json=body, headers=_h(admin)
    )
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.query(UserGroup).filter_by(user_id=user.id).count() == 0


def test_unknown_groups_and_permissions_are_refused(admin):
    user = make_user("unknowns", "Secret-pass-1!", role="viewer")
    url = f"/v1/admin/users/{user.id}/access"
    assert (
        admin.put(url, json={"group_ids": [999999]}, headers=_h(admin)).status_code
        == 400
    )
    assert (
        admin.put(url, json={"permission_ids": [999999]}, headers=_h(admin)).status_code
        == 400
    )
    assert (
        admin.put(
            "/v1/admin/users/999999/access", json={}, headers=_h(admin)
        ).status_code
        == 404
    )


def test_group_permissions_are_replaced_and_typed(admin):
    g = _group(admin, "Perms")
    p1, p2 = _permission_ids()
    url = f"/v1/admin/groups/{g['id']}/permissions"
    assert (
        admin.put(
            url, json={"permission_ids": [p2, p1, p1]}, headers=_h(admin)
        ).status_code
        == 200
    )
    assert (
        admin.put(url, json={"permission_ids": [p2]}, headers=_h(admin)).status_code
        == 200
    )
    with SessionLocal() as db:
        assert [
            x.permission_id
            for x in db.query(GroupPermission).filter_by(group_id=g["id"])
        ] == [p2]
    assert (
        admin.put(url, json={"permission_ids": "7"}, headers=_h(admin)).status_code
        == 422
    )
    assert (
        admin.put(url, json={"permission_ids": [999999]}, headers=_h(admin)).status_code
        == 400
    )
    assert (
        admin.put(
            "/v1/admin/groups/999999/permissions", json={}, headers=_h(admin)
        ).status_code
        == 404
    )


def test_only_administrators_manage_access():
    viewer, user = auth_client(role="viewer")
    assert viewer.get("/v1/admin/groups").status_code == 403
    assert (
        viewer.post(
            "/v1/admin/groups", json={"name": "x"}, headers=_h(viewer)
        ).status_code
        == 403
    )
    assert (
        viewer.put(
            f"/v1/admin/users/{user.id}/access", json={}, headers=_h(viewer)
        ).status_code
        == 403
    )
