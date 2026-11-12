"""Admin namespace guards: role checks and last-admin protection."""

from __future__ import annotations

from tests.conftest import auth_client, make_user


def test_admin_routes_require_admin(client):
    viewer_c, _v = auth_client("VwA", role="viewer")
    assert viewer_c.get("/v1/admin/users").status_code == 403
    r = client.get("/v1/admin/users")
    assert r.status_code == 401


def test_admin_lists_and_updates_users(client):
    c, _a = auth_client("AdmU")
    make_user("TargetU", "Test-passphrase-1!", role="viewer")
    r = c.get("/v1/admin/users")
    assert r.status_code == 200
    assert any(u["username"] == "TargetU" for u in r.json()["items"])
    target = next(u for u in r.json()["items"] if u["username"] == "TargetU")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.patch(
        f"/v1/admin/users/{target['id']}",
        json={"role": "maintainer"},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "maintainer"


def test_last_admin_cannot_be_demoted_or_deactivated(client):
    c, me = auth_client("AdmV")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.patch(
        f"/v1/admin/users/{int(me.id)}",
        json={"role": "viewer"},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 409, "the last active admin cannot be demoted"
    # As in KEEN, no administrator deactivates their own account.
    r = c.patch(
        f"/v1/admin/users/{int(me.id)}",
        json={"is_active": False},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "You cannot deactivate your own account"
    r = c.delete(
        f"/v1/admin/users/{int(me.id)}",
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code in (400, 409)


def test_second_admin_can_be_demoted_by_the_first(client):
    c, _me = auth_client("AdmW")
    other = make_user("Adm2", "Test-passphrase-1!", role="admin")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.patch(
        f"/v1/admin/users/{int(other.id)}",
        json={"role": "viewer"},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 200


def test_last_admin_access_strip_is_refused(client):
    c, me = auth_client("AdmX")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.put(
        f"/v1/admin/users/{int(me.id)}/access",
        json={"group_ids": [], "permission_ids": []},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 409


def test_creating_users_validates_role_and_username(client):
    c, _a = auth_client("AdmY")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.post(
        "/v1/admin/users",
        json={
            "username": "bad role!",
            "password": "Test-passphrase-1!",
            "role": "superadmin",
        },
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code in (400, 422)
    r = c.post(
        "/v1/admin/users",
        json={
            "username": "bad username with space\n",
            "password": "Test-passphrase-1!",
            "role": "viewer",
        },
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code in (400, 422)


def test_features_endpoint_requires_authentication(client):
    r = client.get("/v1/system/features")
    assert r.status_code == 401
    c, _a = auth_client("FeatU")
    body = c.get("/v1/system/features").json()
    assert set(body) == {
        "frameworks",
        "manifests",
        "questions",
        "dependency_scans",
        "comparisons",
        "release_feed",
    }
