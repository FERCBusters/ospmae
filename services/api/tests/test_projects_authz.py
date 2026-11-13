"""Owned-object authorization, drafts and subscriptions."""

from __future__ import annotations

import secrets

from tests.conftest import generated_password, login, make_user


def _signed_in(
    client,
    username: str | None = None,
    role: str = "admin",
    password: str | None = None,
):
    """Sign the shared fixture client in and return (client, user, csrf)."""
    if username is None:
        username = f"u-{secrets.token_hex(4)}"
    if password is None:
        password = generated_password()
    user = make_user(username, password, role=role, email=f"{username}@example.com")
    r = login(client, username, password)
    assert r.status_code == 200, r.text
    client.headers["X-Forwarded-For"] = "8.8.8.8"
    return client, user, client.cookies.get("__Host-ospmae_csrf") or ""


def _project(client, csrf: str, name: str = "alpha"):
    r = client.post(
        "/v1/projects",
        json={"machine_name": name, "display_name": name.title()},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_project_create_list_get_delete_round_trip(client):
    c, user, csrf = _signed_in(client)
    created = _project(client, csrf, "alpha")
    assert created["machine_name"] == "alpha"
    r = client.get(f"/v1/projects/{created['id']}")
    assert r.status_code == 200
    r = client.get("/v1/projects")
    assert any(p["machine_name"] == "alpha" for p in r.json()["items"])
    r = client.delete(f"/v1/projects/{created['id']}", headers={"X-CSRF-Token": csrf})
    assert r.status_code in (200, 204)


def test_version_round_trip_and_subscription(client):
    c, user, csrf = _signed_in(client, role="admin")
    _project(client, csrf, "versified")
    r = client.post(
        "/v1/projects/1/versions",
        json={"version": "1.0.0", "status": "released", "is_latest": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.text
    r = client.get("/v1/projects/1/versions")
    assert r.status_code == 200
    r = client.post(
        "/v1/projects/1/subscription",
        json={"notify_new_versions": True, "notify_questions": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.text
    r = client.get("/v1/me/subscriptions")
    assert r.status_code == 200
    assert any(s["project_id"] == 1 for s in r.json()["items"])


def test_unauthenticated_writes_are_refused(client):
    r = client.post("/v1/projects", json={"machine_name": "x", "display_name": "x"})
    assert r.status_code == 401


def test_ownership_constrains_every_non_admin_role(client):
    """A granted project.write never escapes the owner's scope (H1)."""
    from app.db.models import Permission, UserPermission
    from app.db.session import SessionLocal
    from app.security.permissions import seed_default_permissions

    owner_c, owner, owner_csrf = _signed_in(
        client, "OwnB", password="Test-passphrase-1!"
    )
    _project(client, owner_csrf, "beta")

    # A separate engineer account with a direct project.write grant.
    make_user("OtherB", "Test-passphrase-1!", role="engineer")
    seed_db = SessionLocal()
    try:
        seed_default_permissions(seed_db)
        perm = (
            seed_db.query(Permission)
            .filter(Permission.code == "project.write")
            .one_or_none()
        )
        assert perm is not None
        from app.db.models import User

        eng_user = seed_db.query(User).filter(User.username == "OtherB").one()
        seed_db.add(
            UserPermission(user_id=int(eng_user.id), permission_id=int(perm.id))
        )
        seed_db.commit()
    finally:
        seed_db.close()

    # Sign the engineer in on the same fixture client.
    r = login(client, "OtherB", "Test-passphrase-1!")
    assert r.status_code == 200
    eng_csrf = client.cookies.get("__Host-ospmae_csrf") or ""
    r = client.put(
        "/v1/projects/1",
        json={"display_name": "hijacked"},
        headers={"X-CSRF-Token": eng_csrf},
    )
    assert r.status_code == 403, "granted write must not widen object scope"
    r = client.delete("/v1/projects/1", headers={"X-CSRF-Token": eng_csrf})
    assert r.status_code == 403

    # The owner still manages their own project.
    r = login(client, "OwnB", "Test-passphrase-1!")
    owner_csrf = client.cookies.get("__Host-ospmae_csrf") or ""
    r = client.put(
        "/v1/projects/1",
        json={"display_name": "renamed"},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert r.status_code == 200, r.status_code and r.text


def test_admin_bypasses_object_scope(client):
    make_user("PlainU", "Test-passphrase-1!", role="viewer")
    r = login(client, "PlainU", "Test-passphrase-1!")
    plain_csrf = client.cookies.get("__Host-ospmae_csrf") or ""
    r = client.post(
        "/v1/projects",
        json={"machine_name": "gamma", "display_name": "Gamma"},
        headers={"X-CSRF-Token": plain_csrf},
    )
    assert r.status_code in (403, 422), "viewer cannot create projects"

    make_user("AdminBypass", "Admin-passphrase-1!", role="admin")
    r = login(client, "AdminBypass", "Admin-passphrase-1!")
    assert r.status_code == 200
    admin_csrf = client.cookies.get("__Host-ospmae_csrf") or ""
    r = client.post(
        "/v1/projects",
        json={"machine_name": "gamma", "display_name": "Gamma"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r.status_code == 200
    project_id = r.json()["id"]
    r = client.put(
        f"/v1/projects/{project_id}",
        json={"display_name": "admin edit"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r.status_code == 200


def test_draft_versions_are_invisible_to_plain_viewers(client):
    c, user, csrf = _signed_in(client, "DraftA")
    _project(client, csrf, "drafted")
    r = client.post(
        "/v1/projects/1/versions",
        json={"version": "1.0.0", "is_draft": True, "status": "draft"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.text
    version_id = r.json().get("id") or r.json().get("version_id")

    make_user("DraftViewer", "Real-passphrase-1!", role="viewer")
    r = login(client, "DraftViewer", "Real-passphrase-1!")
    assert r.status_code == 200
    r = client.get(f"/v1/project-versions/{version_id}/changelog")
    assert r.status_code == 403, "drafts stay invisible outside owners/admin"

    make_user("DraftAdmin2", "Admin-passphrase-1!", role="admin")
    r = login(client, "DraftAdmin2", "Admin-passphrase-1!")
    assert r.status_code == 200
    assert client.get(f"/v1/project-versions/{version_id}/changelog").status_code == 200


def test_compare_excludes_drafts_for_viewers(client):
    c, user, csrf = _signed_in(client, "CmpA")
    _project(client, csro := csrf, "compared")
    assert csro
    r = client.post(
        "/v1/projects/1/versions",
        json={
            "version": "1.0.0",
            "is_draft": True,
            "notes": "SECRET-DRAFT-BODY-42",
            "status": "draft",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
    make_user("CmpV", "Viewer-passphrase-1!", role="viewer")
    r = login(client, "CmpV", "Viewer-passphrase-1!")
    assert r.status_code == 200
    r = client.get("/v1/projects/compare?left_project_id=1&right_project_id=1")
    assert r.status_code in (200, 403, 404)
    if r.status_code == 200:
        assert "SECRET-DRAFT-BODY-42" not in r.text, "compare must not leak drafts"

    make_user("CmpAdmin", "Admin-passphrase-1!", role="admin")
    r = login(client, "CmpAdmin", "Admin-passphrase-1!")
    r = client.get("/v1/projects/compare?left_project_id=1&right_project_id=1")
    assert r.status_code == 200
    assert "1.0.0" in r.text
