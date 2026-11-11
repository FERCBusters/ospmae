"""Administration of groups, permissions, ownership, organisations, and the
audit, changelog and mail views."""

from __future__ import annotations

from app.db.models import (
    AuditLog,
    Group,
    GroupPermission,
    Organisation,
    Permission,
    Project,
    ProjectOwnerGroup,
    User,
    UserGroup,
)
from app.db.session import SessionLocal
from app.security.permissions import seed_default_permissions

from tests.support import csrf, make_group, make_project, ok, signed_in


def _permission(code: str) -> int:
    with SessionLocal() as s:
        seed_default_permissions(s)
        s.commit()
        return s.query(Permission.id).filter_by(code=code).scalar()


# ---------------------------------------------------------------------------
# Groups and permissions.
# ---------------------------------------------------------------------------


def test_groups_are_created_renamed_given_roles_and_removed():
    admin, _ = signed_in("admin")

    def post(**body):
        return admin.post("/v1/admin/groups", json=body, headers=csrf(admin))

    created = ok(
        post(name=" Maintainers ", description="  who ship ", role="MAINTAINER")
    )
    assert (created["name"], created["description"], created["role"]) == (
        "Maintainers",
        "who ship",
        "maintainer",
    )
    gid = created["id"]
    assert post(name="Maintainers").status_code == 409
    assert post(name="   ").status_code == 400
    assert post(name="Bad", role="emperor").status_code == 400

    def patch(group_id=gid, **body):
        return admin.patch(
            f"/v1/admin/groups/{group_id}", json=body, headers=csrf(admin)
        )

    other = ok(post(name="Readers"))
    renamed = ok(patch(name=" Shippers ", description="", role=""))
    assert (renamed["name"], renamed["description"], renamed["role"]) == (
        "Shippers",
        None,
        None,
    )
    assert ok(patch(role="viewer"))["role"] == "viewer"
    assert ok(patch(name="Shippers"))["name"] == "Shippers"  # its own name is no clash
    assert patch(name="Readers").status_code == 409
    assert patch(name="  ").status_code == 400
    assert patch(role="emperor").status_code == 400
    assert patch(group_id=999999, name="x").status_code == 404

    with SessionLocal() as s:
        user = s.query(User).first()
        s.add(UserGroup(user_id=user.id, group_id=gid))
        s.commit()
    listed = {g["name"]: g for g in ok(admin.get("/v1/admin/groups"))["items"]}
    assert list(listed) == ["Readers", "Shippers"]
    assert (listed["Shippers"]["member_count"], listed["Readers"]["member_count"]) == (
        1,
        0,
    )

    assert ok(admin.delete(f"/v1/admin/groups/{gid}", headers=csrf(admin))) == {
        "status": "ok",
        "deleted_group_id": gid,
    }
    assert (
        admin.delete(f"/v1/admin/groups/{gid}", headers=csrf(admin)).status_code == 404
    )
    with SessionLocal() as s:
        assert s.query(UserGroup).count() == 0  # memberships go with the group
        assert s.get(Group, other["id"]) is not None


def test_a_groups_permissions_grant_its_members_the_routes_they_gate():
    admin, _ = signed_in("admin")
    member, member_id = signed_in("viewer")
    gid = make_group("Exporters", members=[member_id])
    manifest_perm = _permission("manifest.export")
    audit_perm = _permission("audittrail.read")
    path = f"/v1/admin/groups/{gid}/permissions"

    before = ok(admin.get(path))
    assert before["permission_ids"] == []
    assert "manifest.export" in {p["code"] for p in before["available_permissions"]}
    assert member.get("/v1/manifests").status_code == 403
    assert member.get("/v1/admin/audit").status_code == 403

    saved = ok(
        admin.put(
            path,
            json={"permission_ids": [audit_perm, manifest_perm, manifest_perm]},
            headers=csrf(admin),
        )
    )
    assert saved["permission_ids"] == sorted([manifest_perm, audit_perm])
    assert ok(admin.get(path))["permission_ids"] == sorted([manifest_perm, audit_perm])
    assert member.get("/v1/manifests").status_code == 200
    assert member.get("/v1/admin/audit").status_code == 200
    assert member.get("/v1/admin/entity-changelog").status_code == 200
    # Reading the trail is all it grants: administration stays closed.
    assert member.get("/v1/admin/groups").status_code == 403
    listed = {g["id"]: g for g in ok(admin.get("/v1/admin/groups"))["items"]}
    assert listed[gid]["permission_count"] == 2

    assert (
        admin.put(
            path, json={"permission_ids": [999999]}, headers=csrf(admin)
        ).status_code
        == 400
    )
    assert (
        admin.put(path, json={"permission_ids": ["3"]}, headers=csrf(admin)).status_code
        == 422
    )
    with SessionLocal() as s:
        assert s.query(GroupPermission).filter_by(group_id=gid).count() == 2
    ok(admin.put(path, json={"permission_ids": []}, headers=csrf(admin)))
    assert member.get("/v1/manifests").status_code == 403
    for call in (
        admin.get,
        lambda p: admin.put(p, json={"permission_ids": []}, headers=csrf(admin)),
    ):
        assert call("/v1/admin/groups/999999/permissions").status_code == 404


def test_a_permission_granted_to_one_account_applies_to_that_account():
    admin, _ = signed_in("admin")
    reader, reader_id = signed_in("viewer")
    perm = _permission("manifest.export")
    codes = [p["code"] for p in ok(admin.get("/v1/admin/permissions"))["items"]]
    assert codes == sorted(codes) and "project.write" in codes

    path = f"/v1/admin/users/{reader_id}/permissions/{perm}"
    assert reader.get("/v1/manifests").status_code == 403
    assert ok(admin.post(path, headers=csrf(admin))) == {"status": "ok"}
    assert ok(admin.post(path, headers=csrf(admin))) == {
        "status": "ok",
        "already_linked": True,
    }
    assert reader.get("/v1/manifests").status_code == 200
    assert (
        admin.post(
            f"/v1/admin/users/999999/permissions/{perm}", headers=csrf(admin)
        ).status_code
        == 404
    )
    assert (
        admin.post(
            f"/v1/admin/users/{reader_id}/permissions/999999", headers=csrf(admin)
        ).status_code
        == 404
    )


# ---------------------------------------------------------------------------
# Accounts.
# ---------------------------------------------------------------------------


def test_accounts_are_deleted_but_never_the_last_administrator_or_oneself():
    admin, admin_id = signed_in("admin")
    author, author_id = signed_in("maintainer")
    project = make_project(author, "kept")

    own = admin.delete(f"/v1/admin/users/{admin_id}", headers=csrf(admin))
    assert (own.status_code, own.json()["detail"]) == (
        400,
        "You cannot delete your own user",
    )
    assert (
        admin.delete("/v1/admin/users/999999", headers=csrf(admin)).status_code == 404
    )

    assert ok(admin.delete(f"/v1/admin/users/{author_id}", headers=csrf(admin))) == {
        "status": "ok",
        "deleted_user_id": author_id,
    }
    # Their sessions end with them, and what they created stays, unowned.
    assert author.get("/v1/me").status_code == 401
    with SessionLocal() as s:
        assert s.get(Project, project["id"]).created_by_user_id is None

    # A second administrator may remove the first, but the last one stays.
    second, second_id = signed_in("admin")
    with SessionLocal() as s:
        s.get(User, second_id).is_active = False
        s.commit()
    assert (
        ok(admin.delete(f"/v1/admin/users/{second_id}", headers=csrf(admin)))["status"]
        == "ok"
    )
    third, third_id = signed_in("admin")
    assert (
        ok(third.delete(f"/v1/admin/users/{admin_id}", headers=csrf(third)))["status"]
        == "ok"
    )
    with SessionLocal() as s:
        assert [u.id for u in s.query(User).filter_by(role="admin")] == [third_id]


# ---------------------------------------------------------------------------
# Project ownership.
# ---------------------------------------------------------------------------


def test_ownership_moves_to_another_account_and_other_groups():
    admin, _ = signed_in("admin")
    author, _ = signed_in("maintainer")
    heir, heir_id = signed_in("maintainer")
    helper, helper_id = signed_in("maintainer")
    team = make_group("Team", members=[helper_id])
    spare = make_group("Spare")
    pid = make_project(author, "handover")["id"]
    path = f"/v1/admin/projects/{pid}/ownership"

    def edit(client):
        return client.put(
            f"/v1/projects/{pid}", json={"license": "MIT"}, headers=csrf(client)
        )

    assert edit(heir).status_code == 403 and edit(helper).status_code == 403
    assert ok(
        admin.patch(
            path,
            json={"owner_user_id": heir_id, "owner_group_ids": [team, spare]},
            headers=csrf(admin),
        )
    ) == {"ok": True}
    assert edit(heir).status_code == 200 and edit(helper).status_code == 200
    assert edit(author).status_code == 403
    with SessionLocal() as s:
        assert {
            link.group_id
            for link in s.query(ProjectOwnerGroup).filter_by(project_id=pid)
        } == {team, spare}

    # The change is in the project's changelog.
    log = ok(admin.get(f"/v1/projects/{pid}/changelog"))
    changed = {c["field"] for entry in log["items"] for c in entry["changes"]}
    assert "owner_group_ids" in changed

    # Groups can be cleared on their own; unknown owners and groups are refused whole.
    ok(admin.patch(path, json={"owner_group_ids": []}, headers=csrf(admin)))
    assert edit(helper).status_code == 403 and edit(heir).status_code == 200
    bad_group = admin.patch(
        path, json={"owner_group_ids": [team, 999999]}, headers=csrf(admin)
    )
    assert (bad_group.status_code, bad_group.json()["detail"]) == (
        400,
        "Unknown group ids: [999999]",
    )
    assert (
        admin.patch(
            path, json={"owner_user_id": 999999}, headers=csrf(admin)
        ).status_code
        == 400
    )
    with SessionLocal() as s:
        assert s.query(ProjectOwnerGroup).filter_by(project_id=pid).count() == 0
        assert s.get(Project, pid).created_by_user_id == heir_id
    assert (
        admin.patch(
            "/v1/admin/projects/999999/ownership",
            json={"owner_user_id": heir_id},
            headers=csrf(admin),
        ).status_code
        == 404
    )
    assert (
        heir.patch(path, json={"owner_group_ids": []}, headers=csrf(heir)).status_code
        == 403
    )


# ---------------------------------------------------------------------------
# Organisations.
# ---------------------------------------------------------------------------


def test_organisations_are_kept_unique_and_counted():
    admin, _ = signed_in("admin")

    def post(**body):
        return admin.post("/v1/admin/organisations", json=body, headers=csrf(admin))

    acme = ok(post(name=" Acme ", description="Makers", website="https://acme.example"))
    assert acme["name"] == "Acme"
    assert post(name="Acme").status_code == 409
    assert post(name="  ").status_code == 400
    assert post().status_code == 400
    globex = ok(post(name="Globex"))
    make_project(admin, "one", organisation="Acme")
    make_project(admin, "two", organisation_id=acme["id"])

    viewer, _ = signed_in("viewer")
    listed = ok(viewer.get("/v1/organisations"))
    assert [(o["name"], o["project_count"], o["website"]) for o in listed] == [
        ("Acme", 2, "https://acme.example"),
        ("Globex", 0, None),
    ]

    def patch(org_id, **body):
        return admin.patch(
            f"/v1/admin/organisations/{org_id}", json=body, headers=csrf(admin)
        )

    assert (
        ok(patch(acme["id"], name=" Acme Corp ", description="", website=""))["name"]
        == "Acme Corp"
    )
    with SessionLocal() as s:
        row = s.get(Organisation, acme["id"])
        assert (row.description, row.website) == (None, None)
    assert patch(globex["id"], name="Acme Corp").status_code == 409
    # A blank or repeated name changes nothing.
    assert ok(patch(globex["id"], name="   "))["name"] == "Globex"
    assert (
        ok(patch(globex["id"], name="Globex", description="Rivals"))["name"] == "Globex"
    )
    assert patch(999999, name="x").status_code == 404
    assert (
        viewer.post(
            "/v1/admin/organisations", json={"name": "x"}, headers=csrf(viewer)
        ).status_code
        == 403
    )


def test_an_organisation_lists_the_accounts_and_groups_on_its_view():
    admin, _ = signed_in("admin")
    person, person_id = signed_in("viewer")
    team = make_group("Team")
    org = ok(
        admin.post(
            "/v1/admin/organisations", json={"name": "Acme"}, headers=csrf(admin)
        )
    )["id"]
    path = f"/v1/admin/organisations/{org}/members"

    def add(**body):
        return admin.post(path, json=body, headers=csrf(admin))

    user_member = ok(add(user_id=person_id, role="steward"))
    ok(add(group_id=team))
    assert add(user_id=person_id).status_code == 409
    for body in ({}, {"user_id": person_id, "group_id": team}):
        assert add(**body).status_code == 400
    assert add(user_id=999999).status_code == 404
    assert add(group_id=999999).status_code == 404
    assert (
        admin.post(
            "/v1/admin/organisations/999999/members",
            json={"user_id": person_id},
            headers=csrf(admin),
        ).status_code
        == 404
    )

    detail = ok(admin.get(f"/v1/admin/organisations/{org}"))
    members = {m["kind"]: m for m in detail["members"]}
    assert set(members) == {"user", "group"}
    assert members["user"]["role"] == "steward"
    assert members["group"]["name"] == "Team"
    with SessionLocal() as s:
        assert members["user"]["name"] == s.get(User, person_id).username
    assert admin.get("/v1/admin/organisations/999999").status_code == 404

    # Removal is scoped to the organisation the member belongs to.
    other = ok(
        admin.post(
            "/v1/admin/organisations", json={"name": "Other"}, headers=csrf(admin)
        )
    )["id"]
    wrong = admin.delete(
        f"/v1/admin/organisations/{other}/members/{user_member['id']}",
        headers=csrf(admin),
    )
    assert wrong.status_code == 404
    assert ok(admin.delete(f"{path}/{user_member['id']}", headers=csrf(admin))) == {
        "deleted": True
    }
    assert [
        m["kind"] for m in ok(admin.get(f"/v1/admin/organisations/{org}"))["members"]
    ] == ["group"]


# ---------------------------------------------------------------------------
# Audit trail, changelog and mail.
# ---------------------------------------------------------------------------


def test_the_audit_trail_filters_by_who_what_and_outcome():
    admin, admin_id = signed_in("admin")
    viewer, viewer_id = signed_in("viewer")
    with SessionLocal() as s:
        admin_name = s.get(User, admin_id).username
        viewer_name = s.get(User, viewer_id).username
    make_project(admin, "audited")
    assert (
        viewer.post(
            "/v1/projects",
            json={"machine_name": "x", "display_name": "X"},
            headers=csrf(viewer),
        ).status_code
        == 403
    )
    viewer.get("/v1/projects/999999")
    with SessionLocal() as s:
        # A sign-in callback's address carries one-time codes; it is never listed.
        s.add(
            AuditLog(
                username="sso",
                method="GET",
                path="/v1/auth/oidc/callback",
                status_code=302,
                duration_ms=1,
            )
        )
        s.commit()

    def trail(**params):
        return ok(admin.get("/v1/admin/audit", params={"limit": 200, **params}))

    everything = trail()
    assert everything["total"] == len(everything["items"])
    assert all("callback" not in item["path"] for item in everything["items"])

    posts = trail(method=" post ", path="/v1/projects")
    assert {(i["username"], i["status_code"]) for i in posts["items"]} == {
        (admin_name, 200),
        (viewer_name, 403),
    }
    refused = trail(status_min=400, status_max=499, username=viewer_name.upper())
    assert sorted(
        (i["method"], i["path"], i["status_code"]) for i in refused["items"]
    ) == [
        ("GET", "/v1/projects/999999", 404),
        ("POST", "/v1/projects", 403),
    ]
    assert trail(path="100%")["total"] == 0
    # A blank method filter is no filter (the trail records its own reads too).
    assert trail(method="  ")["total"] > everything["total"]

    page = ok(admin.get("/v1/admin/audit", params={"limit": 1, "offset": 1}))
    assert (page["limit"], page["offset"], len(page["items"])) == (1, 1, 1)
    clamped = ok(admin.get("/v1/admin/audit", params={"limit": 5000, "offset": -4}))
    assert (clamped["limit"], clamped["offset"]) == (200, 0)
    assert viewer.get("/v1/admin/audit").status_code == 403


def test_the_catalogue_changelog_is_searchable_across_entities():
    admin, admin_id = signed_in("admin")
    alpha = make_project(admin, "alpha", display_name="Alpha")
    make_project(admin, "beta", display_name="Beta")
    version = ok(
        admin.post(
            f"/v1/projects/{alpha['id']}/versions",
            json={"version": "1.0.0"},
            headers=csrf(admin),
        )
    )
    with SessionLocal() as s:
        name = s.get(User, admin_id).username

    def log(**params):
        return ok(admin.get("/v1/admin/entity-changelog", params=params))

    assert log()["total"] == 3
    assert {e["entity_title"] for e in log(entity_type=" Project ")["items"]} == {
        "Alpha",
        "Beta",
    }
    versions = log(entity_type="project_version", entity_id=version["id"])
    assert [e["action"] for e in versions["items"]] == ["created"]
    assert log(q="beta")["total"] == 1
    assert log(q=name[:6])["total"] == 3  # the search covers who made the change
    assert log(username=name)["total"] == 3
    assert log(username="nobody-by-that-name")["total"] == 0
    assert log(q="100%_")["total"] == 0
    assert (
        admin.get(
            "/v1/admin/entity-changelog", params={"entity_type": "manifest"}
        ).status_code
        == 400
    )


def test_the_mail_view_reports_queue_state(outbox):
    admin, _ = signed_in("admin")
    owner, owner_id = signed_in("architect")
    _peer, peer_id = signed_in("architect", email="peer@x.test")
    team = make_group("Team", members=[owner_id, peer_id])
    saved = ok(owner.post("/v1/manifests", json={"name": "Pack"}, headers=csrf(owner)))
    ok(
        owner.patch(
            f"/v1/manifests/{saved['id']}/sharing",
            json={"owner_group_id": team},
            headers=csrf(owner),
        )
    )

    view = ok(admin.get("/v1/admin/notifications", params={"limit": 0}))
    assert (view["pending"], view["failed"]) == (1, 0)
    (mail,) = view["notifications"]
    assert (mail["recipient"], mail["status"], mail["user_id"]) == (
        "peer@x.test",
        "pending",
        peer_id,
    )
    assert "body" not in mail
    with SessionLocal() as s:
        from app.db.models import Notification

        s.query(Notification).update(
            {Notification.status: "failed", Notification.last_error: "550"}
        )
        s.commit()
    view = ok(admin.get("/v1/admin/notifications"))
    assert (view["pending"], view["failed"]) == (0, 1)
    assert view["notifications"][0]["last_error"] == "550"
    assert owner.get("/v1/admin/notifications").status_code == 403
