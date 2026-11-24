"""Administration that is OSPMAE's own: what group permissions open,
project ownership, organisations and the catalogue changelog. Accounts,
groups, the audit trail and the mail view are covered with mosp's
administration in test_admin_accounts.py and test_admin_access_routes.py."""

from __future__ import annotations

from app.db.models import (
    Organisation,
    Permission,
    Project,
    ProjectOwnerGroup,
    User,
    group_permissions,
)
from app.db.session import SessionLocal
from app.security.permissions import seed_default_permissions

from tests.support import csrf, make_group, make_project, ok, signed_in

# An identifier no account, group or permission holds.
UNKNOWN = "00000000-0000-4000-8000-000000000000"


def _permission(code: str) -> str:
    with SessionLocal() as s:
        seed_default_permissions(s)
        s.commit()
        return str(s.query(Permission.id).filter_by(code=code).scalar())


# ---------------------------------------------------------------------------
# Groups and permissions.
# ---------------------------------------------------------------------------


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
    assert listed[str(gid)]["permission_count"] == 2

    assert (
        admin.put(
            path, json={"permission_ids": [UNKNOWN]}, headers=csrf(admin)
        ).status_code
        == 400
    )
    assert (
        admin.put(path, json={"permission_ids": ["3"]}, headers=csrf(admin)).status_code
        == 422
    )
    with SessionLocal() as s:
        assert (
            s.query(group_permissions)
            .filter(group_permissions.c.group_id == gid)
            .count()
            == 2
        )
    ok(admin.put(path, json={"permission_ids": []}, headers=csrf(admin)))
    assert member.get("/v1/manifests").status_code == 403
    for call in (
        admin.get,
        lambda p: admin.put(p, json={"permission_ids": []}, headers=csrf(admin)),
    ):
        assert call(f"/v1/admin/groups/{UNKNOWN}/permissions").status_code == 404


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
            json={
                "owner_user_id": str(heir_id),
                "owner_group_ids": [str(team), str(spare)],
            },
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
        path, json={"owner_group_ids": [str(team), UNKNOWN]}, headers=csrf(admin)
    )
    assert (bad_group.status_code, bad_group.json()["detail"]) == (
        400,
        f"Unknown group ids: ['{UNKNOWN}']",
    )
    assert (
        admin.patch(
            path, json={"owner_user_id": UNKNOWN}, headers=csrf(admin)
        ).status_code
        == 400
    )
    with SessionLocal() as s:
        assert s.query(ProjectOwnerGroup).filter_by(project_id=pid).count() == 0
        assert s.get(Project, pid).created_by_user_id == heir_id
    assert (
        admin.patch(
            "/v1/admin/projects/999999/ownership",
            json={"owner_user_id": str(heir_id)},
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

    user_member = ok(add(user_id=str(person_id), role="steward"))
    ok(add(group_id=str(team)))
    assert add(user_id=str(person_id)).status_code == 409
    for body in ({}, {"user_id": str(person_id), "group_id": str(team)}):
        assert add(**body).status_code == 400
    assert add(user_id=UNKNOWN).status_code == 404
    assert add(group_id=UNKNOWN).status_code == 404
    assert (
        admin.post(
            "/v1/admin/organisations/999999/members",
            json={"user_id": str(person_id)},
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
