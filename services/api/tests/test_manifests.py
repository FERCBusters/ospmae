"""Manifests: what an export carries in each format, what a saved snapshot
keeps, and who may read, change, share and copy one."""

from __future__ import annotations

import csv
import io
from datetime import datetime

import pytest
from app.db.models import Manifest, ProjectVersion
from app.db.session import SessionLocal
from openpyxl import load_workbook

from tests.support import (
    csrf,
    make_framework,
    make_group,
    make_node,
    make_project,
    make_version,
    map_nodes,
    ok,
    record_dependency,
    signed_in,
)


@pytest.fixture()
def catalogue():
    """Two projects mapped onto a small taxonomy, one of them scanned."""
    admin, admin_id = signed_in("admin")
    fw = make_framework(admin)
    wallet = make_node(admin, fw["id"], "wallet")
    storage = make_node(admin, fw["id"], "storage", parent_id=wallet["id"])
    issuer = make_node(admin, fw["id"], "issuer")

    alpha = make_project(
        admin,
        "alpha",
        organisation="Acme",
        project_type="library",
        license="MIT",
        programming_languages=["Python", "Rust"],
        supported_profiles=["OpenID4VCI"],
        link_to_app="https://alpha.example",
    )
    alpha_v = make_version(
        admin, alpha["id"], "1.2.0", status="stable", release_date="2026-03-04"
    )
    map_nodes(admin, alpha_v["id"], fw["id"], [storage["id"], issuer["id"]])
    record_dependency(
        alpha_v["id"],
        "pypi",
        "requests",
        "2.0.0",
        vulnerabilities=[("CVE-2026-1", "high", "2.0.1"), ("CVE-2026-2", None, None)],
    )
    record_dependency(alpha_v["id"], "pypi", "idna", "3.0", indirect=True)

    beta = make_project(admin, "beta", display_name="=Beta|Co")
    beta_v = make_version(admin, beta["id"], "0.1.0", status="alpha")
    map_nodes(admin, beta_v["id"], fw["id"], [issuer["id"]])

    return {
        "admin": admin,
        "admin_id": admin_id,
        "fw": fw["id"],
        "nodes": {
            "wallet": wallet["id"],
            "storage": storage["id"],
            "issuer": issuer["id"],
        },
        "alpha": alpha["id"],
        "alpha_v": alpha_v["id"],
        "beta": beta["id"],
        "beta_v": beta_v["id"],
    }


def _export(client, path, **params):
    response = client.get(path, params=params)
    assert response.status_code == 200, response.text
    return response


# ---------------------------------------------------------------------------
# Exports.
# ---------------------------------------------------------------------------


def test_json_export_carries_versions_capabilities_and_findings(catalogue):
    admin = catalogue["admin"]
    response = _export(
        admin, "/v1/manifests/export", framework_id=catalogue["fw"], name="my export!"
    )
    assert response.headers["content-type"].startswith("application/json")
    # The file name is reduced to safe characters.
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="my-export-.json"'
    )
    items = {row["machine_name"]: row for row in response.json()["items"]}
    assert list(items) == ["beta", "alpha"]  # ordered by display name: "=Beta|Co"

    alpha = items["alpha"]
    assert alpha["latest_version"] == "1.2.0"
    assert alpha["latest_version_id"] == catalogue["alpha_v"]
    assert alpha["latest_release_date"].startswith("2026-03-04")
    assert alpha["capabilities"] == ["Issuer", "Wallet > Storage"]
    assert alpha["capability_ids"] == [
        catalogue["nodes"]["issuer"],
        catalogue["nodes"]["storage"],
    ]
    assert alpha["programming_languages"] == ["Python", "Rust"]
    assert (alpha["dependency_count"], alpha["vulnerability_count"]) == (2, 2)
    deps = {d["package"]: d for d in alpha["dependencies"]}
    assert [d["package"] for d in alpha["dependencies"]] == ["idna", "requests"]
    assert deps["idna"]["is_indirect"] is True and deps["idna"]["vulnerabilities"] == []
    findings = deps["requests"]["vulnerabilities"]
    assert [
        (v["vulnerability_id"], v["severity"], v["fixed_version"]) for v in findings
    ] == [
        ("CVE-2026-1", "HIGH", "2.0.1"),
        ("CVE-2026-2", None, None),
    ]
    assert findings[0]["references"] == ["https://advisories.example/CVE-2026-1"]

    beta = items["beta"]
    assert beta["capabilities"] == ["Issuer"]
    assert (beta["dependency_count"], beta["dependencies"]) == (0, [])


def test_export_filters_by_capability_subtree_project_language_status_and_text(
    catalogue,
):
    admin, fw, nodes = catalogue["admin"], catalogue["fw"], catalogue["nodes"]

    def names(**params):
        rows = _export(admin, "/v1/manifests/export", framework_id=fw, **params)
        return [row["machine_name"] for row in rows.json()["items"]]

    # A parent node selects projects mapped to any descendant.
    assert names(node_ids=str(nodes["wallet"])) == ["alpha"]
    assert names(capability_ids=str(nodes["issuer"])) == ["beta", "alpha"]
    assert names(project_ids=f"{catalogue['beta']},junk,-4,0") == ["beta"]
    assert names(languages="rust") == []  # tags match as stored
    assert names(programming_languages="Rust,Go") == ["alpha"]
    assert names(statuses="STABLE") == ["alpha"]
    assert names(statuses="alpha, stable") == ["beta", "alpha"]
    assert names(q="acme") == ["alpha"]
    assert names(q="100%") == []  # wildcards in the text are literal
    assert names(q="   ") == ["beta", "alpha"]

    # A node of another framework is refused, naming the offender.
    other = make_framework(admin, "other", "Other")
    foreign = make_node(admin, other["id"], "foreign")
    response = admin.get(
        "/v1/manifests/export",
        params={"framework_id": fw, "node_ids": str(foreign["id"])},
    )
    assert response.status_code == 400
    assert str(foreign["id"]) in response.json()["detail"]


def test_markdown_export_has_the_matrix_and_per_dependency_findings(catalogue):
    admin = catalogue["admin"]
    response = _export(
        admin, "/v1/manifests/export", framework_id=catalogue["fw"], fmt="markdown"
    )
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"].endswith('project-manifest.md"')
    text = response.text
    lines = text.splitlines()
    issuer, storage = catalogue["nodes"]["issuer"], catalogue["nodes"]["storage"]
    assert f"| Alpha | Acme | library | 1.2.0 | {issuer}, {storage} | 2 | 2 |" in lines
    # A pipe in a name is escaped so it cannot break the table.
    assert f"| =Beta\\|Co | — | — | 0.1.0 | {issuer} | 0 | 0 |" in lines
    assert "| Capability Path | =Beta\\|Co | Alpha |" in lines
    assert "| Issuer | ✅ | ✅ |" in lines
    assert "| Wallet > Storage | — | ✅ |" in lines
    assert "### Alpha — 1.2.0" in lines
    assert "2 dependencies; 2 vulnerabilities" in lines
    assert "| pypi | idna | 3.0 | yes | — | — | — | — | — |" in lines
    assert (
        "| pypi | requests | 2.0.0 | no | CVE-2026-1 | HIGH | CVE-2026-1 in requests "
        "| 2.0.1 | https://advisories.example/CVE-2026-1 |" in lines
    )
    # Beta has no dependencies and gets no section.
    assert "### =Beta" not in text


def test_markdown_export_says_so_when_there_is_nothing_to_tabulate(catalogue):
    admin = catalogue["admin"]
    empty = make_framework(admin, "empty", "Empty")
    text = _export(
        admin,
        "/v1/manifests/export",
        framework_id=empty["id"],
        fmt="markdown",
        project_ids=str(catalogue["beta"]),
    ).text
    assert "No capability mappings available." in text
    assert "No dependency data available." in text
    none = _export(
        admin,
        "/v1/manifests/export",
        framework_id=empty["id"],
        fmt="markdown",
        q="no such project",
    ).text
    assert none.splitlines()[2:] == [
        "",
        "## Capability Matrix",
        "No capability mappings available.",
        "",
        "## Dependencies",
        "No dependency data available.",
    ]


def test_spreadsheet_export_fills_every_sheet_and_defuses_formulas(catalogue):
    admin = catalogue["admin"]
    for fmt in ("xlsx", "spreadsheet"):
        response = _export(
            admin, "/v1/manifests/export", framework_id=catalogue["fw"], format=fmt
        )
        assert response.headers["content-disposition"].endswith('.xlsx"')
    book = load_workbook(io.BytesIO(response.content))
    assert book.sheetnames == [
        "Projects",
        "CapabilityMappings",
        "Capabilities",
        "Dependencies",
        "DependencyVulnerabilities",
    ]

    def rows(sheet):
        values = list(book[sheet].iter_rows(values_only=True))
        return [dict(zip(values[0], row)) for row in values[1:]]

    projects = {row["machine_name"]: row for row in rows("Projects")}
    assert projects["alpha"]["programming_languages"] == "Python; Rust"
    assert projects["alpha"]["dependency_count"] == 2
    assert projects["alpha"]["supported_profiles"] == "OpenID4VCI"
    # A name starting with "=" would run as a formula; it is stored as text.
    assert projects["beta"]["display_name"] == "'=Beta|Co"
    assert {
        (row["project_name"], row["capability_path"])
        for row in rows("CapabilityMappings")
    } == {
        ("Alpha", "Issuer"),
        ("Alpha", "Wallet > Storage"),
        ("'=Beta|Co", "Issuer"),
    }
    assert [row["capability_path"] for row in rows("Capabilities")] == sorted(
        ["Issuer", "Wallet > Storage"],
        key=lambda p: {"Issuer": catalogue["nodes"]["issuer"]}.get(
            p, catalogue["nodes"]["storage"]
        ),
    )
    deps = {row["package"]: row for row in rows("Dependencies")}
    assert deps["idna"]["is_indirect"] is True
    assert deps["requests"]["source_files"] == "requirements.txt"
    assert deps["requests"]["vulnerability_count"] == 2
    vulns = rows("DependencyVulnerabilities")
    assert [(v["vulnerability_id"], v["severity"], v["scanner"]) for v in vulns] == [
        ("CVE-2026-1", "HIGH", "grype"),
        ("CVE-2026-2", None, "grype"),
    ]
    assert vulns[0]["references"] == "https://advisories.example/CVE-2026-1"


def test_csv_export_defuses_formulas_and_unknown_formats_are_refused(catalogue):
    admin = catalogue["admin"]
    response = _export(
        admin, "/v1/manifests/export", framework_id=catalogue["fw"], format="CSV "
    )
    assert response.headers["content-type"].startswith("text/csv")
    parsed = list(csv.reader(io.StringIO(response.text)))
    assert parsed[0] == ["project_id", "machine_name", "display_name", "capabilities"]
    assert parsed[1][1:] == ["beta", "'=Beta|Co", "Issuer"]
    assert parsed[2][1:] == ["alpha", "Alpha", "Issuer; Wallet > Storage"]

    refused = admin.get("/v1/manifests/export", params={"format": "pdf"})
    assert refused.status_code == 400
    assert "json, xlsx" in refused.json()["detail"]


def test_single_project_export_follows_the_chosen_version(catalogue):
    admin, alpha = catalogue["admin"], catalogue["alpha"]
    old = make_version(admin, alpha, "1.0.0", is_latest=False)
    base = f"/v1/projects/{alpha}/manifest/export"

    latest = _export(admin, base, framework_id=catalogue["fw"])
    assert latest.headers["content-disposition"].endswith('"alpha-1-2-0.json"')
    (row,) = latest.json()["items"]
    assert (row["latest_version"], row["dependency_count"]) == ("1.2.0", 2)
    assert row["capabilities"] == ["Issuer", "Wallet > Storage"]

    chosen = _export(admin, base, version_id=old["id"], name="pinned", fmt="json")
    assert chosen.headers["content-disposition"].endswith('"pinned.json"')
    (row,) = chosen.json()["items"]
    # The older version inherited the mappings at creation, and was never scanned.
    assert (row["latest_version"], row["dependency_count"]) == ("1.0.0", 0)
    assert row["latest_version_id"] == old["id"]

    assert admin.get(base, params={"version_id": 999999}).status_code == 404
    assert admin.get("/v1/projects/999999/manifest/export").status_code == 404
    bare = make_project(admin, "bare")
    response = admin.get(f"/v1/projects/{bare['id']}/manifest/export")
    assert response.status_code == 404
    assert response.json()["detail"] == "Project has no versions"


def test_a_draft_is_exported_and_saved_only_by_those_who_may_see_it(catalogue):
    admin, alpha = catalogue["admin"], catalogue["alpha"]
    draft = make_version(admin, alpha, "2.0.0-rc1", is_draft=True)
    architect, _ = signed_in("architect")
    for call in (
        lambda c: c.get(
            f"/v1/projects/{alpha}/manifest/export", params={"version_id": draft["id"]}
        ),
        lambda c: c.post(
            f"/v1/projects/{alpha}/manifest/save",
            params={"version_id": draft["id"]},
            json={"name": "sneak"},
            headers=csrf(c),
        ),
    ):
        refused = call(architect)
        assert refused.status_code == 403
        assert refused.json()["detail"] == "Draft version is not accessible"
        assert call(admin).status_code == 200
    # Without naming it, the architect gets the published Latest.
    (row,) = architect.get(f"/v1/projects/{alpha}/manifest/export").json()["items"]
    assert row["latest_version"] == "1.2.0"


# ---------------------------------------------------------------------------
# Saved snapshots.
# ---------------------------------------------------------------------------


def test_a_saved_manifest_is_a_snapshot_that_outlives_later_edits(catalogue):
    admin, fw = catalogue["admin"], catalogue["fw"]
    saved = ok(
        admin.post(
            "/v1/manifests",
            json={
                "name": "  Release review ",
                "description": " for the board ",
                "framework_id": fw,
                "node_ids": [catalogue["nodes"]["issuer"]],
                "project_ids": [catalogue["alpha"], catalogue["beta"], -1],
            },
            headers=csrf(admin),
        )
    )
    assert (saved["name"], saved["description"]) == ("Release review", "for the board")
    assert (saved["item_count"], saved["framework_id"]) == (2, fw)

    # The catalogue moves on: a rename, a new Latest and a changed mapping.
    ok(
        admin.put(
            f"/v1/projects/{catalogue['alpha']}",
            json={"display_name": "Alpha Renamed"},
            headers=csrf(admin),
        )
    )
    make_version(admin, catalogue["alpha"], "9.0.0", is_latest=True)
    map_nodes(admin, catalogue["alpha_v"], fw, [])

    detail = ok(admin.get(f"/v1/manifests/{saved['id']}"))
    assert detail["filters"] == detail["filters_json"]
    assert detail["filters"]["node_ids"] == [catalogue["nodes"]["issuer"]]
    assert detail["filters"]["project_ids"] == [catalogue["alpha"], catalogue["beta"]]
    assert (detail["can_manage"], detail["can_clone"]) == (True, False)
    assert detail["framework_machine_name"] == "tax"
    items = {row["machine_name"]: row for row in detail["items"]}
    alpha = items["alpha"]
    assert (alpha["display_name"], alpha["latest_version"]) == ("Alpha", "1.2.0")
    assert alpha["capabilities"] == ["Issuer", "Wallet > Storage"]
    assert alpha["latest_release_date"].startswith("2026-03-04")
    # Scan findings are read live for the version the snapshot pinned.
    assert (alpha["dependency_count"], alpha["vulnerability_count"]) == (2, 2)

    exported = _export(admin, f"/v1/manifests/{saved['id']}/export", fmt="markdown")
    assert exported.headers["content-disposition"].endswith('"Release-review.md"')
    assert "| Alpha | Acme | library | 1.2.0 |" in exported.text
    renamed = _export(admin, f"/v1/manifests/{saved['id']}/export", name="x y")
    assert renamed.headers["content-disposition"].endswith('"x-y.json"')

    listed = ok(admin.get("/v1/manifests"))["items"]
    assert [
        (m["id"], m["item_count"], m["node_count"], m["project_count"]) for m in listed
    ] == [(saved["id"], 2, 1, 2)]
    assert listed[0]["created_by_username"]


def test_a_project_page_save_pins_one_version(catalogue):
    admin, alpha, fw = catalogue["admin"], catalogue["alpha"], catalogue["fw"]
    saved = ok(
        admin.post(
            f"/v1/projects/{alpha}/manifest/save",
            params={"framework_id": fw},
            json={"name": "alpha pin", "description": "  "},
            headers=csrf(admin),
        )
    )
    assert (saved["item_count"], saved["description"]) == (1, None)
    detail = ok(admin.get(f"/v1/manifests/{saved['id']}"))
    assert detail["filters"] == {
        "framework_id": fw,
        "project_ids": [alpha],
        "project_version_ids": [catalogue["alpha_v"]],
    }
    (row,) = detail["items"]
    assert row["capabilities"] == ["Issuer", "Wallet > Storage"]

    assert (
        admin.post(
            f"/v1/projects/{alpha}/manifest/save",
            params={"version_id": 999999},
            json={"name": "x"},
            headers=csrf(admin),
        ).status_code
        == 404
    )
    bare = make_project(admin, "bare")
    assert (
        admin.post(
            f"/v1/projects/{bare['id']}/manifest/save",
            json={"name": "x"},
            headers=csrf(admin),
        ).status_code
        == 404
    )


def test_deleting_the_pinned_version_keeps_the_snapshot_without_findings(catalogue):
    admin = catalogue["admin"]
    saved = ok(
        admin.post(
            "/v1/manifests",
            json={"name": "kept", "framework_id": catalogue["fw"]},
            headers=csrf(admin),
        )
    )
    ok(
        admin.delete(f"/v1/projects/{catalogue['alpha']}", headers=csrf(admin)),
        status=204,
    )
    items = {
        row["machine_name"]: row
        for row in ok(admin.get(f"/v1/manifests/{saved['id']}"))["items"]
    }
    alpha = items["alpha"]
    assert (alpha["project_id"], alpha["latest_version_id"]) == (None, None)
    assert alpha["latest_version"] == "1.2.0"
    assert alpha["capabilities"] == ["Issuer", "Wallet > Storage"]
    assert (alpha["dependency_count"], alpha["dependencies"]) == (0, [])
    # A row without a project still exports.
    text = _export(admin, f"/v1/manifests/{saved['id']}/export", fmt="markdown").text
    lines = text.splitlines()
    issuer, storage = catalogue["nodes"]["issuer"], catalogue["nodes"]["storage"]
    assert f"| Alpha | Acme | library | 1.2.0 | {issuer}, {storage} | 0 | 0 |" in lines
    # The matrix is keyed by project, so it lists the projects that remain.
    assert "| Capability Path | =Beta\\|Co |" in lines


# ---------------------------------------------------------------------------
# Who may do what.
# ---------------------------------------------------------------------------


def test_manifest_routes_need_the_manifest_permission(catalogue):
    viewer, _ = signed_in("viewer")
    admin = catalogue["admin"]
    saved = ok(admin.post("/v1/manifests", json={"name": "m"}, headers=csrf(admin)))
    calls = [
        viewer.get("/v1/manifests/export"),
        viewer.get(f"/v1/projects/{catalogue['alpha']}/manifest/export"),
        viewer.post(
            f"/v1/projects/{catalogue['alpha']}/manifest/save",
            json={"name": "x"},
            headers=csrf(viewer),
        ),
        viewer.post("/v1/manifests", json={"name": "x"}, headers=csrf(viewer)),
        viewer.get("/v1/manifests"),
        viewer.get(f"/v1/manifests/{saved['id']}"),
        viewer.get(f"/v1/manifests/{saved['id']}/export"),
        viewer.delete(f"/v1/manifests/{saved['id']}", headers=csrf(viewer)),
        viewer.patch(
            f"/v1/manifests/{saved['id']}/sharing",
            json={"is_public": True},
            headers=csrf(viewer),
        ),
        viewer.post(f"/v1/manifests/{saved['id']}/clone", headers=csrf(viewer)),
    ]
    assert [r.status_code for r in calls] == [403] * len(calls)
    with SessionLocal() as s:
        assert s.query(Manifest).count() == 1
        assert s.get(Manifest, saved["id"]).is_public is False


def test_a_private_manifest_is_its_owners_until_shared(catalogue, outbox):
    owner, owner_id = signed_in("architect")
    peer, peer_id = signed_in("product_owner", email="peer@x.test")
    outsider, _ = signed_in("architect")
    quiet, quiet_id = signed_in("viewer", email="quiet@x.test")
    team = make_group("Team", members=[owner_id, peer_id, quiet_id])
    elsewhere = make_group("Elsewhere", members=[peer_id])

    saved = ok(owner.post("/v1/manifests", json={"name": "plan"}, headers=csrf(owner)))
    mid = saved["id"]
    assert [m["id"] for m in ok(peer.get("/v1/manifests"))["items"]] == []
    assert peer.get(f"/v1/manifests/{mid}/export").status_code == 403
    assert (
        peer.post(f"/v1/manifests/{mid}/clone", headers=csrf(peer)).status_code == 403
    )
    assert peer.get(f"/v1/manifests/{mid}").status_code == 403

    # The owner shares only with a group they belong to, and it must exist.
    def share(client, **body):
        return client.patch(
            f"/v1/manifests/{mid}/sharing", json=body, headers=csrf(client)
        )

    assert share(owner, owner_group_id=elsewhere).status_code == 403
    assert share(catalogue["admin"], owner_group_id=999999).status_code == 400
    assert share(peer, owner_group_id=team).status_code == 403
    shared = ok(share(owner, owner_group_id=team))
    assert (shared["owner_group_id"], shared["owner_group_name"]) == (team, "Team")
    assert (shared["is_public"], shared["can_manage"]) == (False, True)
    # Members who can use manifests are told; the sharer and others are not.
    mails = [(m.recipient, m.subject) for m in outbox.messages()]
    assert [recipient for recipient, _ in mails] == ["peer@x.test"]
    assert "plan" in outbox.messages()[0].body

    listed = ok(peer.get("/v1/manifests"))["items"]
    assert [(m["id"], m["can_manage"], m["can_clone"]) for m in listed] == [
        (mid, False, True)
    ]
    assert listed[0]["owner_group_name"] == "Team"
    assert peer.get(f"/v1/manifests/{mid}/export").status_code == 200
    # Reading the editable detail, deleting and re-sharing stay the owner's.
    assert peer.get(f"/v1/manifests/{mid}").status_code == 403
    assert peer.delete(f"/v1/manifests/{mid}", headers=csrf(peer)).status_code == 403
    assert outsider.get(f"/v1/manifests/{mid}/export").status_code == 403

    # Re-saving the same group mails nobody again; unsharing closes it.
    ok(share(owner, owner_group_id=team))
    assert len(outbox.messages()) == 1
    ok(share(owner, owner_group_id=None))
    assert peer.get(f"/v1/manifests/{mid}/export").status_code == 403

    # Public opens it to everyone who can use manifests.
    assert ok(share(owner, is_public=True))["is_public"] is True
    assert outsider.get(f"/v1/manifests/{mid}/export").status_code == 200
    assert [m["id"] for m in ok(outsider.get("/v1/manifests"))["items"]] == [mid]
    # An explicit null leaves the flag as it is.
    assert ok(share(owner, is_public=None))["is_public"] is True

    assert owner.delete(f"/v1/manifests/{mid}", headers=csrf(owner)).status_code == 204
    assert owner.get(f"/v1/manifests/{mid}").status_code == 404
    assert owner.get(f"/v1/manifests/{mid}/export").status_code == 404


def test_saving_into_a_group_follows_the_same_membership_rule(catalogue):
    owner, owner_id = signed_in("architect")
    mine = make_group("Mine", members=[owner_id])
    theirs = make_group("Theirs")
    alpha = catalogue["alpha"]

    for path, params in (
        ("/v1/manifests", {}),
        (f"/v1/projects/{alpha}/manifest/save", {}),
    ):

        def save(client, group_id):
            return client.post(
                path,
                params=params,
                json={"name": "grouped", "owner_group_id": group_id},
                headers=csrf(client),
            )

        assert save(owner, theirs).status_code == 403
        assert save(owner, mine).json()["owner_group_id"] == mine
        assert save(catalogue["admin"], 999999).status_code == 400
        # An administrator may place a manifest in any group.
        assert save(catalogue["admin"], theirs).json()["owner_group_id"] == theirs


def test_a_copy_is_private_to_whoever_made_it(catalogue):
    owner, _ = signed_in("architect")
    reader, _ = signed_in("architect")
    saved = ok(
        owner.post(
            "/v1/manifests",
            json={
                "name": "source",
                "description": "original",
                "framework_id": catalogue["fw"],
            },
            headers=csrf(owner),
        )
    )
    ok(
        owner.patch(
            f"/v1/manifests/{saved['id']}/sharing",
            json={"is_public": True},
            headers=csrf(owner),
        )
    )

    copy = ok(reader.post(f"/v1/manifests/{saved['id']}/clone", headers=csrf(reader)))
    assert (copy["name"], copy["description"]) == ("source (copy)", "original")
    named = ok(
        reader.post(
            f"/v1/manifests/{saved['id']}/clone",
            json={"name": " mine ", "description": ""},
            headers=csrf(reader),
        )
    )
    assert (named["name"], named["description"]) == ("mine", "")
    blank = ok(
        reader.post(
            f"/v1/manifests/{saved['id']}/clone",
            json={"name": "   "},
            headers=csrf(reader),
        )
    )
    assert blank["name"] == "source (copy)"

    detail = ok(reader.get(f"/v1/manifests/{copy['id']}"))
    assert (detail["is_public"], detail["owner_group_id"]) == (False, None)
    assert detail["can_manage"] is True
    original = ok(owner.get(f"/v1/manifests/{saved['id']}"))

    def carried(rows):
        return [
            (
                row["machine_name"],
                row["display_name"],
                row["latest_version"],
                row["latest_version_id"],
                row["capability_ids"],
                row["capabilities"],
                row["dependency_count"],
            )
            for row in rows
        ]

    assert carried(detail["items"]) == carried(original["items"])
    assert len(detail["items"]) == 2
    # The copy is the reader's alone, and deleting it leaves the source.
    assert owner.get(f"/v1/manifests/{copy['id']}").status_code == 403
    ok(reader.delete(f"/v1/manifests/{copy['id']}", headers=csrf(reader)), status=204)
    assert len(ok(owner.get(f"/v1/manifests/{saved['id']}"))["items"]) == 2
    assert (
        reader.post("/v1/manifests/999999/clone", headers=csrf(reader)).status_code
        == 404
    )


def test_manifest_routes_answer_404_while_the_feature_is_off(catalogue, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "feature_manifests", False)
    admin = catalogue["admin"]
    assert admin.get("/v1/manifests").status_code == 404
    assert admin.get("/v1/manifests/export").status_code == 404
    assert (
        admin.get(f"/v1/projects/{catalogue['alpha']}/manifest/export").status_code
        == 404
    )


def test_release_dates_survive_the_snapshot_round_trip(catalogue):
    admin = catalogue["admin"]
    saved = ok(
        admin.post(
            "/v1/manifests",
            json={"name": "dates", "project_ids": [catalogue["alpha"]]},
            headers=csrf(admin),
        )
    )
    with SessionLocal() as s:
        (item,) = s.get(Manifest, saved["id"]).items
        version = s.get(ProjectVersion, catalogue["alpha_v"])
        assert item.latest_release_date == version.release_date == datetime(2026, 3, 4)
