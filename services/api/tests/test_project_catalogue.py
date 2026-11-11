"""The project catalogue as its readers and maintainers use it: listing and
filtering, comparison, the capability graph, framework mappings, the
changelog, subscriptions and who owns what."""

from __future__ import annotations

import pytest
from app.db.models import Organisation, Project, ProjectSubscription, ProjectVersion
from app.db.session import SessionLocal

from tests.support import (
    csrf,
    make_framework,
    make_group,
    make_node,
    make_project,
    make_version,
    map_nodes,
    ok,
    signed_in,
)


@pytest.fixture()
def admin():
    client, _ = signed_in("admin")
    return client


@pytest.fixture()
def taxonomy(admin):
    fw = make_framework(admin)
    wallet = make_node(admin, fw["id"], "wallet", sort_order=2)
    storage = make_node(admin, fw["id"], "storage", parent_id=wallet["id"])
    keys = make_node(admin, fw["id"], "keys", parent_id=storage["id"])
    issuer = make_node(admin, fw["id"], "issuer", sort_order=1)
    return {
        "fw": fw["id"],
        "wallet": wallet["id"],
        "storage": storage["id"],
        "keys": keys["id"],
        "issuer": issuer["id"],
    }


# ---------------------------------------------------------------------------
# Listing and reading.
# ---------------------------------------------------------------------------


def test_listing_reports_each_projects_latest_version_and_its_capabilities(
    admin, taxonomy
):
    alpha = make_project(admin, "alpha", programming_languages=["Go", "go", " "])
    make_version(admin, alpha["id"], "1.0.0", status="stable")
    newest = make_version(admin, alpha["id"], "1.1.0", status="beta")
    map_nodes(admin, newest["id"], taxonomy["fw"], [taxonomy["keys"]])
    make_project(admin, "empty")

    body = ok(admin.get("/v1/projects", params={"framework_id": taxonomy["fw"]}))
    assert body["framework"]["machine_name"] == "tax"
    items = {p["machine_name"]: p for p in body["items"]}
    assert list(items) == ["alpha", "empty"]
    assert items["alpha"]["latest_version"]["version"] == "1.1.0"
    assert items["alpha"]["capability_paths"] == ["Wallet > Storage > Keys"]
    # Tags are de-duplicated without regard to case.
    assert items["alpha"]["programming_languages"] == ["Go"]
    assert items["empty"]["latest_version"] is None
    assert items["empty"]["capability_paths"] == []

    def names(**params):
        params.setdefault("framework_id", taxonomy["fw"])
        return [
            p["machine_name"]
            for p in ok(admin.get("/v1/projects", params=params))["items"]
        ]

    # A node selects projects whose Latest version maps to it or below it.
    assert names(node_ids=str(taxonomy["wallet"])) == ["alpha"]
    assert names(capability_ids=str(taxonomy["issuer"])) == []
    assert names(statuses="beta") == ["alpha"]
    assert names(statuses="stable") == []  # 1.0.0 is no longer Latest
    assert names(languages="Go") == ["alpha"]
    assert names(project_ids=str(items["empty"]["id"])) == ["empty"]
    assert names(q="EMP") == ["empty"]
    # The default framework is UWRA, where nothing here is mapped.
    assert ok(admin.get("/v1/projects"))["framework"]["machine_name"] == "uwra"
    assert admin.get("/v1/projects", params={"framework_id": 999999}).status_code == 404


def test_a_csv_filter_is_bounded_and_ignores_what_is_not_an_id(admin):
    from app.api.routes.projects import _normalize_csv_ints

    assert _normalize_csv_ints(None) == []
    assert _normalize_csv_ints("3, x, -1, 0, 3, ,7") == [3, 7]
    huge = ",".join(str(n) for n in range(1, 5000))
    assert _normalize_csv_ints(huge) == list(range(1, 1001))
    # The route accepts the oversized list without building an oversized query.
    make_project(admin, "one")
    assert (
        len(ok(admin.get("/v1/projects", params={"project_ids": huge}))["items"]) == 1
    )


def test_project_detail_orders_versions_and_hides_drafts_from_other_readers(
    admin, taxonomy
):
    project = make_project(admin, "alpha")
    pid = project["id"]
    make_version(admin, pid, "1.0.0", release_date="2026-01-01")
    latest = make_version(admin, pid, "2.0.0", release_date="2026-02-01")
    make_version(admin, pid, "0.9.0", release_date="2025-06-01", is_latest=False)
    make_version(admin, pid, "3.0.0-rc1", is_draft=True)
    map_nodes(admin, latest["id"], taxonomy["fw"], [taxonomy["issuer"]])

    detail = ok(
        admin.get(f"/v1/projects/{pid}", params={"framework_id": taxonomy["fw"]})
    )
    # Drafts first, then Latest, then the rest newest first.
    assert [v["version"] for v in detail["versions"]] == [
        "3.0.0-rc1",
        "2.0.0",
        "1.0.0",
        "0.9.0",
    ]
    assert detail["can_view_drafts"] is True
    assert detail["latest_version"]["version"] == "2.0.0"
    assert detail["capability_paths"] == ["Issuer"]
    by_version = {v["version"]: v for v in detail["versions"]}
    assert by_version["2.0.0"]["capability_paths"] == ["Issuer"]
    assert by_version["1.0.0"]["capability_paths"] == []

    viewer, _ = signed_in("viewer")
    seen = ok(viewer.get(f"/v1/projects/{pid}"))
    assert seen["can_view_drafts"] is False
    assert [v["version"] for v in seen["versions"]] == ["2.0.0", "1.0.0", "0.9.0"]
    listed = ok(viewer.get(f"/v1/projects/{pid}/versions"))
    assert [v["version"] for v in listed["items"]] == ["2.0.0", "1.0.0", "0.9.0"]
    assert len(ok(admin.get(f"/v1/projects/{pid}/versions"))["items"]) == 4
    assert viewer.get("/v1/projects/999999").status_code == 404
    assert viewer.get("/v1/projects/999999/versions").status_code == 404


def test_latest_falls_to_the_greatest_version_when_none_is_marked(admin):
    pid = make_project(admin, "alpha")["id"]
    for label in ("1.2.0", "1.10.0", "1.9.0"):
        make_version(admin, pid, label, is_latest=False)
    with SessionLocal() as s:
        s.query(ProjectVersion).update({ProjectVersion.is_latest: False})
        s.commit()
    assert ok(admin.get(f"/v1/projects/{pid}"))["latest_version"]["version"] == "1.10.0"

    # Labels that are not versions fall back to the most recent release.
    other = make_project(admin, "named")["id"]
    make_version(admin, other, "bookworm", release_date="2026-01-01", is_latest=False)
    make_version(admin, other, "trixie", release_date="2026-06-01", is_latest=False)
    with SessionLocal() as s:
        s.query(ProjectVersion).update({ProjectVersion.is_latest: False})
        s.commit()
    assert (
        ok(admin.get(f"/v1/projects/{other}"))["latest_version"]["version"] == "trixie"
    )


# ---------------------------------------------------------------------------
# Creating and updating.
# ---------------------------------------------------------------------------


def test_machine_names_and_version_labels_are_unique(admin):
    pid = make_project(admin, "alpha")["id"]
    clash = admin.post(
        "/v1/projects",
        json={"machine_name": " alpha ", "display_name": "Again"},
        headers=csrf(admin),
    )
    assert clash.status_code == 409
    first = make_version(admin, pid, "1.0.0")
    second = make_version(admin, pid, "2.0.0")
    clash = admin.post(
        f"/v1/projects/{pid}/versions", json={"version": " 1.0.0 "}, headers=csrf(admin)
    )
    assert clash.status_code == 409
    clash = admin.put(
        f"/v1/project-versions/{second['id']}",
        json={"version": "1.0.0"},
        headers=csrf(admin),
    )
    assert clash.status_code == 409
    # Renaming a version to its own label is not a clash.
    same = ok(
        admin.put(
            f"/v1/project-versions/{first['id']}",
            json={"version": " 1.0.0 ", "notes": "kept"},
            headers=csrf(admin),
        )
    )
    assert (same["version"], same["notes"]) == ("1.0.0", "kept")
    assert (
        admin.put(
            "/v1/project-versions/999999", json={"notes": "x"}, headers=csrf(admin)
        ).status_code
        == 404
    )
    with SessionLocal() as s:
        assert s.query(Project).count() == 1
        assert s.query(ProjectVersion).count() == 2


def test_organisations_are_recorded_once_and_followed_by_id(admin):
    first = make_project(admin, "one", organisation=" Acme ")
    second = make_project(admin, "two", organisation="Acme")
    assert first["organisation"] == second["organisation"] == "Acme"
    assert first["organisation_id"] == second["organisation_id"]
    with SessionLocal() as s:
        assert s.query(Organisation).count() == 1
        other = Organisation(name="Globex")
        s.add(other)
        s.commit()
        globex = other.id

    by_id = make_project(admin, "three", organisation_id=globex)
    assert (by_id["organisation"], by_id["organisation_id"]) == ("Globex", globex)
    unknown = admin.post(
        "/v1/projects",
        json={"machine_name": "four", "display_name": "Four", "organisation_id": 999},
        headers=csrf(admin),
    )
    assert unknown.status_code == 400

    moved = ok(
        admin.put(
            f"/v1/projects/{first['id']}",
            json={"organisation_id": globex},
            headers=csrf(admin),
        )
    )
    assert (moved["organisation"], moved["organisation_id"]) == ("Globex", globex)
    cleared = ok(
        admin.put(
            f"/v1/projects/{first['id']}",
            json={"organisation": ""},
            headers=csrf(admin),
        )
    )
    assert (cleared["organisation"], cleared["organisation_id"]) == (None, None)
    renamed = ok(
        admin.put(
            f"/v1/projects/{first['id']}",
            json={"organisation": "Initech"},
            headers=csrf(admin),
        )
    )
    assert renamed["organisation"] == "Initech"
    with SessionLocal() as s:
        assert {o.name for o in s.query(Organisation)} == {"Acme", "Globex", "Initech"}


def test_update_cleans_tags_and_reports_the_latest_versions_capabilities(
    admin, taxonomy
):
    pid = make_project(admin, "alpha")["id"]
    version = make_version(admin, pid, "1.0.0")
    ok(admin.get("/v1/frameworks"))  # the default framework is seeded on first use
    with SessionLocal() as s:
        from app.db.models import Framework, FrameworkNode

        uwra = s.query(Framework).filter_by(machine_name="uwra").one()
        node = (
            s.query(FrameworkNode)
            .filter_by(framework_id=uwra.id)
            .order_by(FrameworkNode.level.desc(), FrameworkNode.id)
            .first()
        )
        uwra_id, node_id = uwra.id, node.id
    map_nodes(admin, version["id"], uwra_id, [node_id])

    updated = ok(
        admin.put(
            f"/v1/projects/{pid}",
            json={
                "supported_formats": ["SD-JWT", "sd-jwt", ""],
                "programming_languages": ["Rust"],
                "release_rss_ignore_patterns": [
                    {"pattern": "rc", "match_type": "contains"}
                ],
            },
            headers=csrf(admin),
        )
    )
    assert updated["supported_formats"] == ["SD-JWT"]
    assert updated["programming_languages"] == ["Rust"]
    assert [r["pattern"] for r in updated["release_rss_ignore_patterns"]] == ["rc"]
    # The response carries the default framework's paths for the Latest version.
    assert len(updated["capability_paths"]) == 1
    assert updated["latest_version"]["version"] == "1.0.0"


def test_unmarking_latest_hands_the_marker_to_the_best_remaining_version(admin):
    pid = make_project(admin, "alpha")["id"]
    old = make_version(admin, pid, "1.0.0")
    new = make_version(admin, pid, "2.0.0")
    assert new["is_latest"] is True

    ok(
        admin.put(
            f"/v1/project-versions/{old['id']}",
            json={"is_latest": True},
            headers=csrf(admin),
        )
    )
    unmarked = ok(
        admin.put(
            f"/v1/project-versions/{old['id']}",
            json={"is_latest": False},
            headers=csrf(admin),
        )
    )
    assert unmarked["is_latest"] is False
    with SessionLocal() as s:
        marks = {v.version: v.is_latest for v in s.query(ProjectVersion)}
    assert marks == {"1.0.0": False, "2.0.0": True}

    # Turning the Latest version into a draft does the same.
    drafted = ok(
        admin.put(
            f"/v1/project-versions/{new['id']}",
            json={"is_draft": True},
            headers=csrf(admin),
        )
    )
    assert (drafted["is_draft"], drafted["is_latest"]) == (True, False)
    with SessionLocal() as s:
        marks = {v.version: v.is_latest for v in s.query(ProjectVersion)}
    assert marks == {"1.0.0": True, "2.0.0": False}


def test_a_new_version_inherits_the_latest_versions_mappings(admin, taxonomy):
    pid = make_project(admin, "alpha")["id"]
    first = make_version(admin, pid, "1.0.0")
    map_nodes(
        admin, first["id"], taxonomy["fw"], [taxonomy["keys"], taxonomy["issuer"]]
    )
    second = make_version(admin, pid, "1.1.0")
    got = ok(
        admin.get(
            f"/v1/project-versions/{second['id']}/framework-nodes",
            params={"framework_id": taxonomy["fw"]},
        )
    )
    assert got["node_ids"] == sorted([taxonomy["keys"], taxonomy["issuer"]])


# ---------------------------------------------------------------------------
# Ownership.
# ---------------------------------------------------------------------------


def test_group_members_manage_what_their_group_owns(admin):
    owner, owner_id = signed_in("maintainer")
    colleague, colleague_id = signed_in("maintainer")
    stranger, _ = signed_in("maintainer")
    team = make_group("Team", members=[owner_id, colleague_id])

    project = make_project(owner, "shared")
    assert project["owner_group_ids"] == [team]
    pid = project["id"]
    draft = make_version(owner, pid, "1.0.0", is_draft=True)

    # A colleague in the owning group edits, sees drafts and deletes versions.
    ok(
        colleague.put(
            f"/v1/projects/{pid}", json={"license": "MIT"}, headers=csrf(colleague)
        )
    )
    assert ok(colleague.get(f"/v1/projects/{pid}"))["can_view_drafts"] is True
    assert ok(stranger.get(f"/v1/projects/{pid}"))["can_view_drafts"] is False
    for call in (
        stranger.put(
            f"/v1/projects/{pid}", json={"license": "GPL"}, headers=csrf(stranger)
        ),
        stranger.post(
            f"/v1/projects/{pid}/versions",
            json={"version": "9"},
            headers=csrf(stranger),
        ),
        stranger.put(
            f"/v1/project-versions/{draft['id']}",
            json={"notes": "x"},
            headers=csrf(stranger),
        ),
        stranger.delete(f"/v1/project-versions/{draft['id']}", headers=csrf(stranger)),
        stranger.delete(f"/v1/projects/{pid}", headers=csrf(stranger)),
    ):
        assert call.status_code == 403
    with SessionLocal() as s:
        assert s.get(Project, pid).license == "MIT"
    ok(
        colleague.delete(
            f"/v1/project-versions/{draft['id']}", headers=csrf(colleague)
        ),
        204,
    )
    ok(colleague.delete(f"/v1/projects/{pid}", headers=csrf(colleague)), 204)
    assert admin.delete(f"/v1/projects/{pid}", headers=csrf(admin)).status_code == 404


# ---------------------------------------------------------------------------
# Framework mappings.
# ---------------------------------------------------------------------------


def test_mappings_are_kept_per_framework_and_validated(admin, taxonomy):
    pid = make_project(admin, "alpha")["id"]
    version = make_version(admin, pid, "1.0.0")
    vid = version["id"]
    other = make_framework(admin, "other", "Other")
    foreign = make_node(admin, other["id"], "foreign")

    mapped = map_nodes(admin, vid, taxonomy["fw"], [taxonomy["keys"], taxonomy["keys"]])
    assert mapped["node_ids"] == [taxonomy["keys"]]
    assert mapped["nodes"] == [
        {
            "id": taxonomy["keys"],
            "key": "keys",
            "display_name": "Keys",
            "parent_id": taxonomy["storage"],
            "level": 2,
            "path": "Wallet > Storage > Keys",
        }
    ]
    map_nodes(admin, vid, other["id"], [foreign["id"]])
    # Replacing one framework's mapping leaves the other's alone.
    map_nodes(admin, vid, taxonomy["fw"], [taxonomy["issuer"]])
    assert ok(
        admin.get(
            f"/v1/project-versions/{vid}/framework-nodes",
            params={"framework_id": other["id"]},
        )
    )["node_ids"] == [foreign["id"]]
    assert ok(
        admin.get(
            f"/v1/project-versions/{vid}/capabilities",
            params={"framework_id": taxonomy["fw"]},
        )
    )["node_ids"] == [taxonomy["issuer"]]

    crossed = admin.put(
        f"/v1/project-versions/{vid}/framework-nodes",
        json={"framework_id": taxonomy["fw"], "node_ids": [foreign["id"]]},
        headers=csrf(admin),
    )
    assert crossed.status_code == 400
    assert str(foreign["id"]) in crossed.json()["detail"]
    # The older route takes a comma-separated list.
    legacy = ok(
        admin.put(
            f"/v1/project-versions/{vid}/capabilities",
            json={
                "framework_id": taxonomy["fw"],
                "node_ids": f"{taxonomy['wallet']}, {taxonomy['issuer']}",
            },
            headers=csrf(admin),
        )
    )
    assert legacy["node_ids"] == sorted([taxonomy["wallet"], taxonomy["issuer"]])
    cleared = map_nodes(admin, vid, taxonomy["fw"], [])
    assert (cleared["node_ids"], cleared["nodes"]) == ([], [])

    # The changelog names the nodes a mapping change added.
    log = ok(admin.get(f"/v1/project-versions/{vid}/changelog"))
    fields = [c["field"] for entry in log["items"] for c in entry["changes"]]
    assert "capability_nodes" in fields


def test_mapping_needs_ownership_and_drafts_stay_private(admin, taxonomy):
    owner, _ = signed_in("maintainer")
    pid = make_project(owner, "alpha")["id"]
    draft = make_version(owner, pid, "1.0.0", is_draft=True)
    other, _ = signed_in("maintainer")
    refused = other.put(
        f"/v1/project-versions/{draft['id']}/framework-nodes",
        json={"framework_id": taxonomy["fw"], "node_ids": [taxonomy["issuer"]]},
        headers=csrf(other),
    )
    assert refused.status_code == 403
    for path in ("framework-nodes", "capabilities", "changelog"):
        assert (
            other.get(f"/v1/project-versions/{draft['id']}/{path}").status_code == 403
        )
        assert (
            owner.get(f"/v1/project-versions/{draft['id']}/{path}").status_code == 200
        )
    assert owner.get("/v1/project-versions/999999/framework-nodes").status_code == 404
    assert owner.get("/v1/project-versions/999999/changelog").status_code == 404


# ---------------------------------------------------------------------------
# Graph.
# ---------------------------------------------------------------------------


def test_the_graph_links_project_version_and_the_selected_branch(admin, taxonomy):
    project = make_project(admin, "alpha", display_name="Alpha")
    pid = project["id"]
    empty = ok(
        admin.get(f"/v1/projects/{pid}/graph", params={"framework_id": taxonomy["fw"]})
    )
    assert empty["version"] is None
    assert [n["id"] for n in empty["nodes"]] == [f"project:{pid}"]
    assert (empty["links"], empty["capability_tree"]) == ([], [])

    version = make_version(admin, pid, "1.0.0")
    map_nodes(
        admin, version["id"], taxonomy["fw"], [taxonomy["keys"], taxonomy["issuer"]]
    )
    graph = ok(
        admin.get(f"/v1/projects/{pid}/graph", params={"framework_id": taxonomy["fw"]})
    )
    vid = version["id"]
    assert graph["version"]["version"] == "1.0.0"
    nodes = {n["id"]: n for n in graph["nodes"]}
    # Ancestors of a selected node are drawn but not marked selected.
    assert {k: (v["label"], v["level"], v["selected"]) for k, v in nodes.items()} == {
        f"project:{pid}": ("Alpha", 0, True),
        f"version:{vid}": ("1.0.0", 1, True),
        f"node:{taxonomy['issuer']}": ("Issuer", 2, True),
        f"node:{taxonomy['wallet']}": ("Wallet", 2, False),
        f"node:{taxonomy['storage']}": ("Storage", 3, False),
        f"node:{taxonomy['keys']}": ("Keys", 4, True),
    }
    assert {(link["source"], link["target"]) for link in graph["links"]} == {
        (f"project:{pid}", f"version:{vid}"),
        (f"version:{vid}", f"node:{taxonomy['issuer']}"),
        (f"version:{vid}", f"node:{taxonomy['wallet']}"),
        (f"node:{taxonomy['wallet']}", f"node:{taxonomy['storage']}"),
        (f"node:{taxonomy['storage']}", f"node:{taxonomy['keys']}"),
    }
    # Roots follow their sort order: Issuer (1) before Wallet (2).
    assert [root["key"] for root in graph["capability_tree"]] == ["issuer", "wallet"]
    assert graph["capability_tree"][1]["children"][0]["children"][0]["selected"] is True


def test_the_graph_serves_a_chosen_version_and_guards_drafts(admin, taxonomy):
    pid = make_project(admin, "alpha")["id"]
    old = make_version(admin, pid, "1.0.0")
    make_version(admin, pid, "2.0.0")
    draft = make_version(admin, pid, "3.0.0", is_draft=True)
    base = f"/v1/projects/{pid}/graph"
    assert ok(admin.get(base))["version"]["version"] == "2.0.0"
    assert (
        ok(admin.get(base, params={"version_id": old["id"]}))["version"]["version"]
        == "1.0.0"
    )
    assert (
        ok(admin.get(base, params={"version_id": draft["id"]}))["version"]["is_draft"]
        is True
    )
    assert admin.get(base, params={"version_id": 999999}).status_code == 404
    viewer, _ = signed_in("viewer")
    assert viewer.get(base, params={"version_id": draft["id"]}).status_code == 403
    assert ok(viewer.get(base))["version"]["version"] == "2.0.0"

    # A project with only a draft shows it to its owner and nothing to others.
    solo = make_project(admin, "solo")["id"]
    make_version(admin, solo, "0.1.0", is_draft=True)
    assert ok(admin.get(f"/v1/projects/{solo}/graph"))["version"]["version"] == "0.1.0"
    assert ok(viewer.get(f"/v1/projects/{solo}/graph"))["version"] is None


# ---------------------------------------------------------------------------
# Comparison.
# ---------------------------------------------------------------------------


def test_comparison_diffs_two_projects_at_the_chosen_versions(admin, taxonomy):
    left = make_project(admin, "left", license="MIT")["id"]
    right = make_project(admin, "right", license="Apache-2.0")["id"]
    left_old = make_version(admin, left, "1.0.0")
    left_new = make_version(admin, left, "2.0.0")
    right_v = make_version(admin, right, "5.0.0")
    map_nodes(admin, left_new["id"], taxonomy["fw"], [taxonomy["keys"]])
    map_nodes(
        admin, right_v["id"], taxonomy["fw"], [taxonomy["issuer"], taxonomy["keys"]]
    )

    engineer, _ = signed_in("engineer")
    params = {
        "left_project_id": left,
        "right_project_id": right,
        "framework_id": taxonomy["fw"],
    }
    body = ok(engineer.get("/v1/projects/compare", params=params))
    assert body["left"]["latest_version"]["version"] == "2.0.0"
    assert body["left"]["capability_paths"] == ["Wallet > Storage > Keys"]
    assert body["right"]["capability_paths"] == ["Issuer", "Wallet > Storage > Keys"]
    diff = body["diff"]
    assert f"--- project:{left}" in diff and f"+++ project:{right}" in diff
    assert '-  "license": "MIT",' in diff
    assert '+  "license": "Apache-2.0",' in diff
    assert '+    "Issuer",' in diff

    pinned = ok(
        engineer.get(
            "/v1/projects/compare", params={**params, "left_version_id": left_old["id"]}
        )
    )
    assert pinned["left"]["latest_version"]["version"] == "1.0.0"
    # A version id belonging to the other project selects nothing.
    crossed = ok(
        engineer.get(
            "/v1/projects/compare", params={**params, "left_version_id": right_v["id"]}
        )
    )
    assert crossed["left"]["latest_version"] is None
    assert crossed["left"]["capability_paths"] == []

    assert (
        engineer.get(
            "/v1/projects/compare", params={**params, "right_project_id": 999999}
        ).status_code
        == 404
    )
    viewer, _ = signed_in("viewer")
    assert viewer.get("/v1/projects/compare", params=params).status_code == 403


def test_comparison_never_shows_a_draft_to_someone_who_cannot_see_both_sides(admin):
    owner, _ = signed_in("maintainer")
    mine = make_project(owner, "mine")["id"]
    theirs = make_project(admin, "theirs")["id"]
    make_version(owner, mine, "1.0.0")
    draft = make_version(owner, mine, "2.0.0", is_draft=True)
    make_version(admin, theirs, "1.0.0")
    params = {"left_project_id": mine, "right_project_id": theirs}

    engineer, _ = signed_in("engineer")
    seen = ok(
        engineer.get(
            "/v1/projects/compare", params={**params, "left_version_id": draft["id"]}
        )
    )
    assert seen["left"]["latest_version"] is None
    assert (
        ok(engineer.get("/v1/projects/compare", params=params))["left"][
            "latest_version"
        ]["version"]
        == "1.0.0"
    )
    # An administrator sees both sides' drafts.
    full = ok(
        admin.get(
            "/v1/projects/compare", params={**params, "left_version_id": draft["id"]}
        )
    )
    assert full["left"]["latest_version"]["version"] == "2.0.0"


def test_comparison_is_absent_while_the_feature_is_off(admin, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "feature_comparisons", False)
    assert (
        admin.get(
            "/v1/projects/compare", params={"left_project_id": 1, "right_project_id": 2}
        ).status_code
        == 404
    )


# ---------------------------------------------------------------------------
# Changelog.
# ---------------------------------------------------------------------------


def test_the_project_changelog_records_who_changed_what(admin):
    pid = make_project(admin, "alpha", license="MIT")["id"]
    ok(
        admin.put(
            f"/v1/projects/{pid}", json={"license": "Apache-2.0"}, headers=csrf(admin)
        )
    )
    ok(
        admin.put(
            f"/v1/projects/{pid}", json={"license": "Apache-2.0"}, headers=csrf(admin)
        )
    )
    log = ok(admin.get(f"/v1/projects/{pid}/changelog"))
    actions = [entry["action"] for entry in log["items"]]
    # Newest first; a save that changes nothing records nothing.
    assert actions == ["updated", "created"]
    assert log["total"] == 2
    update = log["items"][0]
    assert update["changes"] == [
        {"field": "license", "label": "License", "before": "MIT", "after": "Apache-2.0"}
    ]
    assert update["request_method"] == "PUT"
    assert update["request_path"] == f"/v1/projects/{pid}"
    assert update["changed_by_username"]

    page = ok(
        admin.get(f"/v1/projects/{pid}/changelog", params={"limit": 1, "offset": 1})
    )
    assert [e["action"] for e in page["items"]] == ["created"]
    assert (page["limit"], page["offset"], page["total"]) == (1, 1, 2)
    assert admin.get("/v1/projects/999999/changelog").status_code == 404

    version = make_version(admin, pid, "1.0.0")
    ok(
        admin.put(
            f"/v1/project-versions/{version['id']}",
            json={"status": "stable"},
            headers=csrf(admin),
        )
    )
    ok(admin.delete(f"/v1/project-versions/{version['id']}", headers=csrf(admin)), 204)
    with SessionLocal() as s:
        from app.db.models import EntityChangelog

        actions = {
            e.action
            for e in s.query(EntityChangelog).filter_by(
                entity_type="project_version", entity_id=version["id"]
            )
        }
    assert actions == {"created", "updated", "deleted"}


# ---------------------------------------------------------------------------
# Subscriptions.
# ---------------------------------------------------------------------------


def test_subscriptions_follow_the_chosen_notices(admin):
    pid = make_project(admin, "alpha")["id"]
    reader, reader_id = signed_in("viewer", email="reader@x.test")
    path = f"/v1/projects/{pid}/subscription"
    off = {"subscribed": False, "notify_new_versions": False, "notify_questions": False}
    assert ok(reader.get(path)) == off

    # Subscribing with no choices means new versions only.
    assert ok(reader.post(path, headers=csrf(reader))) == {
        "subscribed": True,
        "notify_new_versions": True,
        "notify_questions": False,
    }
    assert ok(reader.get(f"/v1/projects/{pid}"))["is_subscribed"] is True
    changed = ok(
        reader.post(
            path,
            json={"notify_new_versions": False, "notify_questions": True},
            headers=csrf(reader),
        )
    )
    assert changed == {
        "subscribed": True,
        "notify_new_versions": False,
        "notify_questions": True,
    }
    assert ok(reader.get(path)) == changed
    with SessionLocal() as s:
        assert s.query(ProjectSubscription).filter_by(user_id=reader_id).count() == 1

    # Deselecting every notice removes the subscription.
    assert (
        ok(
            reader.post(
                path,
                json={"notify_new_versions": False, "notify_questions": False},
                headers=csrf(reader),
            )
        )
        == off
    )
    with SessionLocal() as s:
        assert s.query(ProjectSubscription).count() == 0

    ok(reader.post(path, headers=csrf(reader)))
    ok(reader.delete(path, headers=csrf(reader)), 204)
    assert ok(reader.get(path)) == off
    for call in (reader.get, reader.delete, reader.post):
        kwargs = {} if call is reader.get else {"headers": csrf(reader)}
        assert call("/v1/projects/999999/subscription", **kwargs).status_code == 404


def test_subscribing_needs_an_address_to_mail(admin):
    pid = make_project(admin, "alpha")["id"]
    nameless, _ = signed_in("viewer")
    with SessionLocal() as s:
        from app.db.models import User

        s.query(User).filter(User.email.isnot(None)).update({User.email: None})
        s.commit()
    refused = nameless.post(f"/v1/projects/{pid}/subscription", headers=csrf(nameless))
    assert refused.status_code == 400
    with SessionLocal() as s:
        assert s.query(ProjectSubscription).count() == 0
