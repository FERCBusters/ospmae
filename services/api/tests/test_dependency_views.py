"""What the catalogue shows of scan results: a version's dependency tree, the
cross-project graphs, capability and dependency detail, the dashboard, and
who may start a scan."""

from __future__ import annotations

import pytest
from app.api.routes.dependencies import _dependency_namespace
from app.core.config import settings
from app.db.models import ProjectVersion, ProjectVersionDependency
from app.db.session import SessionLocal

from tests.support import (
    SOURCE,
    csrf,
    make_framework,
    make_group,
    make_node,
    make_project,
    make_version,
    map_nodes,
    ok,
    record_dependency,
    set_scan_state,
    signed_in,
)


class _ScanTask:
    launched: list[int] = []
    refuse = False

    @classmethod
    def apply_async(cls, args, **_options):
        if cls.refuse:
            raise ConnectionError("broker unavailable")
        cls.launched.append(int(args[0]))


@pytest.fixture()
def scans(monkeypatch):
    from app.tasks import dependency_discovery

    _ScanTask.launched = []
    _ScanTask.refuse = False
    monkeypatch.setattr(
        dependency_discovery, "discover_project_version_dependencies", _ScanTask
    )
    return _ScanTask


@pytest.fixture()
def admin():
    client, _ = signed_in("admin")
    return client


@pytest.fixture()
def scanned(admin):
    """One project whose Latest version has dependencies in four ecosystems."""
    project = make_project(admin, "alpha", display_name="Alpha")
    version = make_version(admin, project["id"], "1.0.0")
    vid = version["id"]
    ids = {
        "confirm": record_dependency(
            vid,
            "npm",
            "@inquirer/confirm",
            "5.1.21",
            vulnerabilities=[("CVE-1", "critical", "5.2.0"), ("GHSA-2", "low", None)],
        ),
        "lodash": record_dependency(vid, "npm", "lodash", "4.17.21", indirect=True),
        "console": record_dependency(vid, "composer", "symfony/console", "7.0"),
        "guava": record_dependency(vid, "maven", "com.google:guava", "33"),
        "bare": record_dependency(vid, "pypi", "requests", ""),
    }
    return {"project": project["id"], "version": vid, "ids": ids}


# ---------------------------------------------------------------------------
# A version's dependency graph.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("npm", "@scope/pkg", "@scope"),
        ("NPM", "lodash", "(unscoped)"),
        ("npm", " @scope/pkg", "@scope"),
        ("npm", "a@b/c", "(unscoped)"),
        ("composer", "vendor/package", "vendor"),
        ("packagist", "solo", "(root)"),
        ("maven", "org.example:artifact", "org.example"),
        ("gradle", "artifact", "(root)"),
        ("go", "github.com/pkg/errors", "github.com"),
        ("pypi", "requests", "(root)"),
        ("pypi", "", "(unknown)"),
    ],
)
def test_packages_group_under_their_scope_vendor_or_group(ecosystem, name, expected):
    assert _dependency_namespace(ecosystem, name) == expected


def test_dependency_graph_groups_by_ecosystem_and_namespace(admin, scanned):
    body = ok(admin.get(f"/v1/projects/{scanned['project']}/dependency-graph"))
    assert body["project"]["name"] == "Alpha"
    assert body["version"]["version"] == "1.0.0"
    assert body["summary"] == {
        "dependency_count": 5,
        "vulnerability_count": 2,
        "ecosystems": {"npm": 2, "composer": 1, "maven": 1, "pypi": 1},
        "namespaces": {
            "npm": {"@inquirer": 1, "(unscoped)": 1},
            "composer": {"symfony": 1},
            "maven": {"com.google": 1},
            "pypi": {"(root)": 1},
        },
    }

    root = body["dependency_tree"]
    assert root["name"] == "Alpha"
    (version_node,) = root["children"]
    assert version_node["name"] == "1.0.0"
    ecosystems = {eco["name"]: eco for eco in version_node["children"]}
    assert list(ecosystems) == ["composer", "maven", "npm", "pypi"]
    npm = {ns["name"]: ns["children"] for ns in ecosystems["npm"]["children"]}
    # Inside its scope a package is shown without the scope prefix.
    (confirm,) = npm["@inquirer"]
    assert confirm["name"] == "confirm@5.1.21"
    assert confirm["package"] == "@inquirer/confirm"
    assert (confirm["vulnerability_count"], confirm["is_indirect"]) == (2, False)
    assert confirm["dependency_version_id"] == scanned["ids"]["confirm"]
    assert npm["(unscoped)"][0]["name"] == "lodash@4.17.21"
    assert npm["(unscoped)"][0]["is_indirect"] is True
    assert ecosystems["composer"]["children"][0]["children"][0]["name"] == "console@7.0"
    assert (
        ecosystems["maven"]["children"][0]["children"][0]["name"]
        == "com.google:guava@33"
    )
    # A dependency without a recorded version is labelled by name alone.
    assert ecosystems["pypi"]["children"][0]["children"][0]["name"] == "requests"

    flat = {d["name"]: d for d in body["dependencies"]}
    assert flat["requests"]["label"] == "requests"
    assert flat["@inquirer/confirm"]["source_files"] == ["requirements.txt"]
    assert [
        (v["vulnerability_id"], v["severity"], v["namespace"], v["dependency_label"])
        for v in body["vulnerabilities"]
    ] == [
        ("CVE-1", "CRITICAL", "@inquirer", "@inquirer/confirm@5.1.21"),
        ("GHSA-2", "LOW", "@inquirer", "@inquirer/confirm@5.1.21"),
    ]

    lean = ok(
        admin.get(
            f"/v1/projects/{scanned['project']}/dependency-graph",
            params={"include_vulnerabilities": "false"},
        )
    )
    assert lean["vulnerabilities"] == []
    assert lean["summary"]["vulnerability_count"] == 2


def test_dependency_graph_serves_the_chosen_version_and_guards_drafts(admin, scanned):
    pid = scanned["project"]
    draft = make_version(admin, pid, "2.0.0", is_draft=True)
    record_dependency(draft["id"], "pypi", "flask", "3.0")
    base = f"/v1/projects/{pid}/dependency-graph"

    chosen = ok(admin.get(base, params={"version_id": draft["id"]}))
    assert [d["name"] for d in chosen["dependencies"]] == ["flask"]
    assert chosen["version"]["is_latest"] is False

    viewer, _ = signed_in("viewer")
    assert viewer.get(base, params={"version_id": draft["id"]}).status_code == 403
    assert ok(viewer.get(base))["version"]["version"] == "1.0.0"
    assert admin.get(base, params={"version_id": 999999}).status_code == 404
    # A version of another project is not found under this one.
    other = make_project(admin, "other")
    foreign = make_version(admin, other["id"], "1.0.0")
    assert admin.get(base, params={"version_id": foreign["id"]}).status_code == 404
    assert admin.get("/v1/projects/999999/dependency-graph").status_code == 404
    bare = make_project(admin, "bare")
    response = admin.get(f"/v1/projects/{bare['id']}/dependency-graph")
    assert (response.status_code, response.json()["detail"]) == (
        404,
        "Project has no versions",
    )


def test_draft_graphs_open_to_the_owner_and_the_owning_group(admin):
    owner, owner_id = signed_in("maintainer")
    colleague, colleague_id = signed_in("viewer")
    make_group("Team", members=[owner_id, colleague_id])
    pid = make_project(owner, "owned")["id"]
    draft = make_version(owner, pid, "1.0.0", is_draft=True)
    path = f"/v1/projects/{pid}/dependency-graph"
    for client in (owner, colleague):
        assert client.get(path, params={"version_id": draft["id"]}).status_code == 200
    stranger, stranger_id = signed_in("maintainer")
    make_group("Elsewhere", members=[stranger_id])
    assert stranger.get(path, params={"version_id": draft["id"]}).status_code == 403


# ---------------------------------------------------------------------------
# Starting a scan.
# ---------------------------------------------------------------------------


def test_a_requested_scan_clears_the_old_result_and_launches(admin, scanned, scans):
    vid = scanned["version"]
    set_scan_state(
        vid,
        "complete",
        link_to_source_code=SOURCE,
        dependency_count=5,
        vulnerability_count=2,
        dependency_last_commit="abc123",
        dependency_discovery_error="old",
    )
    path = f"/v1/project-versions/{vid}/dependency-discovery"
    assert ok(admin.post(path, headers=csrf(admin))) == {
        "queued": True,
        "launched": True,
        "project_version_id": vid,
    }
    assert scans.launched == [vid]
    with SessionLocal() as s:
        version = s.get(ProjectVersion, vid)
        assert version.dependency_discovery_status == "queued"
        assert (version.dependency_count, version.vulnerability_count) == (0, 0)
        assert version.dependency_last_commit is None
        assert version.dependency_discovery_error is None
        assert (
            s.query(ProjectVersionDependency).filter_by(project_version_id=vid).count()
            == 0
        )

    # Queued without launching: the dispatcher picks it up.
    assert (
        ok(admin.post(path, params={"run_now": "false"}, headers=csrf(admin)))[
            "launched"
        ]
        is False
    )
    assert scans.launched == [vid]
    # A broker that refuses leaves the scan queued for the dispatcher.
    scans.refuse = True
    assert ok(admin.post(path, headers=csrf(admin)))["launched"] is False
    with SessionLocal() as s:
        assert s.get(ProjectVersion, vid).dependency_discovery_status == "queued"


def test_only_owners_start_scans_and_only_where_there_is_source(
    admin, scans, monkeypatch
):
    owner, owner_id = signed_in("maintainer")
    colleague, colleague_id = signed_in("viewer")
    make_group("Team", members=[owner_id, colleague_id])
    pid = make_project(owner, "owned")["id"]
    version = make_version(owner, pid, "1.0.0")
    path = f"/v1/project-versions/{version['id']}/dependency-discovery"

    no_source = owner.post(path, headers=csrf(owner))
    assert no_source.status_code == 400
    assert "link_to_source_code" in no_source.json()["detail"]
    set_scan_state(version["id"], "not_run", link_to_source_code=SOURCE)

    stranger, _ = signed_in("maintainer")
    assert stranger.post(path, headers=csrf(stranger)).status_code == 403
    assert scans.launched == []
    # The owner, a member of the owning group and an administrator may.
    for client in (owner, colleague, admin):
        assert client.post(path, headers=csrf(client)).status_code == 200
    assert scans.launched == [version["id"]] * 3
    assert (
        admin.post(
            "/v1/project-versions/999999/dependency-discovery", headers=csrf(admin)
        ).status_code
        == 404
    )

    monkeypatch.setattr(settings, "dependency_discovery_enabled", False)
    off = admin.post(path, headers=csrf(admin))
    assert (off.status_code, off.json()["detail"]) == (
        400,
        "Dependency discovery is disabled",
    )
    assert len(scans.launched) == 3


# ---------------------------------------------------------------------------
# Cross-project graphs.
# ---------------------------------------------------------------------------


@pytest.fixture()
def fleet(admin):
    """Three projects sharing dependencies, capabilities and licences."""
    fw = make_framework(admin)
    wallet = make_node(admin, fw["id"], "wallet")
    issuer = make_node(admin, fw["id"], "issuer")
    out = {
        "fw": fw["id"],
        "wallet": wallet["id"],
        "issuer": issuer["id"],
        "v": {},
        "p": {},
    }
    plan = {
        "one": (
            "MIT",
            [("pypi", "requests", "2.0"), ("pypi", "idna", "3.0")],
            ["wallet", "issuer"],
        ),
        "two": ("MIT", [("pypi", "requests", "2.0")], ["wallet"]),
        "three": (None, [("pypi", "attrs", "1.0")], []),
    }
    for name, (licence, deps, caps) in plan.items():
        project = make_project(admin, name, license=licence)
        old = make_version(admin, project["id"], "0.9.0")
        new = make_version(admin, project["id"], "1.0.0")
        for eco, dep, ver in deps:
            record_dependency(new["id"], eco, dep, ver)
        # Only the superseded version uses this one.
        record_dependency(old["id"], "pypi", "legacy", "0.1")
        map_nodes(admin, new["id"], fw["id"], [out[c] for c in caps])
        out["v"][name] = new["id"]
        out["p"][name] = project["id"]
    return out


def _labels(body, kind):
    return {n["label"]: n for n in body["nodes"] if n["type"] == kind}


def test_dependency_lens_ranks_shared_dependencies_of_latest_versions(admin, fleet):
    body = ok(admin.get("/v1/visualisations/bipartite", params={"min_usage": 1}))
    deps = _labels(body, "dependency_version")
    assert {name: d["usage_count"] for name, d in deps.items()} == {
        "requests@2.0": 2,
        "idna@3.0": 1,
        "attrs@1.0": 1,
    }
    assert deps["requests@2.0"]["ecosystem"] == "pypi"
    # Most used first.
    assert [n["label"] for n in body["nodes"] if n["type"] == "dependency_version"][
        0
    ] == "requests@2.0"
    projects = _labels(body, "project_version")
    assert set(projects) == {"One 1.0.0", "Two 1.0.0", "Three 1.0.0"}
    assert projects["One 1.0.0"]["project_id"] == fleet["p"]["one"]
    assert len(body["links"]) == 4
    requests_id = deps["requests@2.0"]["id"]
    assert {
        link["source"] for link in body["links"] if link["target"] == requests_id
    } == {
        f"p:{fleet['v']['one']}",
        f"p:{fleet['v']['two']}",
    }

    # The default threshold keeps only what two or more projects share.
    shared = ok(admin.get("/v1/visualisations/bipartite", params={"lens": "deps"}))
    assert list(_labels(shared, "dependency_version")) == ["requests@2.0"]
    assert set(_labels(shared, "project_version")) == {"One 1.0.0", "Two 1.0.0"}
    assert shared["meta"]["min_usage"] == 2

    everything = ok(
        admin.get(
            "/v1/visualisations/dependencies-bipartite",
            params={"latest_only": "false", "min_usage": 3},
        )
    )
    # Superseded versions count once included: all three used "legacy".
    assert list(_labels(everything, "dependency_version")) == ["legacy@0.1"]
    assert len(_labels(everything, "project_version")) == 3

    capped = ok(
        admin.get(
            "/v1/visualisations/bipartite",
            params={"min_usage": 1, "limit_items": 1, "limit_projects": 1},
        )
    )
    assert list(_labels(capped, "dependency_version")) == ["requests@2.0"]
    assert len(_labels(capped, "project_version")) == 1
    assert len(capped["links"]) == 1

    nothing = ok(admin.get("/v1/visualisations/bipartite", params={"min_usage": 50}))
    assert (nothing["nodes"], nothing["links"]) == ([], [])


def test_dependency_lens_is_for_administrators(fleet):
    viewer, _ = signed_in("viewer")
    for path in (
        "/v1/visualisations/bipartite",
        "/v1/visualisations/dependencies-bipartite",
    ):
        assert viewer.get(path).status_code == 403


def test_capability_lens_links_versions_to_the_nodes_they_map(admin, fleet):
    viewer, _ = signed_in("viewer")
    body = ok(
        viewer.get(
            "/v1/visualisations/bipartite",
            params={"lens": "capabilities", "min_usage": 1},
        )
    )
    caps = _labels(body, "capability")
    assert {label: c["usage_count"] for label, c in caps.items()} == {
        "Taxonomy: Wallet": 2,
        "Taxonomy: Issuer": 1,
    }
    assert caps["Taxonomy: Wallet"]["framework"] == "Taxonomy"
    assert caps["Taxonomy: Wallet"]["framework_node_id"] == fleet["wallet"]
    assert set(_labels(body, "project_version")) == {"One 1.0.0", "Two 1.0.0"}
    assert {(link["source"], link["target"]) for link in body["links"]} == {
        (f"p:{fleet['v']['one']}", f"c:{fleet['wallet']}"),
        (f"p:{fleet['v']['one']}", f"c:{fleet['issuer']}"),
        (f"p:{fleet['v']['two']}", f"c:{fleet['wallet']}"),
    }
    assert body["meta"]["lens"] == "capabilities"

    shared = ok(
        viewer.get("/v1/visualisations/bipartite", params={"lens": "framework"})
    )
    assert list(_labels(shared, "capability")) == ["Taxonomy: Wallet"]
    # Superseded versions inherited nothing here, so including them adds none.
    older = ok(
        viewer.get(
            "/v1/visualisations/bipartite",
            params={"lens": "capability", "latest_only": "false", "min_usage": 1},
        )
    )
    assert len(_labels(older, "capability")) == 2
    none = ok(
        viewer.get(
            "/v1/visualisations/bipartite",
            params={"lens": "capabilities", "min_usage": 9},
        )
    )
    assert none == {
        "nodes": [],
        "links": [],
        "meta": {"latest_only": True, "lens": "capabilities"},
    }


def test_licence_lens_groups_projects_and_names_the_unlicensed(admin, fleet):
    viewer, _ = signed_in("viewer")
    body = ok(
        viewer.get(
            "/v1/visualisations/bipartite", params={"lens": "licenses", "min_usage": 1}
        )
    )
    licences = _labels(body, "license")
    assert {label: lic["usage_count"] for label, lic in licences.items()} == {
        "MIT": 2,
        "(unknown)": 1,
    }
    assert {(link["source"], link["target"]) for link in body["links"]} == {
        (f"p:{fleet['v']['one']}", "l:MIT"),
        (f"p:{fleet['v']['two']}", "l:MIT"),
        (f"p:{fleet['v']['three']}", "l:(unknown)"),
    }
    shared = ok(viewer.get("/v1/visualisations/bipartite", params={"lens": "license"}))
    assert list(_labels(shared, "license")) == ["MIT"]
    assert set(_labels(shared, "project_version")) == {"One 1.0.0", "Two 1.0.0"}
    # Every version of a project appears once superseded ones are included.
    older = ok(
        viewer.get(
            "/v1/visualisations/bipartite",
            params={"lens": "licenses", "latest_only": "false", "min_usage": 1},
        )
    )
    assert len(_labels(older, "project_version")) == 6
    none = ok(
        viewer.get(
            "/v1/visualisations/bipartite", params={"lens": "licenses", "min_usage": 9}
        )
    )
    assert none["nodes"] == []

    unknown = viewer.get("/v1/visualisations/bipartite", params={"lens": "colour"})
    assert (unknown.status_code, unknown.json()["detail"]) == (
        400,
        "Unknown lens 'colour'",
    )


def test_empty_catalogue_draws_empty_graphs(admin):
    for lens in ("dependencies", "capabilities", "licenses"):
        body = ok(
            admin.get(
                "/v1/visualisations/bipartite", params={"lens": lens, "min_usage": 1}
            )
        )
        assert (body["nodes"], body["links"]) == ([], [])


# ---------------------------------------------------------------------------
# Capability detail.
# ---------------------------------------------------------------------------


def test_capability_detail_lists_users_and_keeps_drafts_to_their_owners(admin):
    fw = make_framework(admin)
    wallet = make_node(admin, fw["id"], "wallet", description="Holds credentials")
    keys = make_node(admin, fw["id"], "keys", parent_id=wallet["id"])

    owner, owner_id = signed_in("maintainer")
    colleague, colleague_id = signed_in("viewer")
    make_group("Team", members=[owner_id, colleague_id])
    owned = make_project(owner, "owned", display_name="Owned")["id"]
    published = make_version(owner, owned, "1.0.0")
    draft = make_version(owner, owned, "2.0.0", is_draft=True)
    for vid in (published["id"], draft["id"]):
        map_nodes(owner, vid, fw["id"], [keys["id"]])
    other = make_project(admin, "another", display_name="Another")["id"]
    other_v = make_version(admin, other, "5.0.0")
    map_nodes(admin, other_v["id"], fw["id"], [keys["id"]])

    body = ok(owner.get(f"/v1/capabilities/{keys['id']}"))
    assert body["capability"] == {
        "framework_node_id": keys["id"],
        "framework_id": fw["id"],
        "framework_machine_name": "tax",
        "framework_display_name": "Taxonomy",
        "key": "keys",
        "display_name": "Keys",
        "description": None,
        "parent_id": wallet["id"],
        "level": 1,
        "path": "Wallet / Keys",
    }

    def seen(client):
        return [
            (p["project_name"], p["project_version"], p["is_draft"])
            for p in ok(client.get(f"/v1/capabilities/{keys['id']}"))["projects"]
        ]

    with_draft = [
        ("Another", "5.0.0", False),
        ("Owned", "1.0.0", False),
        ("Owned", "2.0.0", True),
    ]
    assert seen(owner) == seen(colleague) == seen(admin) == with_draft
    stranger, stranger_id = signed_in("maintainer")
    assert seen(stranger) == with_draft[:2]
    # Belonging to some other group opens nothing.
    make_group("Elsewhere", members=[stranger_id])
    assert seen(stranger) == with_draft[:2]

    root = ok(owner.get(f"/v1/capabilities/{wallet['id']}"))
    assert (root["capability"]["path"], root["capability"]["description"]) == (
        "Wallet",
        "Holds credentials",
    )
    assert root["projects"] == []
    assert owner.get("/v1/capabilities/999999").status_code == 404


# ---------------------------------------------------------------------------
# Dependency detail and directory.
# ---------------------------------------------------------------------------


def test_dependency_detail_orders_findings_and_lists_scope_neighbours(admin, scanned):
    vid = scanned["version"]
    record_dependency(vid, "npm", "@inquirer/core", "9.0")
    record_dependency(vid, "npm", "@inquirer/select", "4.0")
    record_dependency(
        vid,
        "npm",
        "@other/thing",
        "1.0",
        vulnerabilities=[
            ("B-low", "low", None),
            ("A-medium", "MEDIUM", None),
            ("C-odd", "catastrophic", None),
            ("D-none", None, None),
            ("A-high", "high", "1.1"),
        ],
    )
    detail = ok(admin.get(f"/v1/dependencies/{scanned['ids']['confirm']}"))
    assert detail["dependency_version"]["name"] == "@inquirer/confirm"
    assert detail["dependency_version"]["version"] == "5.1.21"
    assert [v["vulnerability_id"] for v in detail["vulnerabilities"]] == [
        "CVE-1",
        "GHSA-2",
    ]
    assert detail["severity_counts"] == {"CRITICAL": 1, "LOW": 1}
    assert detail["projects"] == [
        {
            "project_id": scanned["project"],
            "project_name": "Alpha",
            "project_version_id": vid,
            "project_version": "1.0.0",
            "is_latest": True,
            "is_draft": False,
            "is_indirect": False,
            "source_files": ["requirements.txt"],
        }
    ]
    assert detail["namespace"]["scope"] == "@inquirer"
    assert [p["name"] for p in detail["namespace"]["packages"]] == [
        "@inquirer/confirm",
        "@inquirer/core",
        "@inquirer/select",
    ]
    assert detail["namespace"]["truncated"] is False
    limited = ok(
        admin.get(
            f"/v1/dependencies/{scanned['ids']['confirm']}",
            params={"namespace_limit": 2},
        )
    )
    assert len(limited["namespace"]["packages"]) == 2
    assert limited["namespace"]["truncated"] is True
    assert detail["package"] == {
        "project_count": 1,
        "versions": [
            {
                "public_id": detail["package"]["versions"][0]["public_id"],
                "version": "5.1.21",
                "project_count": 1,
                "current": True,
            }
        ],
        "versions_truncated": False,
    }

    # Unscoped packages have no namespace; severities sort worst first, with
    # unrecognised and missing ones last.
    assert (
        ok(admin.get(f"/v1/dependencies/{scanned['ids']['lodash']}"))["namespace"]
        is None
    )
    with SessionLocal() as s:
        from app.db.models import DependencyPackage, DependencyVersion

        other = (
            s.query(DependencyVersion.id)
            .join(DependencyPackage)
            .filter(DependencyPackage.name == "@other/thing")
            .scalar()
        )
    ranked = ok(admin.get(f"/v1/dependencies/{other}"))
    assert [v["vulnerability_id"] for v in ranked["vulnerabilities"]] == [
        "A-high",
        "A-medium",
        "B-low",
        "C-odd",
        "D-none",
    ]
    assert ranked["severity_counts"] == {
        "LOW": 1,
        "MEDIUM": 1,
        "CATASTROPHIC": 1,
        "UNKNOWN": 1,
        "HIGH": 1,
    }
    viewer, _ = signed_in("viewer")
    assert viewer.get(f"/v1/dependencies/{other}").status_code == 403


# ---------------------------------------------------------------------------
# Dashboard.
# ---------------------------------------------------------------------------


def test_dashboard_summarises_each_projects_latest_release(admin, scanned, monkeypatch):
    vid = scanned["version"]
    record_dependency(
        vid,
        "pypi",
        "old",
        "1",
        vulnerabilities=[("X-1", "CRITICAL", None), ("X-2", None, None)],
    )
    set_scan_state(vid, "complete", dependency_count=6, dependency_last_commit="abc123")
    acme = make_project(
        admin, "beta", display_name="Beta", organisation="Acme", project_type="library"
    )
    make_project(admin, "empty")
    # Published versions but no Latest marker: the greatest label stands in.
    unmarked = make_project(admin, "unmarked")
    for label in ("1.0.0", "2.0.0"):
        make_version(admin, unmarked["id"], label)
    with SessionLocal() as s:
        s.query(ProjectVersion).filter_by(project_id=unmarked["id"]).update(
            {ProjectVersion.is_latest: False}
        )
        s.commit()
    # A project with only a draft has no release to report.
    hidden = make_project(admin, "hidden")
    make_version(admin, hidden["id"], "0.1.0", is_draft=True)
    make_project(
        admin,
        "tracked",
        track_branch=True,
        tracked_repo_url=SOURCE,
        tracked_branch="main",
    )

    viewer, _ = signed_in("viewer")
    body = ok(viewer.get("/v1/dashboard"))
    assert body["dependency_scans_enabled"] is True
    rows = {row["machine_name"]: row for row in body["projects"]}
    assert [row["name"] for row in body["projects"]] == [
        "Alpha",
        "Beta",
        "Empty",
        "Hidden",
        "Tracked",
        "Unmarked",
    ]

    alpha = rows["alpha"]
    assert alpha["latest"]["version"] == "1.0.0"
    assert alpha["dependencies"]["discovery_status"] == "complete"
    assert (alpha["dependencies"]["count"], alpha["dependencies"]["last_commit"]) == (
        6,
        "abc123",
    )
    assert alpha["vulnerabilities"] == {
        "total": 4,
        "by_severity": {"critical": 2, "low": 1, "unknown": 1},
    }
    for name in ("empty", "hidden"):
        assert (
            rows[name]["latest"],
            rows[name]["dependencies"],
            rows[name]["vulnerabilities"],
        ) == (
            None,
            None,
            None,
        )
    assert rows["unmarked"]["latest"]["version"] == "2.0.0"
    assert rows["unmarked"]["vulnerabilities"] == {"total": 0, "by_severity": {}}
    assert rows["tracked"]["tracked_branch"] == "main"
    assert rows["tracked"]["latest"]["version"] == "main"
    assert rows["alpha"]["tracked_branch"] is None
    assert (rows["beta"]["organisation"], rows["beta"]["project_type"]) == (
        "Acme",
        "library",
    )

    filtered = ok(
        viewer.get("/v1/dashboard", params={"organisation_id": acme["organisation_id"]})
    )
    assert [row["machine_name"] for row in filtered["projects"]] == ["beta"]

    monkeypatch.setattr(settings, "feature_dependency_scans", False)
    # The dashboard belongs to dependency scanning and goes with it.
    assert viewer.get("/v1/dashboard").status_code == 404
