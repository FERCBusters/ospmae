"""Framework and taxonomy management: permissions, integrity and tree shape."""

from __future__ import annotations

import pytest
from app.db.models import Framework, FrameworkNode, ProjectVersionFrameworkNode
from app.db.session import SessionLocal

from tests.conftest import auth_client


def _h(c):
    return {"X-CSRF-Token": c.cookies.get("__Host-ospmae_csrf") or ""}


@pytest.fixture()
def admin():
    c, user = auth_client(role="admin")
    return c


def _framework(c, machine="tax"):
    r = c.post(
        "/v1/frameworks",
        json={"machine_name": f" {machine.upper()} ", "display_name": " Taxonomy "},
        headers=_h(c),
    )
    assert r.status_code == 200, r.text
    return r.json()


def _node(c, fw_id, key, parent_id=None, **extra):
    r = c.post(
        f"/v1/frameworks/{fw_id}/nodes",
        json={"key": key, "display_name": key.title(), "parent_id": parent_id, **extra},
        headers=_h(c),
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_frameworks_are_created_normalised_and_unique(admin):
    fw = _framework(admin)
    assert (fw["machine_name"], fw["display_name"]) == ("tax", "Taxonomy")
    assert admin.get(f"/v1/frameworks/{fw['id']}").json()["machine_name"] == "tax"
    dup = admin.post(
        "/v1/frameworks",
        json={"machine_name": "tax", "display_name": "Again"},
        headers=_h(admin),
    )
    assert dup.status_code == 409
    listed = [f["machine_name"] for f in admin.get("/v1/frameworks").json()["items"]]
    assert "tax" in listed
    assert admin.get("/v1/frameworks/999999").status_code == 404


def test_reading_needs_an_account_and_writing_needs_framework_write(admin):
    fw = _framework(admin)
    viewer, _ = auth_client(role="viewer")
    assert viewer.get(f"/v1/frameworks/{fw['id']}/nodes").status_code == 200
    for method, path, body in (
        ("post", "/v1/frameworks", {"machine_name": "x", "display_name": "X"}),
        ("put", f"/v1/frameworks/{fw['id']}", {"display_name": "Y"}),
        ("delete", f"/v1/frameworks/{fw['id']}", None),
        ("post", f"/v1/frameworks/{fw['id']}/nodes", {"key": "a", "display_name": "A"}),
    ):
        kwargs = {"headers": _h(viewer)}
        if body is not None:
            kwargs["json"] = body
        r = getattr(viewer, method)(path, **kwargs)
        assert r.status_code == 403, (method, path, r.status_code)
    with SessionLocal() as db:
        assert db.get(Framework, fw["id"]).display_name == "Taxonomy"
        assert db.query(FrameworkNode).filter_by(framework_id=fw["id"]).count() == 0


def test_nodes_form_a_tree_with_levels_and_paths(admin):
    fw = _framework(admin)
    root = _node(admin, fw["id"], "identity", sort_order=2)
    other = _node(admin, fw["id"], "access", sort_order=1)
    child = _node(admin, fw["id"], "issuance", parent_id=root["id"])
    assert (root["level"], child["level"]) == (0, 1)

    body = admin.get(f"/v1/frameworks/{fw['id']}/nodes").json()
    assert [n["key"] for n in body["tree"]] == ["access", "identity"]
    assert [n["key"] for n in body["tree"][1]["children"]] == ["issuance"]
    paths = {n["key"]: n["path"] for n in body["items"]}
    assert paths == {
        "identity": "Identity",
        "access": "Access",
        "issuance": "Identity / Issuance",
    }
    assert other["parent_id"] is None


def test_node_keys_and_parents_are_checked(admin):
    fw = _framework(admin)
    other_fw = _framework(admin, "other")
    foreign = _node(admin, other_fw["id"], "foreign")
    _node(admin, fw["id"], "a")
    dup = admin.post(
        f"/v1/frameworks/{fw['id']}/nodes",
        json={"key": "a", "display_name": "A"},
        headers=_h(admin),
    )
    assert dup.status_code == 409
    wrong_parent = admin.post(
        f"/v1/frameworks/{fw['id']}/nodes",
        json={"key": "b", "display_name": "B", "parent_id": foreign["id"]},
        headers=_h(admin),
    )
    assert wrong_parent.status_code == 400
    root_by_zero = _node(admin, fw["id"], "c", parent_id=0)
    assert root_by_zero["parent_id"] is None


def test_a_node_cannot_move_under_its_own_descendant(admin):
    fw = _framework(admin)
    a = _node(admin, fw["id"], "a")
    b = _node(admin, fw["id"], "b", parent_id=a["id"])
    c = _node(admin, fw["id"], "c", parent_id=b["id"])
    for parent in (a["id"], c["id"]):
        r = admin.put(
            f"/v1/framework-nodes/{a['id']}",
            json={"parent_id": parent},
            headers=_h(admin),
        )
        assert r.status_code == 400
    with SessionLocal() as db:
        assert db.get(FrameworkNode, a["id"]).parent_id is None
    # The tree still reads, and every path ends.
    assert admin.get(f"/v1/frameworks/{fw['id']}/nodes").status_code == 200


def test_moving_a_node_relevels_its_subtree(admin):
    fw = _framework(admin)
    a = _node(admin, fw["id"], "a")
    b = _node(admin, fw["id"], "b", parent_id=a["id"])
    c = _node(admin, fw["id"], "c", parent_id=b["id"])
    d = _node(admin, fw["id"], "d")
    moved = admin.put(
        f"/v1/framework-nodes/{a['id']}", json={"parent_id": d["id"]}, headers=_h(admin)
    )
    assert moved.json()["level"] == 1
    with SessionLocal() as db:
        assert [db.get(FrameworkNode, n["id"]).level for n in (a, b, c)] == [1, 2, 3]
    to_root = admin.put(
        f"/v1/framework-nodes/{b['id']}", json={"parent_id": 0}, headers=_h(admin)
    )
    assert (to_root.json()["parent_id"], to_root.json()["level"]) == (None, 0)
    with SessionLocal() as db:
        assert db.get(FrameworkNode, c["id"]).level == 1


def test_node_updates_check_keys(admin):
    fw = _framework(admin)
    a = _node(admin, fw["id"], "a")
    _node(admin, fw["id"], "b")
    url = f"/v1/framework-nodes/{a['id']}"
    assert admin.put(url, json={"key": "b"}, headers=_h(admin)).status_code == 409
    assert admin.put(url, json={"key": " "}, headers=_h(admin)).status_code == 400
    r = admin.put(
        url,
        json={
            "key": "a2",
            "display_name": " A two ",
            "sort_order": 5,
            "description": "",
        },
        headers=_h(admin),
    )
    assert (r.json()["key"], r.json()["display_name"], r.json()["sort_order"]) == (
        "a2",
        "A two",
        5,
    )
    assert r.json()["description"] is None
    missing = admin.put("/v1/framework-nodes/999999", json={}, headers=_h(admin))
    assert missing.status_code == 404


def test_nodes_with_children_are_not_deleted(admin):
    fw = _framework(admin)
    a = _node(admin, fw["id"], "a")
    b = _node(admin, fw["id"], "b", parent_id=a["id"])
    assert (
        admin.delete(f"/v1/framework-nodes/{a['id']}", headers=_h(admin)).status_code
        == 409
    )
    assert admin.delete(f"/v1/framework-nodes/{b['id']}", headers=_h(admin)).json() == {
        "ok": True
    }
    assert admin.delete(f"/v1/framework-nodes/{a['id']}", headers=_h(admin)).json() == {
        "ok": True
    }


def test_a_referenced_framework_needs_force_to_delete(admin):
    from app.db.models import Project, ProjectVersion

    fw = _framework(admin)
    node = _node(admin, fw["id"], "a")
    with SessionLocal() as db:
        project = Project(machine_name="p", display_name="P")
        db.add(project)
        db.flush()
        version = ProjectVersion(project_id=project.id, version="1.0.0")
        db.add(version)
        db.flush()
        db.add(
            ProjectVersionFrameworkNode(
                project_version_id=version.id, framework_node_id=node["id"]
            )
        )
        db.commit()
    refused = admin.delete(f"/v1/frameworks/{fw['id']}", headers=_h(admin))
    assert refused.status_code == 409
    assert "1 project mappings" in refused.json()["detail"]
    forced = admin.delete(f"/v1/frameworks/{fw['id']}?force=true", headers=_h(admin))
    assert forced.json() == {"ok": True}
    with SessionLocal() as db:
        assert db.get(Framework, fw["id"]) is None
        assert db.query(ProjectVersionFrameworkNode).count() == 0
