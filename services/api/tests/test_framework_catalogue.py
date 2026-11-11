"""Framework upkeep and the catalogue's per-node project counts."""

from __future__ import annotations

from app.db.models import Framework, FrameworkNode
from app.db.session import SessionLocal

from tests.support import (
    csrf,
    make_framework,
    make_node,
    make_project,
    make_version,
    map_nodes,
    ok,
    signed_in,
)


def _tree(admin):
    fw = make_framework(admin)
    wallet = make_node(admin, fw["id"], "wallet", sort_order=2, description="Holder")
    storage = make_node(admin, fw["id"], "storage", parent_id=wallet["id"])
    keys = make_node(admin, fw["id"], "keys", parent_id=wallet["id"])
    issuer = make_node(admin, fw["id"], "issuer", sort_order=1)
    return fw["id"], {
        "wallet": wallet["id"],
        "storage": storage["id"],
        "keys": keys["id"],
        "issuer": issuer["id"],
    }


def test_catalogue_counts_each_project_once_however_many_branches_it_maps():
    admin, _ = signed_in("admin")
    fw, n = _tree(admin)
    # Alpha maps two children of Wallet; Beta maps one child and the root.
    alpha = make_project(admin, "alpha")
    alpha_v = make_version(admin, alpha["id"], "1.0.0")
    map_nodes(admin, alpha_v["id"], fw, [n["storage"], n["keys"]])
    beta = make_project(admin, "beta")
    beta_old = make_version(admin, beta["id"], "1.0.0")
    map_nodes(admin, beta_old["id"], fw, [n["issuer"]])
    beta_new = make_version(admin, beta["id"], "2.0.0")
    map_nodes(admin, beta_new["id"], fw, [n["keys"], n["wallet"]])

    viewer, _ = signed_in("viewer")
    body = ok(viewer.get(f"/v1/frameworks/{fw}/catalogue"))
    assert body["meta"] == {"latest_only": True}
    items = {item["key"]: item for item in body["items"]}
    counts = {
        key: (
            item["project_count_direct"],
            item["project_count_descendants"],
            item["project_count_total"],
        )
        for key, item in items.items()
    }
    assert counts == {
        "issuer": (0, 0, 0),  # only Beta's superseded version maps it
        "wallet": (1, 2, 2),  # a union, not 1 + 2 + 1
        "storage": (1, 0, 1),
        "keys": (2, 0, 2),
    }
    assert items["wallet"]["projects_direct"] == [{"id": beta["id"], "name": "Beta"}]
    assert items["wallet"]["projects_total"] == [
        {"id": alpha["id"], "name": "Alpha"},
        {"id": beta["id"], "name": "Beta"},
    ]
    assert (items["keys"]["path"], items["keys"]["level"]) == ("Wallet / Keys", 1)
    # Roots follow their sort order, children their names.
    assert [root["key"] for root in body["tree"]] == ["issuer", "wallet"]
    wallet_node = body["tree"][1]
    assert [child["key"] for child in wallet_node["children"]] == ["keys", "storage"]
    assert wallet_node["project_count_total"] == 2
    assert wallet_node["description"] == "Holder"

    history = ok(
        viewer.get(f"/v1/frameworks/{fw}/catalogue", params={"latest_only": "false"})
    )
    with_history = {item["key"]: item for item in history["items"]}
    assert with_history["issuer"]["project_count_total"] == 1
    assert history["meta"] == {"latest_only": False}
    assert viewer.get("/v1/frameworks/999999/catalogue").status_code == 404


def test_catalogue_summarises_long_project_lists():
    admin, _ = signed_in("admin")
    fw = make_framework(admin)
    node = make_node(admin, fw["id"], "popular")
    for index in range(52):
        project = make_project(admin, f"p{index:02d}")
        version = make_version(admin, project["id"], "1.0.0")
        map_nodes(admin, version["id"], fw["id"], [node["id"]])
    (item,) = ok(admin.get(f"/v1/frameworks/{fw['id']}/catalogue"))["items"]
    assert item["project_count_direct"] == 52
    assert len(item["projects_direct"]) == 51
    assert item["projects_direct"][-1] == {"id": -1, "name": "… (+2 more)"}
    assert item["projects_direct"][0]["name"] == "P00"


def test_an_empty_framework_has_an_empty_catalogue_and_tree():
    admin, _ = signed_in("admin")
    fw = make_framework(admin)
    body = ok(admin.get(f"/v1/frameworks/{fw['id']}/catalogue"))
    assert (body["tree"], body["items"]) == ([], [])
    nodes = ok(admin.get(f"/v1/frameworks/{fw['id']}/nodes"))
    assert (nodes["tree"], nodes["items"]) == ([], [])
    assert nodes["framework"]["machine_name"] == "tax"
    assert admin.get("/v1/frameworks/999999/nodes").status_code == 404


def test_a_framework_is_renamed_within_the_unique_machine_names():
    admin, _ = signed_in("admin")
    fw = make_framework(admin)
    make_framework(admin, "taken", "Taken")
    path = f"/v1/frameworks/{fw['id']}"

    updated = ok(
        admin.put(
            path,
            json={
                "machine_name": " NEW ",
                "display_name": " New name ",
                "description": "d",
            },
            headers=csrf(admin),
        )
    )
    assert (
        updated["machine_name"],
        updated["display_name"],
        updated["description"],
    ) == (
        "new",
        "New name",
        "d",
    )
    # Saving the same machine name again is not a clash; an empty description clears.
    same = ok(
        admin.put(
            path, json={"machine_name": "new", "description": ""}, headers=csrf(admin)
        )
    )
    assert same["description"] is None
    assert (
        admin.put(path, json={"machine_name": "taken"}, headers=csrf(admin)).status_code
        == 409
    )
    assert (
        admin.put(path, json={"machine_name": "   "}, headers=csrf(admin)).status_code
        == 400
    )
    assert (
        admin.put(
            "/v1/frameworks/999999", json={"display_name": "x"}, headers=csrf(admin)
        ).status_code
        == 404
    )
    with SessionLocal() as s:
        assert s.get(Framework, fw["id"]).machine_name == "new"

    viewer, _ = signed_in("viewer")
    assert (
        viewer.put(path, json={"display_name": "x"}, headers=csrf(viewer)).status_code
        == 403
    )
    assert (
        viewer.post(
            "/v1/frameworks",
            json={"machine_name": "v", "display_name": "V"},
            headers=csrf(viewer),
        ).status_code
        == 403
    )
    blank = admin.post(
        "/v1/frameworks",
        json={"machine_name": "  ", "display_name": "Blank"},
        headers=csrf(admin),
    )
    assert blank.status_code == 400


def test_only_the_owner_or_an_administrator_deletes_a_framework():
    admin, _ = signed_in("admin")
    author, _ = signed_in("framework_admin")
    peer, _ = signed_in("framework_admin")
    fw = make_framework(author, "mine", "Mine")
    assert (
        peer.delete(f"/v1/frameworks/{fw['id']}", headers=csrf(peer)).status_code == 403
    )
    assert ok(author.delete(f"/v1/frameworks/{fw['id']}", headers=csrf(author))) == {
        "ok": True
    }
    assert (
        author.delete(f"/v1/frameworks/{fw['id']}", headers=csrf(author)).status_code
        == 404
    )
    other = make_framework(author, "second", "Second")
    assert ok(admin.delete(f"/v1/frameworks/{other['id']}", headers=csrf(admin))) == {
        "ok": True
    }


def test_nodes_are_edited_moved_and_removed_without_breaking_the_tree():
    admin, _ = signed_in("admin")
    fw, n = _tree(admin)
    leaf = make_node(admin, fw, "leaf", parent_id=n["storage"])

    def put(node_id, **body):
        return admin.put(
            f"/v1/framework-nodes/{node_id}", json=body, headers=csrf(admin)
        )

    edited = ok(
        put(
            n["keys"],
            key=" key-store ",
            display_name=" Key store ",
            description="x",
            sort_order=5,
        )
    )
    assert (
        edited["key"],
        edited["display_name"],
        edited["description"],
        edited["sort_order"],
    ) == (
        "key-store",
        "Key store",
        "x",
        5,
    )
    assert ok(put(n["keys"], key="key-store", description=""))["description"] is None
    assert put(n["keys"], key="storage").status_code == 409
    assert put(n["keys"], key="  ").status_code == 400
    assert put(999999, display_name="x").status_code == 404

    # Moving a branch carries its descendants' levels with it.
    moved = ok(put(n["storage"], parent_id=n["issuer"]))
    assert (moved["parent_id"], moved["level"]) == (n["issuer"], 1)
    with SessionLocal() as s:
        assert s.get(FrameworkNode, leaf["id"]).level == 2
    deeper = ok(put(n["issuer"], parent_id=n["wallet"]))
    assert deeper["level"] == 1
    with SessionLocal() as s:
        assert (
            s.get(FrameworkNode, n["storage"]).level,
            s.get(FrameworkNode, leaf["id"]).level,
        ) == (2, 3)

    # A node cannot become its own ancestor, or join another framework's tree.
    assert (
        put(n["issuer"], parent_id=n["issuer"]).json()["detail"]
        == "Node cannot be its own parent"
    )
    cycle = put(n["issuer"], parent_id=leaf["id"])
    assert (cycle.status_code, cycle.json()["detail"]) == (
        400,
        "Node cannot move under one of its own descendants",
    )
    other = make_framework(admin, "other", "Other")
    foreign = make_node(admin, other["id"], "foreign")
    assert put(n["issuer"], parent_id=foreign["id"]).status_code == 400
    with SessionLocal() as s:
        assert s.get(FrameworkNode, n["issuer"]).parent_id == n["wallet"]

    # Creation follows the same rules.
    def post(**body):
        return admin.post(f"/v1/frameworks/{fw}/nodes", json=body, headers=csrf(admin))

    assert post(key="  ", display_name="Blank").status_code == 400
    assert post(key="wallet", display_name="Again").status_code == 409
    assert (
        post(key="orphan", display_name="Orphan", parent_id=foreign["id"]).status_code
        == 400
    )
    assert (
        admin.post(
            "/v1/frameworks/999999/nodes",
            json={"key": "k", "display_name": "K"},
            headers=csrf(admin),
        ).status_code
        == 404
    )

    # Only leaves are removed.
    blocked = admin.delete(f"/v1/framework-nodes/{n['storage']}", headers=csrf(admin))
    assert blocked.status_code == 409
    assert ok(
        admin.delete(f"/v1/framework-nodes/{leaf['id']}", headers=csrf(admin))
    ) == {"ok": True}
    assert ok(
        admin.delete(f"/v1/framework-nodes/{n['storage']}", headers=csrf(admin))
    ) == {"ok": True}
    assert (
        admin.delete(
            f"/v1/framework-nodes/{n['storage']}", headers=csrf(admin)
        ).status_code
        == 404
    )
    viewer, _ = signed_in("viewer")
    assert (
        viewer.delete(
            f"/v1/framework-nodes/{n['keys']}", headers=csrf(viewer)
        ).status_code
        == 403
    )
    assert (
        viewer.put(
            f"/v1/framework-nodes/{n['keys']}", json={"key": "x"}, headers=csrf(viewer)
        ).status_code
        == 403
    )
