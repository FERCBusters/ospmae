"""What a draft holds reaches only those who may read the draft: an
administrator, the project's creator and its owner groups."""

from __future__ import annotations

from app.db.models import UserGroup
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
    record_dependency,
    signed_in,
)

DRAFT = "2.0.0-embargoed"


def _alpha_with_a_draft():
    """Alpha: 1.0.0 published and mapped to Wallet; a draft mapped to Wallet
    and to a capability nothing published maps."""
    admin, _ = signed_in("admin")
    fw = make_framework(admin)["id"]
    wallet = make_node(admin, fw, "wallet")["id"]
    unannounced = make_node(admin, fw, "unannounced")["id"]
    alpha = make_project(admin, "alpha", license="MIT")["id"]
    published = make_version(admin, alpha, "1.0.0")["id"]
    map_nodes(admin, published, fw, [wallet])
    draft = make_version(admin, alpha, DRAFT, is_draft=True)["id"]
    map_nodes(admin, draft, fw, [wallet, unannounced])
    return {
        "admin": admin,
        "fw": fw,
        "alpha": alpha,
        "published": published,
        "draft": draft,
        "unannounced": unannounced,
    }


def _labels(body, kind: str) -> list[str]:
    return sorted(n["label"] for n in body["nodes"] if n["type"] == kind)


def test_lenses_and_the_catalogue_show_no_draft_to_anyone_whatever_they_ask(db):
    world = _alpha_with_a_draft()
    viewer, _ = signed_in("viewer")
    # The draft is closed to the viewer where it is asked for directly.
    refused = viewer.get(f"/v1/project-versions/{world['draft']}/framework-nodes")
    assert refused.status_code == 403, refused.text

    for reader in (viewer, world["admin"]):
        for latest_only in ("true", "false"):
            params = {"latest_only": latest_only, "min_usage": 1}
            capabilities = ok(
                reader.get(
                    "/v1/visualisations/bipartite",
                    params={**params, "lens": "capabilities"},
                )
            )
            assert _labels(capabilities, "project_version") == ["Alpha 1.0.0"]
            # The capability only the draft maps has no usage to show.
            assert len(_labels(capabilities, "capability")) == 1
            assert len(capabilities["links"]) == 1

            licences = ok(
                reader.get(
                    "/v1/visualisations/bipartite",
                    params={**params, "lens": "licenses"},
                )
            )
            assert _labels(licences, "project_version") == ["Alpha 1.0.0"]

            catalogue = ok(
                reader.get(
                    f"/v1/frameworks/{world['fw']}/catalogue",
                    params={"latest_only": latest_only},
                )
            )
            counts = {
                item["key"]: item["project_count_total"] for item in catalogue["items"]
            }
            assert counts == {"wallet": 1, "unannounced": 0}


def test_superseded_published_versions_still_count_when_history_is_asked_for(db):
    world = _alpha_with_a_draft()
    admin = world["admin"]
    newer = make_version(admin, world["alpha"], "1.1.0")["id"]
    map_nodes(admin, newer, world["fw"], [world["unannounced"]])
    viewer, _ = signed_in("viewer")
    history = ok(
        viewer.get(
            "/v1/visualisations/bipartite",
            params={"lens": "capabilities", "latest_only": "false", "min_usage": 1},
        )
    )
    assert _labels(history, "project_version") == ["Alpha 1.0.0", "Alpha 1.1.0"]
    latest = ok(
        viewer.get(
            "/v1/visualisations/bipartite",
            params={"lens": "capabilities", "min_usage": 1},
        )
    )
    assert _labels(latest, "project_version") == ["Alpha 1.1.0"]


def _exported(client, manifest_id: int) -> list[dict]:
    return ok(
        client.get(f"/v1/manifests/{manifest_id}/export", params={"format": "json"})
    )["items"]


def test_a_shared_manifest_gives_a_draft_only_to_those_who_may_read_the_draft(db):
    owner, owner_id = signed_in("maintainer")
    architect, architect_id = signed_in("architect")
    team = make_group("Team", members=[owner_id, architect_id])
    alpha = make_project(owner, "alpha")["id"]
    make_version(owner, alpha, "1.0.0")
    draft = make_version(owner, alpha, DRAFT, is_draft=True)["id"]
    record_dependency(draft, "pypi", "draft-only-dep", "9.9.9")

    # An owner-group member saves a manifest of the draft and makes it public.
    saved = ok(
        architect.post(
            f"/v1/projects/{alpha}/manifest/save",
            params={"version_id": draft},
            json={"name": "draft snapshot"},
            headers=csrf(architect),
        )
    )
    manifest_id = saved["id"]
    ok(
        architect.patch(
            f"/v1/manifests/{manifest_id}/sharing",
            json={"is_public": True},
            headers=csrf(architect),
        )
    )
    (row,) = _exported(architect, manifest_id)
    assert row["latest_version"] == DRAFT
    assert [d["package"] for d in row["dependencies"]] == ["draft-only-dep"]

    # Another manifest user opens the public manifest: the draft is not in it.
    outsider, _ = signed_in("product_owner")
    direct = outsider.get(
        f"/v1/projects/{alpha}/manifest/export", params={"version_id": draft}
    )
    assert direct.status_code == 403, direct.text
    assert _exported(outsider, manifest_id) == []

    # Once the saver leaves the owner group the draft is closed to them too,
    # including what a scan adds afterwards.
    with SessionLocal() as s:
        s.query(UserGroup).filter_by(user_id=architect_id, group_id=team).delete()
        s.commit()
    record_dependency(draft, "pypi", "added-after-leaving", "1.2.3")
    assert _exported(architect, manifest_id) == []
    assert ok(architect.get(f"/v1/manifests/{manifest_id}"))["items"] == []

    # Published, the version is everyone's, with its dependencies as they are.
    ok(
        owner.put(
            f"/v1/project-versions/{draft}",
            json={"is_draft": False},
            headers=csrf(owner),
        )
    )
    (row,) = _exported(outsider, manifest_id)
    assert sorted(d["package"] for d in row["dependencies"]) == [
        "added-after-leaving",
        "draft-only-dep",
    ]


def test_a_published_versions_history_leaves_out_what_it_held_as_a_draft(db):
    owner, _ = signed_in("maintainer")
    alpha = make_project(owner, "alpha")["id"]
    draft = make_version(
        owner, alpha, "2.0.0", is_draft=True, notes="DRAFT-ONLY note, removed"
    )["id"]
    ok(
        owner.put(
            f"/v1/project-versions/{draft}",
            json={"notes": "second DRAFT-ONLY note"},
            headers=csrf(owner),
        )
    )
    viewer, _ = signed_in("viewer")
    url = f"/v1/project-versions/{draft}/changelog"
    assert viewer.get(url).status_code == 403

    ok(
        owner.put(
            f"/v1/project-versions/{draft}",
            json={"notes": "public notes", "is_draft": False},
            headers=csrf(owner),
        )
    )
    ok(
        owner.put(
            f"/v1/project-versions/{draft}",
            json={"notes": "public notes, amended"},
            headers=csrf(owner),
        )
    )

    # The owner reads all four entries, draft states included.
    full = ok(owner.get(url))
    assert full["total"] == 4
    assert "DRAFT-ONLY" in str(full["items"])

    # Another reader sees the publication and what followed it.
    public = ok(viewer.get(url))
    assert public["total"] == 2
    assert "DRAFT-ONLY" not in str(public)
    amended, publication = public["items"]
    assert amended["after_state"]["notes"] == "public notes, amended"
    assert amended["before_state"]["notes"] == "public notes"
    assert publication["before_state"] is None
    assert publication["after_state"]["notes"] == "public notes"
    assert publication["after_state"]["is_draft"] is False
    assert [change["field"] for change in publication["changes"]] == ["is_draft"]

    # Paging counts what this reader can see.
    page = ok(viewer.get(url, params={"limit": 1, "offset": 1}))
    assert (page["total"], len(page["items"])) == (2, 1)
    assert page["items"][0]["after_state"]["notes"] == "public notes"
    assert ok(viewer.get(url, params={"offset": 2}))["items"] == []
