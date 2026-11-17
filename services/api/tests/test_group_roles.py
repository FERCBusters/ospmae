"""An account whose role is ``inherit`` takes the role its groups hold."""

from __future__ import annotations

import pytest

from tests.support import csrf, make_framework, make_group, make_project, ok, signed_in

FRAMEWORK = {"machine_name": "tax", "display_name": "Taxonomy"}
PROJECT = {"machine_name": "alpha", "display_name": "Alpha"}


def _inheriting(*group_roles: str | None):
    """A signed-in ``inherit`` account in one group per role given."""
    client, user_id = signed_in("inherit")
    for index, role in enumerate(group_roles):
        make_group(f"group-{user_id}-{index}", role=role, members=[user_id])
    return client


def _effective_role(client) -> str:
    return ok(client.get("/v1/me"))["effective_role"]


@pytest.mark.parametrize(
    "role",
    [
        "admin",
        "framework_admin",
        "maintainer",
        "contributor",
        "architect",
        "product_owner",
        "engineer",
        "viewer",
    ],
)
def test_a_group_role_is_inherited_as_the_role_the_group_holds(db, role):
    assert _effective_role(_inheriting(role)) == role


def test_a_maintainer_group_grants_project_writes_and_no_framework_writes(db):
    """Maintainer and framework administrator share a precedence tier; the
    role an account inherits is still the one its group holds."""
    client = _inheriting("maintainer")
    assert _effective_role(client) == "maintainer"
    make_project(client)
    refused = client.post("/v1/frameworks", json=FRAMEWORK, headers=csrf(client))
    assert refused.status_code == 403, refused.text
    frameworks = ok(client.get("/v1/frameworks"))["items"]
    assert FRAMEWORK["machine_name"] not in [f["machine_name"] for f in frameworks]


def test_a_framework_admin_group_grants_framework_writes_and_no_project_writes(db):
    client = _inheriting("framework_admin")
    assert _effective_role(client) == "framework_admin"
    make_framework(client)
    refused = client.post("/v1/projects", json=PROJECT, headers=csrf(client))
    assert refused.status_code == 403, refused.text
    assert ok(client.get("/v1/projects"))["items"] == []


@pytest.mark.parametrize(
    "roles",
    [("maintainer", "framework_admin"), ("framework_admin", "maintainer")],
)
def test_holding_both_tied_roles_resolves_to_maintainer_whatever_the_order(db, roles):
    client = _inheriting(*roles)
    assert _effective_role(client) == "maintainer"
    make_project(client)
    refused = client.post("/v1/frameworks", json=FRAMEWORK, headers=csrf(client))
    assert refused.status_code == 403, refused.text


def test_the_highest_group_role_wins_and_unusable_group_roles_are_ignored(db):
    # A stored role is compared without case or surrounding space.
    assert _effective_role(_inheriting("viewer", "  Contributor ", "engineer")) == (
        "contributor"
    )
    assert _effective_role(_inheriting("maintainer", "admin")) == "admin"
    # A group with no role, an unknown one, or "inherit" lends none.
    assert _effective_role(_inheriting(None, "inherit", "owner")) == "viewer"
    assert _effective_role(_inheriting()) == "viewer"


def test_a_direct_role_is_not_changed_by_group_roles(db):
    client, user_id = signed_in("viewer")
    make_group("admins", role="admin", members=[user_id])
    assert _effective_role(client) == "viewer"
    refused = client.get("/v1/admin/users")
    assert refused.status_code == 403, refused.text
