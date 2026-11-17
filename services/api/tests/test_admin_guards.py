"""Admin namespace guards: role checks and last-admin protection."""

from __future__ import annotations

from tests.conftest import auth_client, make_user


def test_admin_routes_require_admin(client):
    viewer_c, _v = auth_client("VwA", role="viewer")
    assert viewer_c.get("/v1/admin/users").status_code == 403
    r = client.get("/v1/admin/users")
    assert r.status_code == 401


def test_admin_lists_and_updates_users(client):
    c, _a = auth_client("AdmU")
    make_user("TargetU", "Test-passphrase-1!", role="viewer")
    r = c.get("/v1/admin/users")
    assert r.status_code == 200
    assert any(u["username"] == "TargetU" for u in r.json()["items"])
    target = next(u for u in r.json()["items"] if u["username"] == "TargetU")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.patch(
        f"/v1/admin/users/{target['id']}",
        json={"role": "maintainer"},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "maintainer"


def test_last_admin_cannot_be_demoted_or_deactivated(client):
    c, me = auth_client("AdmV")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.patch(
        f"/v1/admin/users/{int(me.id)}",
        json={"role": "viewer"},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 409, "the last active admin cannot be demoted"
    # As in KEEN, no administrator deactivates their own account.
    r = c.patch(
        f"/v1/admin/users/{int(me.id)}",
        json={"is_active": False},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "You cannot deactivate your own account"
    r = c.delete(
        f"/v1/admin/users/{int(me.id)}",
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code in (400, 409)


def test_second_admin_can_be_demoted_by_the_first(client):
    c, _me = auth_client("AdmW")
    other = make_user("Adm2", "Test-passphrase-1!", role="admin")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.patch(
        f"/v1/admin/users/{int(other.id)}",
        json={"role": "viewer"},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 200


def test_last_admin_access_strip_is_refused(client):
    c, me = auth_client("AdmX")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.put(
        f"/v1/admin/users/{int(me.id)}/access",
        json={"group_ids": [], "permission_ids": []},
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 409


def test_creating_users_validates_role_and_username(client):
    c, _a = auth_client("AdmY")
    csrf = c.cookies.get("__Host-ospmae_csrf")
    r = c.post(
        "/v1/admin/users",
        json={
            "username": "bad role!",
            "password": "Test-passphrase-1!",
            "role": "superadmin",
        },
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code in (400, 422)
    r = c.post(
        "/v1/admin/users",
        json={
            "username": "bad username with space\n",
            "password": "Test-passphrase-1!",
            "role": "viewer",
        },
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code in (400, 422)


def test_features_endpoint_requires_authentication(client):
    r = client.get("/v1/system/features")
    assert r.status_code == 401
    c, _a = auth_client("FeatU")
    body = c.get("/v1/system/features").json()
    assert set(body) == {
        "frameworks",
        "manifests",
        "questions",
        "dependency_scans",
        "comparisons",
        "release_feed",
    }


# ---------------------------------------------------------------------------
# An administrator through a group counts as one, on every path.
# ---------------------------------------------------------------------------


def _direct_and_inheriting_admins():
    """A: administrator by role. B: role inherit, administrator through the
    Operators group."""
    from tests.support import make_group, signed_in

    a, a_id = signed_in("admin")
    b, b_id = signed_in("inherit")
    operators = make_group("Operators", role="admin", members=[b_id])
    assert b.get("/v1/admin/users").status_code == 200
    return a, a_id, b, b_id, operators


def _admins(db) -> int:
    from app.security.roles import active_admin_count

    db.expire_all()
    return active_admin_count(db)


def test_an_inheriting_administrator_lets_the_direct_one_step_down(db):
    from tests.support import csrf

    a, a_id, b, _b_id, _group = _direct_and_inheriting_admins()
    assert _admins(db) == 2
    stepped = b.patch(
        f"/v1/admin/users/{a_id}", json={"role": "viewer"}, headers=csrf(b)
    )
    assert stepped.status_code == 200, stepped.text
    assert _admins(db) == 1
    assert a.get("/v1/admin/users").status_code == 403


def test_the_last_administrator_cannot_be_removed_through_its_group(db):
    from tests.support import csrf, ok

    a, a_id, b, b_id, group = _direct_and_inheriting_admins()
    ok(b.patch(f"/v1/admin/users/{a_id}", json={"role": "viewer"}, headers=csrf(b)))

    # B is now the only administrator, and only through Operators.
    refusals = [
        b.patch(f"/v1/admin/groups/{group}", json={"role": "viewer"}, headers=csrf(b)),
        b.patch(f"/v1/admin/groups/{group}", json={"role": None}, headers=csrf(b)),
        b.delete(f"/v1/admin/groups/{group}", headers=csrf(b)),
        b.put(
            f"/v1/admin/users/{b_id}/access",
            json={"group_ids": [], "permission_ids": []},
            headers=csrf(b),
        ),
        b.patch(f"/v1/admin/users/{b_id}", json={"role": "viewer"}, headers=csrf(b)),
    ]
    assert [r.status_code for r in refusals] == [409] * 5, [r.text for r in refusals]
    assert _admins(db) == 1
    assert b.get("/v1/admin/users").status_code == 200
    # Nothing of a refused change was kept.
    groups = ok(b.get("/v1/admin/groups"))["items"]
    assert [(g["name"], g["role"]) for g in groups] == [("Operators", "admin")]
    access = ok(b.get(f"/v1/admin/users/{b_id}/access"))
    assert access["group_ids"] == [group]

    # A change that leaves B an administrator is still made.
    renamed = b.patch(
        f"/v1/admin/groups/{group}", json={"name": "Ops"}, headers=csrf(b)
    )
    assert renamed.status_code == 200, renamed.text
    # With a second administrator back, each of those changes is allowed.
    ok(b.patch(f"/v1/admin/users/{a_id}", json={"role": "admin"}, headers=csrf(b)))
    ok(b.patch(f"/v1/admin/groups/{group}", json={"role": "viewer"}, headers=csrf(b)))
    assert _admins(db) == 1
    assert b.get("/v1/admin/users").status_code == 403


def test_an_inactive_or_directly_ranked_member_of_an_admin_group_is_not_counted(db):
    from app.db.models import User

    from tests.support import make_group, signed_in

    _a, _a_id = signed_in("admin")
    _viewer, viewer_id = signed_in("viewer")
    _gone, gone_id = signed_in("inherit")
    make_group("Operators", role="admin", members=[viewer_id, gone_id])
    assert _admins(db) == 2
    db.query(User).filter(User.id == gone_id).update({User.is_active: False})
    db.commit()
    # The viewer's own role wins over the group's; the inactive account is out.
    assert _admins(db) == 1


def test_two_demotions_at_once_cannot_both_pass(db):
    """Each administrator demotes the other; the second waits for the first
    and then finds itself the last one."""
    import threading

    from app.db.session import SessionLocal
    from app.security.roles import lock_admin_changes

    from tests.support import csrf, signed_in

    a, a_id = signed_in("admin")
    b, b_id = signed_in("admin")
    holder = SessionLocal()
    lock_admin_changes(holder)
    results: dict[str, int] = {}

    def demote(name, client, target):
        results[name] = client.patch(
            f"/v1/admin/users/{target}", json={"role": "viewer"}, headers=csrf(client)
        ).status_code

    threads = [
        threading.Thread(target=demote, args=("a", a, b_id)),
        threading.Thread(target=demote, args=("b", b, a_id)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=0.5)
    # Both wait while another change holds the lock.
    assert results == {}
    holder.rollback()
    holder.close()
    for thread in threads:
        thread.join(timeout=10)
    assert sorted(results.values()) == [200, 409]
    assert _admins(db) == 1


def test_an_administrators_reset_ends_sessions_opened_through_a_provider(
    db, monkeypatch
):
    from app.core.config import settings
    from app.db.models import Session as SessionRow

    from tests.support import csrf, ok, signed_in

    monkeypatch.setattr(settings, "oidc_sso_enabled", True)
    admin, _ = signed_in("admin")
    target, target_id = signed_in("viewer")
    # One of the account's sessions was opened by single sign-on.
    other, _ = signed_in("viewer")
    row = db.query(SessionRow).filter(SessionRow.user_id == target_id).one()
    row.auth_method = "oidc"
    db.commit()
    assert target.get("/v1/me").status_code == 200

    ok(
        admin.post(
            f"/v1/admin/users/{target_id}/password",
            json={"new_password": "A-fresh-passphrase-for-tests-9!"},
            headers=csrf(admin),
        )
    )
    assert db.query(SessionRow).filter(SessionRow.user_id == target_id).count() == 0
    assert target.get("/v1/me").status_code == 401
    assert other.get("/v1/me").status_code == 200
