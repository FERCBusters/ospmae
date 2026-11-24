"""Account administration on mosp's model: creating, changing, resetting and
deleting accounts, direct permissions, the audit readers and the outboxes."""

from __future__ import annotations

import uuid

import pytest
from app.db.models import Notification, Permission, SecurityNotification, User
from app.db.session import SessionLocal
from app.services import notifications
from mosp.services import security_notifications

from tests.conftest import auth_client, generated_password, make_user
from tests.support import csrf, ok, signed_in


@pytest.fixture()
def admin():
    c, _ = auth_client(role="admin")
    return c


@pytest.fixture()
def mail(monkeypatch):
    """Mail configured; deliveries recorded rather than sent."""
    monkeypatch.setattr(security_notifications, "smtp_configured", lambda: True)
    monkeypatch.setattr(notifications, "smtp_configured", lambda: True)
    from app.tasks import notifications as tasks

    kicks = []
    monkeypatch.setattr(
        tasks.deliver_notifications, "apply_async", lambda **kw: kicks.append(kw)
    )
    return kicks


def _create(client, **fields):
    body = {"username": "new-account", "password": generated_password(), **fields}
    return client.post("/v1/admin/users", json=body, headers=csrf(client))


def test_an_account_is_created_with_its_mailbox_and_role(admin):
    created = ok(_create(admin, email=" Someone@Example.org ", role="normal"))
    assert (created["username"], created["role"], created["effective_role"]) == (
        "new-account",
        "normal",
        "normal",
    )
    assert created["email"].lower() == "someone@example.org"
    assert _create(admin).json() == {"detail": "username already exists"}


@pytest.mark.parametrize(
    "fields,detail",
    [
        ({"email": "two@x.test, three@x.test"}, "Invalid email address"),
        ({"role": "owner"}, None),
        ({"username": "two\nlines"}, None),
    ],
)
def test_an_account_needs_one_mailbox_a_known_role_and_a_printable_name(
    admin, fields, detail
):
    response = _create(admin, **fields)
    assert response.status_code in (400, 422), response.text
    if detail:
        assert response.json() == {"detail": detail}
    with SessionLocal() as db:
        assert db.query(User).count() == 1


def test_an_accounts_mailbox_is_set_and_cleared(admin):
    target = make_user("mailbox", generated_password(), role="viewer")
    url = f"/v1/admin/users/{target.id}"
    refused = admin.patch(url, json={"email": "a@x.test b@x.test"}, headers=csrf(admin))
    assert refused.json() == {"detail": "Invalid email address"}
    assert ok(admin.patch(url, json={"email": "a@x.test"}, headers=csrf(admin)))[
        "email"
    ] == ("a@x.test")
    assert (
        ok(admin.patch(url, json={"email": " "}, headers=csrf(admin)))["email"] is None
    )


def test_a_role_change_reaches_the_accounts_open_session(admin):
    client, user = auth_client(role="viewer")
    assert client.get("/v1/admin/users").status_code == 403
    ok(
        admin.patch(
            f"/v1/admin/users/{user.id}", json={"role": "admin"}, headers=csrf(admin)
        )
    )
    assert client.get("/v1/admin/users").status_code == 200


def test_deactivation_ends_sessions_for_good(admin):
    client, user = auth_client(role="viewer")
    url = f"/v1/admin/users/{user.id}"
    ok(admin.patch(url, json={"is_active": False}, headers=csrf(admin)))
    assert client.get("/v1/me").status_code == 401
    ok(admin.patch(url, json={"is_active": True}, headers=csrf(admin)))
    assert client.get("/v1/me").status_code == 401


def _sso_session(user_id):
    """A browser signed in through an SSO provider, as mosp issues one."""
    from app.main import app as application
    from fastapi.testclient import TestClient
    from mosp.core.valkey import get_valkey
    from mosp.security.auth import cookie_name
    from mosp.security.sessions import create_session

    from tests.conftest import peer_wrapper

    with SessionLocal() as s:
        version = s.get(User, user_id).session_version
    browser = TestClient(peer_wrapper(application), base_url="https://testserver")
    browser.cookies.set(
        cookie_name(),
        create_session(
            get_valkey(),
            user_id=str(user_id),
            ttl_seconds=600,
            auth_method="oidc",
            session_version=version,
        ),
    )
    return browser


@pytest.mark.parametrize("change", ["reset", "deactivate"])
def test_sessions_opened_through_sso_end_too(admin, monkeypatch, change):
    from app.core.config import settings

    monkeypatch.setattr(settings, "oidc_enabled", True)
    _, user = auth_client(role="viewer")
    browser = _sso_session(user.id)
    assert browser.get("/v1/me").status_code == 200
    url = f"/v1/admin/users/{user.id}"
    if change == "reset":
        ok(
            admin.post(
                url + "/password",
                json={"new_password": generated_password()},
                headers=csrf(admin),
            )
        )
    else:
        ok(admin.patch(url, json={"is_active": False}, headers=csrf(admin)))
        # A session not presented while the account was inactive does not
        # return when it is activated again.
        ok(admin.patch(url, json={"is_active": True}, headers=csrf(admin)))
    assert browser.get("/v1/me").status_code == 401


def test_a_reset_mails_the_owner_and_hands_delivery_to_the_worker(admin, mail):
    target = make_user("resetme", generated_password(), role="viewer")
    with SessionLocal() as db:
        db.get(User, target.id).email = "resetme@x.test"
        db.commit()
    url = f"/v1/admin/users/{target.id}/password"
    weak = admin.post(url, json={"new_password": "password" * 2}, headers=csrf(admin))
    assert weak.status_code == 400
    ok(
        admin.post(
            url, json={"new_password": generated_password()}, headers=csrf(admin)
        )
    )
    with SessionLocal() as db:
        (notice,) = db.query(SecurityNotification).all()
        assert notice.recipient == "resetme@x.test"
        assert "reset by an administrator" in notice.subject
    assert mail == [{"retry": False}]
    unknown = admin.post(
        f"/v1/admin/users/{uuid.uuid4()}/password",
        json={"new_password": generated_password()},
        headers=csrf(admin),
    )
    assert unknown.status_code == 404


def test_accounts_are_deleted_but_never_ones_own(admin):
    me = ok(admin.get("/v1/me"))
    own = admin.delete(f"/v1/admin/users/{me['id']}", headers=csrf(admin))
    assert own.json() == {"detail": "You cannot delete your own user"}
    target = make_user("leaving", generated_password(), role="viewer")
    assert ok(admin.delete(f"/v1/admin/users/{target.id}", headers=csrf(admin))) == {
        "status": "ok",
        "deleted_user_id": str(target.id),
    }
    gone = admin.delete(f"/v1/admin/users/{target.id}", headers=csrf(admin))
    assert gone.status_code == 404


def test_a_permission_is_granted_once_and_reaches_the_session(admin):
    client, user = auth_client(role="normal")
    assert client.get("/v1/admin/audit").json() == {"detail": "Audit access required"}
    with SessionLocal() as db:
        permission = db.query(Permission).filter_by(code="audittrail.read").one()
        permission_id = permission.id
    url = f"/v1/admin/users/{user.id}/permissions/{permission_id}"
    assert ok(admin.post(url, headers=csrf(admin))) == {"status": "ok"}
    assert ok(admin.post(url, headers=csrf(admin))) == {
        "status": "ok",
        "already_linked": True,
    }
    missing = admin.post(
        f"/v1/admin/users/{user.id}/permissions/{uuid.uuid4()}", headers=csrf(admin)
    )
    assert missing.status_code == 404
    # The audit readers open to the permission; the rest of the namespace stays
    # an administrator's.
    assert client.get("/v1/admin/audit").status_code == 200
    assert client.get("/v1/admin/entity-changelog").status_code == 200
    assert client.get("/v1/admin/users").status_code == 403


def test_the_audit_trail_filters_its_rows(admin):
    admin.get("/v1/me")
    admin.get("/v1/folders")
    everything = ok(admin.get("/v1/admin/audit"))
    assert everything["total"] >= 2
    me_only = ok(
        admin.get("/v1/admin/audit", params={"path": "/v1/me", "method": "get"})
    )
    assert {row["path"] for row in me_only["items"]} == {"/v1/me"}
    refused = ok(
        admin.get("/v1/admin/audit", params={"status_min": 400, "status_max": 499})
    )
    assert all(400 <= row["status_code"] <= 499 for row in refused["items"])
    named = ok(admin.get("/v1/admin/audit", params={"username": "nobody-at-all"}))
    assert named["total"] == 0
    bad = admin.get("/v1/admin/entity-changelog", params={"entity_type": "planet"})
    assert bad.json() == {"detail": "Invalid entity_type"}


def test_the_mail_tab_lists_both_outboxes(admin, mail):
    _, user_id = signed_in("viewer", email="owner@x.test")
    with SessionLocal() as db:
        db.add(
            Notification(
                recipient="share@x.test", subject="Shared", body="b", status="failed"
            )
        )
        db.add(
            SecurityNotification(
                user_id=user_id, recipient="owner@x.test", subject="Notice", body="b"
            )
        )
        db.commit()
    listed = ok(admin.get("/v1/admin/notifications"))
    assert (listed["pending"], listed["failed"]) == (1, 1)
    assert sorted((n["kind"], n["recipient"]) for n in listed["notifications"]) == [
        ("project", "share@x.test"),
        ("security", "owner@x.test"),
    ]
