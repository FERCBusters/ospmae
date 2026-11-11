"""Every e-mail a request queues reaches the committed outbox.

A request's session discards whatever it has not committed when it closes.
These senders once queued their mail after the request's last commit, so the
mail never left: each case here reads the outbox from a fresh session.
"""

from __future__ import annotations

from app.core.config import settings
from app.db.models import Group, User, UserGroup
from app.db.session import SessionLocal

from tests.conftest import auth_client, make_user


def _csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("ospmae_csrf") or ""}


def _admin():
    admin, _user = auth_client(role="admin")
    return admin


def _recipients(outbox, subject_part: str) -> list[str]:
    return sorted(m.recipient for m in outbox.messages() if subject_part in m.subject)


def test_approving_a_pending_account_mails_it(outbox):
    admin = _admin()
    waiting = make_user("waiting", "Waiting-pass1!", role="pending", email="w@x.test")

    response = admin.patch(
        f"/v1/admin/users/{waiting.id}", json={"role": "viewer"}, headers=_csrf(admin)
    )
    assert response.status_code == 200, response.text
    assert _recipients(outbox, "approved") == ["w@x.test"]
    assert outbox.kicks == [{"retry": False}]

    # Changing an already approved account again sends nothing more.
    admin.patch(
        f"/v1/admin/users/{waiting.id}", json={"role": "engineer"}, headers=_csrf(admin)
    )
    assert len(outbox.messages()) == 1


def _inheriting(username: str, email: str, group_id: int) -> User:
    """An account whose role comes from its groups."""
    user = make_user(username, "Inherit-pass1!", role="inherit", email=email)
    with SessionLocal() as s:
        s.add(UserGroup(user_id=user.id, group_id=group_id))
        s.commit()
    return user


def _group(name: str, role: str | None) -> int:
    with SessionLocal() as s:
        group = Group(name=name, role=role)
        s.add(group)
        s.commit()
        return group.id


def test_access_that_approves_an_account_mails_it(outbox):
    admin = _admin()
    waiting = _inheriting("grouped", "g@x.test", _group("arrivals", "pending"))
    group_id = _group("readers", "viewer")

    response = admin.put(
        f"/v1/admin/users/{waiting.id}/access",
        json={"group_ids": [group_id], "permission_ids": []},
        headers=_csrf(admin),
    )
    assert response.status_code == 200, response.text
    assert _recipients(outbox, "approved") == ["g@x.test"]


def test_a_group_role_that_approves_its_members_mails_them(outbox):
    admin = _admin()
    group_id = _group("newcomers", "pending")
    _inheriting("member-a", "a@x.test", group_id)
    _inheriting("member-b", "b@x.test", group_id)

    response = admin.patch(
        f"/v1/admin/groups/{group_id}", json={"role": "viewer"}, headers=_csrf(admin)
    )
    assert response.status_code == 200, response.text
    assert _recipients(outbox, "approved") == ["a@x.test", "b@x.test"]


def _project_with_subscriber(admin, *, questions: bool = False) -> int:
    project = admin.post(
        "/v1/projects",
        json={"machine_name": "mailed", "display_name": "Mailed"},
        headers=_csrf(admin),
    )
    assert project.status_code == 200, project.text
    project_id = project.json()["id"]
    subscriber, _user = auth_client(role="viewer")
    with SessionLocal() as s:
        s.get(User, _user.id).email = "sub@x.test"
        s.commit()
    response = subscriber.post(
        f"/v1/projects/{project_id}/subscription",
        json={"notify_new_versions": True, "notify_questions": questions},
        headers=_csrf(subscriber),
    )
    assert response.status_code == 200, response.text
    return project_id


def test_publishing_a_version_mails_its_subscribers(outbox):
    admin = _admin()
    project_id = _project_with_subscriber(admin)

    published = admin.post(
        f"/v1/projects/{project_id}/versions",
        json={"version": "1.0.0", "status": "released"},
        headers=_csrf(admin),
    )
    assert published.status_code == 200, published.text
    assert _recipients(outbox, "New release for Mailed (1.0.0)") == ["sub@x.test"]

    # A draft is quiet until it is published.
    draft = admin.post(
        f"/v1/projects/{project_id}/versions",
        json={"version": "1.1.0", "status": "released", "is_draft": True},
        headers=_csrf(admin),
    )
    assert draft.status_code == 200, draft.text
    assert _recipients(outbox, "(1.1.0)") == []
    response = admin.put(
        f"/v1/project-versions/{draft.json()['id']}",
        json={"is_draft": False},
        headers=_csrf(admin),
    )
    assert response.status_code == 200, response.text
    assert _recipients(outbox, "New release for Mailed (1.1.0)") == ["sub@x.test"]


def test_questions_and_replies_mail_the_project_followers(outbox):
    admin = _admin()
    with SessionLocal() as s:
        s.query(User).filter(User.role == "admin").update({"email": "owner@x.test"})
        s.commit()
    project_id = _project_with_subscriber(admin, questions=True)
    asker, _user = auth_client(role="engineer")

    question = asker.post(
        f"/v1/projects/{project_id}/questions",
        json={"body": "Which licence?"},
        headers=_csrf(asker),
    )
    assert question.status_code == 200, question.text
    assert _recipients(outbox, "New question on Mailed") == [
        "owner@x.test",
        "sub@x.test",
    ]

    reply = admin.post(
        f"/v1/questions/{question.json()['id']}/reply",
        json={"body": "MIT."},
        headers=_csrf(admin),
    )
    assert reply.status_code == 200, reply.text
    # The project owner replied, so only the subscriber hears of it.
    assert _recipients(outbox, "New reply on Mailed") == ["sub@x.test"]


def test_sharing_a_manifest_mails_the_group(outbox):
    sharer, sharer_user = auth_client(role="admin")
    colleague = make_user(
        "colleague", "Colleague-pass1!", role="admin", email="c@x.test"
    )
    with SessionLocal() as s:
        group = Group(name="architects")
        s.add(group)
        s.flush()
        s.add_all(
            [
                UserGroup(user_id=sharer_user.id, group_id=group.id),
                UserGroup(user_id=colleague.id, group_id=group.id),
            ]
        )
        s.commit()
        group_id = group.id
    saved = sharer.post(
        "/v1/manifests", json={"name": "Platform"}, headers=_csrf(sharer)
    )
    assert saved.status_code == 200, saved.text

    response = sharer.patch(
        f"/v1/manifests/{saved.json()['id']}/sharing",
        json={"owner_group_id": group_id},
        headers=_csrf(sharer),
    )
    assert response.status_code == 200, response.text
    # The sharer is in the group but is not told about their own share.
    assert _recipients(outbox, "Manifest shared with your group") == ["c@x.test"]


def test_header_provisioned_accounts_notify_administrators(outbox, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    from tests.conftest import peer_wrapper

    monkeypatch.setattr(settings, "trust_remote_user", True)
    monkeypatch.setattr(settings, "remote_user_auto_provision", True)
    monkeypatch.setattr(settings, "admin_notification_email", "admins@x.test")
    c = TestClient(peer_wrapper(app), base_url="https://testserver")
    c.headers.update({"X-Test-Peer": "127.0.0.1", "REMOTE_USER": "newcomer"})

    assert c.get("/v1/me").status_code == 200
    [notice] = outbox.messages()
    assert notice.recipient == "admins@x.test"
    assert "New user awaiting review - newcomer" in notice.subject
    assert "trusted remote-user" in notice.body


def test_sso_provisioned_accounts_notify_administrators(outbox, monkeypatch):
    from app.security import oidc

    monkeypatch.setattr(settings, "admin_notification_email", "admins@x.test")
    provider = oidc.SsoProvider(
        key="oidc",
        kind="oidc",
        label="Company SSO",
        enabled=True,
        client_id="client",
        client_secret="secret",
        authorization_endpoint="https://idp.x.test/auth",
        token_endpoint="https://idp.x.test/token",
        scopes="openid email",
        issuer="https://idp.x.test",
        auto_provision=True,
    )
    with SessionLocal() as s:
        user = oidc._get_or_create_user_for_identity(
            s,
            provider=provider,
            subject="subject-1",
            claims={"preferred_username": "fresh", "email": "fresh@x.test"},
        )
        assert user.username == "fresh"

    [notice] = outbox.messages()
    assert notice.recipient == "admins@x.test"
    assert "New user awaiting review - fresh" in notice.subject
    assert "Company SSO" in notice.body
