"""Every e-mail a request queues reaches the committed outbox.

A request's session discards whatever it has not committed when it closes.
These senders once queued their mail after the request's last commit, so the
mail never left: each case here reads the outbox from a fresh session.
"""

from __future__ import annotations

from app.db.models import Group, User, UserGroup
from app.db.session import SessionLocal

from tests.conftest import auth_client, make_user


def _csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("__Host-ospmae_csrf") or ""}


def _admin():
    admin, _user = auth_client(role="admin")
    return admin


def _recipients(outbox, subject_part: str) -> list[str]:
    return sorted(m.recipient for m in outbox.messages() if subject_part in m.subject)


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
        "colleague", "Synthetic-passphrase-8!", role="admin", email="c@x.test"
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
