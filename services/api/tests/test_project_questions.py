"""Questions on a project: who may ask, who may answer, what each reader sees,
and who is told."""

from __future__ import annotations

import pytest
from app.api.routes import project_questions
from app.db.models import ProjectQuestionThread
from app.db.session import SessionLocal

from tests.support import csrf, make_group, make_project, ok, signed_in


@pytest.fixture()
def told(monkeypatch):
    """The live notices the hub would push, as (recipients, payload)."""
    sent: list[tuple[set[int], dict]] = []

    async def broadcast(user_ids, payload):
        sent.append((set(user_ids), payload))

    monkeypatch.setattr(project_questions.hub, "broadcast", broadcast)
    return sent


def ask(client, project_id, body="How does it rotate keys?"):
    return client.post(
        f"/v1/projects/{project_id}/questions",
        json={"body": body},
        headers=csrf(client),
    )


def reply(client, thread_id, body="It rotates daily."):
    return client.post(
        f"/v1/questions/{thread_id}/reply", json={"body": body}, headers=csrf(client)
    )


def test_a_question_goes_from_open_to_answered_and_back(told):
    admin, admin_id = signed_in("admin")
    owner, owner_id = signed_in("maintainer")
    asker, asker_id = signed_in("engineer")
    pid = make_project(owner, "alpha", display_name="Alpha")["id"]

    thread = ok(ask(asker, pid))
    assert (thread["status"], thread["project_id"], thread["last_answer_at"]) == (
        "open",
        pid,
        None,
    )
    assert thread["created_by"]["id"] == asker_id
    assert [p["body"] for p in thread["posts"]] == ["How does it rotate keys?"]
    recipients, notice = told[-1]
    # The owner, administrators and the asker hear of it at once.
    assert recipients == {admin_id, owner_id, asker_id}
    assert notice == {
        "kind": "project_question_created",
        "thread_id": thread["id"],
        "project_id": pid,
        "project_display_name": "Alpha",
        "created_by_user_id": asker_id,
    }

    answered = ok(reply(owner, thread["id"]))
    assert answered["status"] == "answered"
    assert answered["last_answer_at"] is not None
    assert [p["created_by"]["id"] for p in answered["posts"]] == [asker_id, owner_id]
    assert told[-1][1]["kind"] == "project_question_replied"
    assert told[-1][0] == {admin_id, owner_id, asker_id}

    # The asker following up reopens it; an administrator's reply settles it.
    assert ok(reply(asker, thread["id"], "And on restart?"))["status"] == "open"
    settled = ok(reply(admin, thread["id"], "Also on restart."))
    assert settled["status"] == "answered"
    assert len(settled["posts"]) == 4

    assert reply(owner, 999999).status_code == 404
    assert ask(asker, 999999).status_code == 404
    assert ask(asker, pid, "").status_code == 422
    assert ask(asker, pid, "x" * 4001).status_code == 422


def test_asking_and_answering_follow_role_and_ownership(told):
    admin, _ = signed_in("admin")
    owner, owner_id = signed_in("maintainer")
    teammate, teammate_id = signed_in("contributor")
    make_group("Team", members=[owner_id, teammate_id])
    other_maintainer, _ = signed_in("maintainer")
    lone_contributor, _ = signed_in("contributor")
    asker, _ = signed_in("architect")
    viewer, _ = signed_in("viewer")
    pid = make_project(owner, "alpha")["id"]

    # Asking needs the question permission; maintainers and viewers lack it.
    assert (
        viewer.post(
            f"/v1/projects/{pid}/questions", json={"body": "?"}, headers=csrf(viewer)
        ).status_code
        == 403
    )
    assert ask(owner, pid).status_code == 403
    thread = ok(ask(asker, pid))

    def can_answer(client):
        return ok(client.get(f"/v1/projects/{pid}/questions"))["can_answer"]

    assert [can_answer(c) for c in (admin, owner, teammate)] == [True, True, True]
    assert [
        can_answer(c) for c in (other_maintainer, lone_contributor, asker, viewer)
    ] == [
        False,
        False,
        False,
        False,
    ]
    for stranger in (other_maintainer, lone_contributor, viewer):
        assert reply(stranger, thread["id"]).status_code == 403
    assert ok(reply(teammate, thread["id"]))["status"] == "answered"
    with SessionLocal() as s:
        assert len(s.get(ProjectQuestionThread, thread["id"]).posts) == 2


def test_a_granted_answer_permission_still_needs_a_stake_in_the_project(told):
    from app.db.models import Permission, UserPermission
    from app.security.permissions import seed_default_permissions

    owner, owner_id = signed_in("maintainer")
    helper, helper_id = signed_in("viewer")
    outsider, outsider_id = signed_in("viewer")
    make_group("Team", members=[owner_id, helper_id])
    with SessionLocal() as s:
        seed_default_permissions(s)
        answer = s.query(Permission.id).filter_by(code="project.answer").scalar()
        for user_id in (helper_id, outsider_id):
            s.add(UserPermission(user_id=user_id, permission_id=answer))
        s.commit()
    pid = make_project(owner, "alpha")["id"]
    asker, _ = signed_in("engineer")
    thread = ok(ask(asker, pid))

    assert ok(helper.get(f"/v1/projects/{pid}/questions"))["can_answer"] is True
    assert ok(outsider.get(f"/v1/projects/{pid}/questions"))["can_answer"] is False
    assert reply(outsider, thread["id"]).status_code == 403
    assert ok(reply(helper, thread["id"]))["status"] == "answered"
    # The permission opens the answer queue, limited to projects they can answer.
    assert ok(helper.get("/v1/questions/unanswered/summary")) == {"open_count": 0}
    ok(ask(asker, pid, "Another?"))
    assert ok(helper.get("/v1/questions/unanswered/summary")) == {"open_count": 1}
    assert ok(outsider.get("/v1/questions/unanswered/summary")) == {"open_count": 0}
    assert ok(outsider.get("/v1/questions/unanswered"))["items"] == []


def test_readers_see_their_own_threads_and_answerers_see_all(told):
    admin, _ = signed_in("admin")
    owner, _ = signed_in("maintainer")
    first, first_id = signed_in("engineer")
    second, _ = signed_in("engineer")
    pid = make_project(owner, "alpha", display_name="Alpha")["id"]
    other = make_project(owner, "beta")["id"]
    mine = ok(ask(first, pid, "First question"))
    ok(ask(second, pid, "Second question"))
    elsewhere = ok(ask(first, other, "On another project"))

    def bodies(client, project_id=pid):
        items = ok(client.get(f"/v1/projects/{project_id}/questions"))["items"]
        return [item["posts"][0]["body"] for item in items]

    assert bodies(first) == ["First question"]
    assert bodies(second) == ["Second question"]
    # Newest first for those who answer.
    assert bodies(owner) == bodies(admin) == ["Second question", "First question"]
    assert first.get("/v1/projects/999999/questions").status_code == 404

    own = ok(first.get("/v1/me/questions"))["items"]
    assert [(t["id"], t["project_display_name"]) for t in own] == [
        (elsewhere["id"], "Beta"),
        (mine["id"], "Alpha"),
    ]
    assert (
        ok(first.get("/v1/me/questions", params={"limit": 1}))["items"][0]["id"]
        == elsewhere["id"]
    )
    assert ok(owner.get("/v1/me/questions")) == {"items": []}


def test_the_answer_queue_lists_open_questions_the_account_may_answer(told):
    admin, _ = signed_in("admin")
    owner, _ = signed_in("maintainer")
    rival, _ = signed_in("maintainer")
    asker, asker_id = signed_in("engineer")
    mine = make_project(owner, "mine", display_name="Mine")["id"]
    theirs = make_project(rival, "theirs", display_name="Theirs")["id"]
    long_body = "Why  \n" + "x" * 300
    first = ok(ask(asker, mine, long_body))
    second = ok(ask(asker, theirs, "Short one"))
    done = ok(ask(asker, mine, "Already handled"))
    ok(reply(owner, done["id"]))

    assert ok(owner.get("/v1/questions/unanswered/summary")) == {"open_count": 1}
    assert ok(rival.get("/v1/questions/unanswered/summary")) == {"open_count": 1}
    assert ok(admin.get("/v1/questions/unanswered/summary")) == {"open_count": 2}

    queue = ok(owner.get("/v1/questions/unanswered"))
    assert queue["open_count"] == 1
    (item,) = queue["items"]
    assert (item["thread_id"], item["project_display_name"]) == (first["id"], "Mine")
    assert item["asked_by"]["id"] == asker_id
    # The preview is one line, cut to length.
    assert item["question_preview"].startswith("Why   x")
    assert len(item["question_preview"]) == 160 and item["question_preview"].endswith(
        "…"
    )

    everything = ok(admin.get("/v1/questions/unanswered"))
    assert [i["thread_id"] for i in everything["items"]] == [second["id"], first["id"]]
    assert everything["items"][0]["question_preview"] == "Short one"
    assert (
        ok(admin.get("/v1/questions/unanswered", params={"limit": 1}))["open_count"]
        == 1
    )

    for path in ("/v1/questions/unanswered", "/v1/questions/unanswered/summary"):
        assert asker.get(path).status_code == 403


def test_owners_and_question_subscribers_are_mailed_but_never_the_poster(told, outbox):
    owner, owner_id = signed_in("maintainer", email="owner@x.test")
    teammate, teammate_id = signed_in("viewer", email="teammate@x.test")
    make_group("Team", members=[owner_id, teammate_id])
    follower, _ = signed_in("viewer", email="follower@x.test")
    releases_only, _ = signed_in("viewer", email="releases@x.test")
    asker, _ = signed_in("engineer", email="asker@x.test")
    pid = make_project(owner, "alpha", display_name="Alpha")["id"]
    ok(
        follower.post(
            f"/v1/projects/{pid}/subscription",
            json={"notify_new_versions": False, "notify_questions": True},
            headers=csrf(follower),
        )
    )
    ok(
        releases_only.post(
            f"/v1/projects/{pid}/subscription", headers=csrf(releases_only)
        )
    )
    ok(
        asker.post(
            f"/v1/projects/{pid}/subscription",
            json={"notify_questions": True},
            headers=csrf(asker),
        )
    )

    thread = ok(ask(asker, pid, "Is it audited?"))
    asked = sorted(m.recipient for m in outbox.messages())
    assert asked == ["follower@x.test", "owner@x.test", "teammate@x.test"]
    first = outbox.messages()[0]
    assert "New question on Alpha" in first.subject
    assert "Is it audited?" in first.body
    assert "https://ospmae.example.com/project.html?id=" in first.body

    ok(reply(owner, thread["id"], "Yes, yearly."))
    replied = sorted(
        m.recipient for m in outbox.messages() if "New reply on Alpha" in m.subject
    )
    # The asker follows questions, so hears the answer; the answerer does not.
    assert replied == ["asker@x.test", "follower@x.test", "teammate@x.test"]


def test_questions_are_posted_without_a_mail_server(told, outbox, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "smtp_host", "")
    owner, _ = signed_in("maintainer", email="owner@x.test")
    asker, _ = signed_in("engineer")
    pid = make_project(owner, "alpha")["id"]
    assert ok(ask(asker, pid))["status"] == "open"
    assert outbox.messages() == []


def test_a_question_nobody_else_follows_mails_no_one(told, outbox):
    asker, _ = signed_in("admin", email="solo@x.test")
    pid = make_project(asker, "alpha")["id"]
    ok(ask(asker, pid))
    assert outbox.messages() == []


def test_questions_are_absent_while_the_feature_is_off(monkeypatch):
    from app.core.config import settings

    admin, _ = signed_in("admin")
    pid = make_project(admin, "alpha")["id"]
    monkeypatch.setattr(settings, "feature_questions", False)
    assert admin.get(f"/v1/projects/{pid}/questions").status_code == 404
    assert ask(admin, pid).status_code == 404
    assert admin.get("/v1/me/questions").status_code == 404
