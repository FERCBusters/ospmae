from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.api.payloads import ProjectQuestionCreatePayload, ProjectQuestionReplyPayload
from app.core.config import settings
from app.db.models import (
    Project,
    ProjectOwnerGroup,
    ProjectQuestionPost,
    ProjectQuestionThread,
    ProjectSubscription,
    User,
    UserGroup,
)
from app.db.session import get_db
from app.realtime.notifications import hub
from app.security.auth import get_current_user
from app.security.permissions import (
    PERM_PROJECT_ANSWER,
    PERM_PROJECT_QUESTION,
    has_permission,
)
from app.security.roles import (
    ROLE_ADMIN,
    ROLE_CONTRIBUTOR,
    ROLE_MAINTAINER,
    attach_effective_role,
)
from app.services.mailer import (
    send_project_question_created_email,
    send_project_question_replied_email,
)
from app.services.notification_recipients import (
    notification_email_for_user,
    notification_emails_for_users,
)

router = APIRouter(tags=["project-questions"])


logger = logging.getLogger(__name__)


def _public_project_url(project_id: int) -> str | None:
    base = str(getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
    if not base:
        return None
    # Link to the project page; users can switch to the Questions tab.
    return f"{base}/project.html?id={int(project_id)}"


def _subscriber_emails_questions(db: Session, *, project_id: int) -> list[str]:
    users = (
        db.query(User)
        .join(ProjectSubscription, ProjectSubscription.user_id == User.id)
        .filter(ProjectSubscription.project_id == project_id)
        .filter(ProjectSubscription.notify_questions.is_(True))
        .filter(User.is_active.is_(True))
        .all()
    )
    return notification_emails_for_users(db, users=users)


def _owner_emails(db: Session, *, project: Project) -> list[str]:
    users: dict[int, User] = {}

    if project.created_by_user_id:
        owner = (
            db.query(User)
            .filter(User.id == project.created_by_user_id)
            .filter(User.is_active.is_(True))
            .one_or_none()
        )
        if owner:
            users[owner.id] = owner

    owner_group_ids = _get_project_owner_group_ids(db, project.id)
    if owner_group_ids:
        group_users = (
            db.query(User)
            .join(UserGroup, UserGroup.user_id == User.id)
            .filter(UserGroup.group_id.in_(sorted(owner_group_ids)))
            .filter(User.is_active.is_(True))
            .all()
        )
        users.update({user.id: user for user in group_users})

    return notification_emails_for_users(db, users=list(users.values()))


def _notify_discussion_emails(
    db: Session,
    *,
    project: Project,
    actor: User,
    kind: str,
    body: str | None,
) -> None:
    """Email discussion notifications to owners and question-subscribers."""

    # If SMTP isn't configured, don't do anything.
    if not (
        str(getattr(settings, "smtp_host", "") or "").strip()
        and str(getattr(settings, "smtp_from_email", "") or "").strip()
    ):
        return

    url = _public_project_url(project.id)

    recipients: set[str] = set(_subscriber_emails_questions(db, project_id=project.id))
    recipients.update(_owner_emails(db, project=project))

    # Do not email the actor.
    actor_email = notification_email_for_user(db, user=actor)
    if actor_email:
        recipients.discard(actor_email)

    if not recipients:
        return

    for email in sorted(recipients):
        try:
            if kind == "question":
                send_project_question_created_email(
                    to_email=email,
                    project_name=project.display_name,
                    question_body=body,
                    project_url=url,
                )
            else:
                send_project_question_replied_email(
                    to_email=email,
                    project_name=project.display_name,
                    reply_body=body,
                    project_url=url,
                )
        except Exception:
            # Email failures should never break the request.
            logger.exception("Failed to send project question notification email")


def _get_user_group_ids(db: Session, user_id: int) -> set[int]:
    return {
        gid
        for (gid,) in db.query(UserGroup.group_id)
        .filter(UserGroup.user_id == user_id)
        .all()
    }


def _get_project_owner_group_ids(db: Session, project_id: int) -> set[int]:
    return {
        gid
        for (gid,) in db.query(ProjectOwnerGroup.group_id)
        .filter(ProjectOwnerGroup.project_id == project_id)
        .all()
    }


def _can_answer_project(db: Session, user: User, project: Project) -> bool:
    eff = attach_effective_role(db, user)
    if eff == ROLE_ADMIN:
        return True

    if not has_permission(db, user, PERM_PROJECT_ANSWER):
        return False

    owner_group_ids = _get_project_owner_group_ids(db, project.id)
    user_group_ids = _get_user_group_ids(db, user.id)
    shares_group = bool(owner_group_ids & user_group_ids)

    # Spec:
    # - maintainer: can answer if they own the project OR share a group with the project creator
    # - contributor: can answer if they share a group with the project creator
    if eff == ROLE_MAINTAINER:
        return project.created_by_user_id == user.id or shares_group

    if eff == ROLE_CONTRIBUTOR:
        return shares_group

    # If the user has the permission via a direct/group permission assignment, apply the same
    # group-based ownership rule.
    return shares_group or project.created_by_user_id == user.id


def _serialize_thread(thread: ProjectQuestionThread) -> dict[str, Any]:
    return {
        "id": thread.id,
        "project_id": thread.project_id,
        "status": thread.status,
        "project_display_name": thread.project.display_name if thread.project else None,
        "last_answer_at": (
            thread.last_answer_at.isoformat() if thread.last_answer_at else None
        ),
        "created_at": thread.created_at.isoformat() if thread.created_at else None,
        "updated_at": thread.updated_at.isoformat() if thread.updated_at else None,
        "created_by": {
            "id": thread.created_by_user.id if thread.created_by_user else None,
            "username": (
                thread.created_by_user.username if thread.created_by_user else None
            ),
        },
        "posts": [
            {
                "id": p.id,
                "body": p.body,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "created_by": {
                    "id": p.created_by_user.id if p.created_by_user else None,
                    "username": (
                        p.created_by_user.username if p.created_by_user else None
                    ),
                },
            }
            for p in (thread.posts or [])
        ],
    }


def _serialize_unanswered_thread(thread: ProjectQuestionThread) -> dict[str, Any]:
    first_post = None
    try:
        posts = list(thread.posts or [])
        first_post = posts[0] if posts else None
    except Exception:
        first_post = None

    body = (first_post.body if first_post else "") or ""
    body_preview = body.strip().replace("\n", " ")
    if len(body_preview) > 160:
        body_preview = body_preview[:159] + "…"

    return {
        "thread_id": thread.id,
        "project_id": thread.project_id,
        "project_display_name": thread.project.display_name if thread.project else None,
        "asked_by": {
            "id": thread.created_by_user.id if thread.created_by_user else None,
            "username": (
                thread.created_by_user.username if thread.created_by_user else None
            ),
        },
        "asked_at": thread.created_at.isoformat() if thread.created_at else None,
        "updated_at": thread.updated_at.isoformat() if thread.updated_at else None,
        "question_preview": body_preview,
    }


@router.get("/v1/questions/unanswered/summary")
def unanswered_questions_summary(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the count of currently-unanswered project questions the user can answer."""

    eff = attach_effective_role(db, user)
    if eff != ROLE_ADMIN and not has_permission(db, user, PERM_PROJECT_ANSWER):
        raise HTTPException(
            status_code=403, detail="Not permitted to answer project questions"
        )

    q = (
        db.query(ProjectQuestionThread)
        .options(joinedload(ProjectQuestionThread.project))
        .filter(ProjectQuestionThread.status == "open")
        .order_by(
            ProjectQuestionThread.updated_at.desc(), ProjectQuestionThread.id.desc()
        )
    )

    open_count = 0
    if eff == ROLE_ADMIN:
        open_count = q.count()
    else:
        # Apply project-specific answer permission.
        threads = q.all()
        for t in threads:
            if t.project and _can_answer_project(db, user, t.project):
                open_count += 1

    return {"open_count": int(open_count)}


@router.get("/v1/questions/unanswered")
def list_unanswered_questions(
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List unanswered (open) project questions the user can answer."""

    eff = attach_effective_role(db, user)
    if eff != ROLE_ADMIN and not has_permission(db, user, PERM_PROJECT_ANSWER):
        raise HTTPException(
            status_code=403, detail="Not permitted to answer project questions"
        )

    q = (
        db.query(ProjectQuestionThread)
        .options(
            joinedload(ProjectQuestionThread.project),
            joinedload(ProjectQuestionThread.created_by_user),
            joinedload(ProjectQuestionThread.posts).joinedload(
                ProjectQuestionPost.created_by_user
            ),
        )
        .filter(ProjectQuestionThread.status == "open")
        .order_by(
            ProjectQuestionThread.updated_at.desc(), ProjectQuestionThread.id.desc()
        )
        .limit(limit)
    )

    threads = q.all()
    visible: list[ProjectQuestionThread] = []

    if eff == ROLE_ADMIN:
        visible = threads
    else:
        for t in threads:
            if t.project and _can_answer_project(db, user, t.project):
                visible.append(t)

    return {
        "items": [_serialize_unanswered_thread(t) for t in visible],
        "open_count": len(visible),
    }


@router.get("/v1/me/questions")
def list_my_project_questions(
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    threads = (
        db.query(ProjectQuestionThread)
        .options(
            joinedload(ProjectQuestionThread.project),
            joinedload(ProjectQuestionThread.created_by_user),
            joinedload(ProjectQuestionThread.posts).joinedload(
                ProjectQuestionPost.created_by_user
            ),
        )
        .filter(ProjectQuestionThread.created_by_user_id == user.id)
        .order_by(
            ProjectQuestionThread.updated_at.desc(), ProjectQuestionThread.id.desc()
        )
        .limit(limit)
        .all()
    )
    return {"items": [_serialize_thread(t) for t in threads]}


@router.get("/v1/projects/{project_id}/questions")
def list_project_questions(
    project_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    eff = attach_effective_role(db, user)
    can_answer = _can_answer_project(db, user, project)

    q = (
        db.query(ProjectQuestionThread)
        .options(
            joinedload(ProjectQuestionThread.created_by_user),
            joinedload(ProjectQuestionThread.posts).joinedload(
                ProjectQuestionPost.created_by_user
            ),
        )
        .filter(ProjectQuestionThread.project_id == project_id)
        .order_by(
            ProjectQuestionThread.updated_at.desc(), ProjectQuestionThread.id.desc()
        )
    )

    # Non-admin users who cannot answer only see threads they created.
    if eff != ROLE_ADMIN and not can_answer:
        q = q.filter(ProjectQuestionThread.created_by_user_id == user.id)

    threads = q.all()
    return {"items": [_serialize_thread(t) for t in threads], "can_answer": can_answer}


@router.post("/v1/projects/{project_id}/questions")
async def create_project_question(
    project_id: int,
    payload: ProjectQuestionCreatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not has_permission(db, user, PERM_PROJECT_QUESTION):
        raise HTTPException(
            status_code=403, detail="Not permitted to ask project questions"
        )

    project = db.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    thread = ProjectQuestionThread(
        project_id=project_id,
        created_by_user_id=user.id,
        status="open",
    )
    post = ProjectQuestionPost(created_by_user_id=user.id, body=payload.body)
    thread.posts.append(post)

    db.add(thread)
    db.commit()
    db.refresh(thread)

    # Email subscribers (questions/replies) and project owners.
    _notify_discussion_emails(
        db, project=project, actor=user, kind="question", body=payload.body
    )

    # Notify admins + answerers for the project.
    recipients: set[int] = set()
    for u in db.query(User).filter(User.is_active == True).all():  # noqa: E712
        if (
            _can_answer_project(db, u, project)
            or attach_effective_role(db, u) == ROLE_ADMIN
        ):
            recipients.add(u.id)

    # Always include the question author (for multi-tab usage).
    recipients.add(user.id)

    await hub.broadcast(
        recipients,
        {
            "kind": "project_question_created",
            "thread_id": thread.id,
            "project_id": project.id,
            "project_display_name": project.display_name,
            "created_by_user_id": user.id,
        },
    )

    # Reload with relationships for response
    thread = (
        db.query(ProjectQuestionThread)
        .options(
            joinedload(ProjectQuestionThread.created_by_user),
            joinedload(ProjectQuestionThread.posts).joinedload(
                ProjectQuestionPost.created_by_user
            ),
        )
        .filter(ProjectQuestionThread.id == thread.id)
        .one()
    )
    return _serialize_thread(thread)


@router.post("/v1/questions/{thread_id}/reply")
async def reply_project_question(
    thread_id: int,
    payload: ProjectQuestionReplyPayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    thread = (
        db.query(ProjectQuestionThread)
        .options(joinedload(ProjectQuestionThread.posts))
        .filter(ProjectQuestionThread.id == thread_id)
        .one_or_none()
    )
    if not thread:
        raise HTTPException(status_code=404, detail="Question thread not found")

    project = db.query(Project).filter(Project.id == thread.project_id).one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    can_answer = _can_answer_project(db, user, project)
    is_author = thread.created_by_user_id == user.id
    eff = attach_effective_role(db, user)

    if not (eff == ROLE_ADMIN or can_answer or is_author):
        raise HTTPException(
            status_code=403, detail="Not permitted to reply to this question thread"
        )

    post = ProjectQuestionPost(
        thread_id=thread.id, created_by_user_id=user.id, body=payload.body
    )
    db.add(post)

    # If an answerer/admin replies, flip to answered; if author replies, flip back to open.
    now = datetime.utcnow()
    if eff == ROLE_ADMIN or can_answer:
        thread.status = "answered"
        thread.last_answer_at = now
    else:
        thread.status = "open"

    thread.updated_at = now
    db.add(thread)

    db.commit()

    # Email subscribers (questions/replies) and project owners.
    _notify_discussion_emails(
        db, project=project, actor=user, kind="reply", body=payload.body
    )

    # Notify the author and answerers/admins.
    recipients: set[int] = set()
    for u in db.query(User).filter(User.is_active == True).all():  # noqa: E712
        if (
            _can_answer_project(db, u, project)
            or attach_effective_role(db, u) == ROLE_ADMIN
        ):
            recipients.add(u.id)

    recipients.add(thread.created_by_user_id)

    await hub.broadcast(
        recipients,
        {
            "kind": "project_question_replied",
            "thread_id": thread.id,
            "project_id": project.id,
            "project_display_name": project.display_name,
            "created_by_user_id": user.id,
        },
    )

    # Return refreshed thread
    thread = (
        db.query(ProjectQuestionThread)
        .options(
            joinedload(ProjectQuestionThread.created_by_user),
            joinedload(ProjectQuestionThread.posts).joinedload(
                ProjectQuestionPost.created_by_user
            ),
        )
        .filter(ProjectQuestionThread.id == thread.id)
        .one()
    )
    return _serialize_thread(thread)
