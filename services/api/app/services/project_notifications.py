"""Who hears about a project's releases, and the link the mail carries.

Publishing a version tells the project's subscribers, whether a maintainer
published it (app/api/routes/projects.py) or the release feed did for a
project that publishes new releases automatically (app/tasks/release_feed.py).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Project, ProjectSubscription, ProjectVersion, User
from app.services.mailer import send_project_version_published_email
from app.services.notification_recipients import notification_emails_for_users
from app.tasks.notifications import commit_and_kick


def public_project_url(project_id: int) -> str | None:
    """The project page's public address, when the installation has one."""

    base = settings.public_base_url.strip().rstrip("/")
    if not base:
        return None
    return f"{base}/project.html?id={int(project_id)}"


def subscriber_emails(
    db: Session, *, project_id: int, kind: str = "new_versions"
) -> list[str]:
    """Subscriber e-mail addresses for a notification kind."""

    q = (
        db.query(User)
        .join(ProjectSubscription, ProjectSubscription.user_id == User.id)
        .filter(ProjectSubscription.project_id == project_id)
        .filter(User.is_active.is_(True))
    )

    if kind == "questions":
        q = q.filter(ProjectSubscription.notify_questions.is_(True))
    else:
        q = q.filter(ProjectSubscription.notify_new_versions.is_(True))

    return notification_emails_for_users(db, users=q.all())


def notify_subscribers_published(
    db: Session, *, project: Project, version: ProjectVersion
) -> None:
    """Mail the project's subscribers about a version that is now published."""

    # Drafts never notify subscribers.
    if version.is_draft:
        return

    url = public_project_url(project.id)
    for email in subscriber_emails(db, project_id=project.id):
        send_project_version_published_email(
            db=db,
            to_email=email,
            project_name=project.display_name,
            version=version.version,
            project_url=url,
        )
    # The version was committed before this mail was queued.
    commit_and_kick(db)
