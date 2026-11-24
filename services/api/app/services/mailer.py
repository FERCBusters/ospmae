"""OSPMAE's own notices: project releases, drafts, shared manifests and
question threads.

Each is queued in the caller's transaction through OSPMAE's outbox
(app.services.notifications), which mosp's mail transport
(mosp.services.mailer) delivers out of band.
"""

from __future__ import annotations

import uuid

from mosp.services.mailer import sender_name, smtp_configured
from sqlalchemy.orm import Session

from app.services import notifications as outbox


def single_line(text: str | None) -> str:
    """Header text on one line.

    A message header refuses every character str.splitlines() breaks at (CR,
    LF, VT, FF, the separators FS, GS and RS, NEL, and the Unicode line and
    paragraph separators), and a refused subject fails the mail on every
    attempt, so a name that carries one is flattened here.
    """
    return " ".join(str(text or "").splitlines()) if text else ""


def queue_email(
    db: Session,
    *,
    user_id: uuid.UUID | None,
    recipient: str,
    subject: str,
    body: str,
) -> None:
    """Queue through the caller's transaction-aware outbox, with the subject
    on one line."""
    if not smtp_configured() or not (recipient or "").strip():
        return
    outbox.queue_email(
        db,
        user_id=user_id,
        recipient=recipient,
        subject=single_line(subject),
        body=body,
    )


def send_project_version_published_email(
    *,
    db: Session,
    user_id: uuid.UUID | None = None,
    to_email: str,
    project_name: str,
    version: str,
    project_url: str | None = None,
) -> None:
    """Notify a subscriber that a new project version was published."""

    from_name = sender_name()
    subject = f"{from_name}: New release for {project_name} ({version})"

    body = (
        f"Hello,\n\nA new version of '{project_name}' has been published: {version}\n\n"
    )
    if project_url:
        body += f"View project: {project_url}\n\n"
    body += "You are receiving this email because you subscribed to this project.\n"

    queue_email(db, user_id=user_id, recipient=to_email, subject=subject, body=body)


def send_project_version_draft_email(
    *,
    db: Session,
    user_id: uuid.UUID | None = None,
    to_email: str,
    project_name: str,
    version: str,
    project_url: str | None = None,
    source: str = "release feed",
) -> None:
    """Notify project owners that a draft version was auto-created."""

    from_name = sender_name()
    subject = f"{from_name}: Draft release detected for {project_name} ({version})"

    body = (
        f"Hello,\n\n"
        f"OSPMAE detected a new release for '{project_name}' from {source} and created it as a DRAFT: {version}\n\n"
        f"Draft releases are hidden from general browsing and do not notify subscribers until you publish them.\n\n"
    )
    if project_url:
        body += f"Review/publish: {project_url}\n\n"
    body += "If this release is correct, edit the version and uncheck 'Draft' to publish it.\n"

    queue_email(db, user_id=user_id, recipient=to_email, subject=subject, body=body)


def send_manifest_shared_email(
    *,
    db: Session,
    user_id: uuid.UUID | None = None,
    to_email: str,
    manifest_name: str,
    shared_by_username: str | None = None,
    group_name: str | None = None,
    manifest_url: str | None = None,
) -> None:
    """Notify a user that a manifest was shared with their group."""

    from_name = sender_name()
    subject = f"{from_name}: Manifest shared with your group - {manifest_name}"

    who = (shared_by_username or "").strip() or "Someone"
    group_label = (group_name or "").strip() or "your group"

    body = (
        f"Hello,\n\n"
        f"{who} shared a saved manifest with {group_label} in OSPMAE.\n\n"
        f"Manifest: {manifest_name}\n\n"
    )
    if manifest_url:
        body += f"Open it here: {manifest_url}\n\n"
    body += "Log in to OSPMAE and open the 'Saved manifests' page to view, export, or clone it.\n"

    queue_email(db, user_id=user_id, recipient=to_email, subject=subject, body=body)


def _preview_text(value: str | None, limit: int = 240) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    s = " ".join(s.split())
    if len(s) <= limit:
        return s
    return s[: limit - 1] + "…"


def send_project_question_created_email(
    *,
    db: Session,
    user_id: uuid.UUID | None = None,
    to_email: str,
    project_name: str,
    question_body: str | None = None,
    project_url: str | None = None,
) -> None:
    """Notify a user that a new question was posted on a project."""

    from_name = sender_name()
    subject = f"{from_name}: New question on {project_name}"

    preview = _preview_text(question_body)
    body = f"Hello,\n\nA new question was posted on '{project_name}'.\n\n"
    if preview:
        body += f"Question: {preview}\n\n"
    if project_url:
        body += f"View project (Questions tab): {project_url}\n\n"
    body += "You are receiving this email because you subscribed to questions/replies for this project.\n"

    queue_email(db, user_id=user_id, recipient=to_email, subject=subject, body=body)


def send_project_question_replied_email(
    *,
    db: Session,
    user_id: uuid.UUID | None = None,
    to_email: str,
    project_name: str,
    reply_body: str | None = None,
    project_url: str | None = None,
) -> None:
    """Notify a user that a project question thread received a reply."""

    from_name = sender_name()
    subject = f"{from_name}: New reply on {project_name}"

    preview = _preview_text(reply_body)
    body = f"Hello,\n\nA reply was posted to a question on '{project_name}'.\n\n"
    if preview:
        body += f"Reply: {preview}\n\n"
    if project_url:
        body += f"View project (Questions tab): {project_url}\n\n"
    body += "You are receiving this email because you subscribed to questions/replies for this project.\n"

    queue_email(db, user_id=user_id, recipient=to_email, subject=subject, body=body)
