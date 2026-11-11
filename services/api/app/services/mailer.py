from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.core.config import settings
from app.services import notifications as outbox


def smtp_configured() -> bool:
    return bool((settings.smtp_host or "").strip()) and bool(
        (settings.smtp_from_email or "").strip()
    )


def send_email(*, to_email: str, subject: str, body: str) -> None:
    """Transport used by the notification worker; raises on failure.

    The rest of the application never sends directly: it queues a
    notification row (see app/services/notifications.py), so delivery is
    observable and retried out of band.
    """
    _deliver_email(to_email=to_email, subject=subject, body=body)


def queue_email(
    db: Session,
    *,
    user_id: int | None,
    recipient: str,
    subject: str,
    body: str,
) -> None:
    """Queue through the caller's transaction-aware outbox."""
    if not smtp_configured() or not (recipient or "").strip():
        return
    outbox.queue_email(
        db, user_id=user_id, recipient=recipient, subject=subject, body=body
    )


def _deliver_email(*, to_email: str, subject: str, body: str) -> None:
    if not smtp_configured():
        return

    host = (settings.smtp_host or "").strip()
    port = int(getattr(settings, "smtp_port", 587) or 587)
    user = (settings.smtp_username or "").strip() or None
    pwd = (settings.smtp_password or "").strip() or None
    use_tls = bool(getattr(settings, "smtp_use_tls", True))
    use_ssl = bool(getattr(settings, "smtp_use_ssl", False))
    timeout = int(getattr(settings, "smtp_timeout_seconds", 20) or 20)

    from_email = (settings.smtp_from_email or "").strip()
    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"

    to_addr = (to_email or "").strip()
    if not to_addr:
        return

    msg = EmailMessage()
    # Subject text often carries user-controlled names; strip CR/LF so the
    # header line stays one line whatever a display name contains.
    msg["Subject"] = str(subject or "").replace("\r", " ").replace("\n", " ")
    msg["From"] = f"{from_name} <{from_email}>" if from_name else from_email
    msg["To"] = to_addr
    msg.set_content(body)

    context = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as s:
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
        return

    with smtplib.SMTP(host, port, timeout=timeout) as s:
        s.ehlo()
        if use_tls:
            s.starttls(context=context)
            s.ehlo()
        if user and pwd:
            s.login(user, pwd)
        s.send_message(msg)


def send_project_version_published_email(
    *,
    db: Session,
    user_id: int | None = None,
    to_email: str,
    project_name: str,
    version: str,
    project_url: str | None = None,
) -> None:
    """Notify a subscriber that a new project version was published."""

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
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
    user_id: int | None = None,
    to_email: str,
    project_name: str,
    version: str,
    project_url: str | None = None,
    source: str = "release feed",
) -> None:
    """Notify project owners that a draft version was auto-created."""

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
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
    user_id: int | None = None,
    to_email: str,
    manifest_name: str,
    shared_by_username: str | None = None,
    group_name: str | None = None,
    manifest_url: str | None = None,
) -> None:
    """Notify a user that a manifest was shared with their group."""

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
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
    user_id: int | None = None,
    to_email: str,
    project_name: str,
    question_body: str | None = None,
    project_url: str | None = None,
) -> None:
    """Notify a user that a new question was posted on a project."""

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
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
    user_id: int | None = None,
    to_email: str,
    project_name: str,
    reply_body: str | None = None,
    project_url: str | None = None,
) -> None:
    """Notify a user that a project question thread received a reply."""

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
    subject = f"{from_name}: New reply on {project_name}"

    preview = _preview_text(reply_body)
    body = f"Hello,\n\nA reply was posted to a question on '{project_name}'.\n\n"
    if preview:
        body += f"Reply: {preview}\n\n"
    if project_url:
        body += f"View project (Questions tab): {project_url}\n\n"
    body += "You are receiving this email because you subscribed to questions/replies for this project.\n"

    queue_email(db, user_id=user_id, recipient=to_email, subject=subject, body=body)
