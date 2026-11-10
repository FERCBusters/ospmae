from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from app.core.config import settings


def _smtp_config_ok() -> bool:
    return bool((settings.smtp_host or "").strip()) and bool(
        (settings.smtp_from_email or "").strip()
    )


def send_password_reset_email(
    *, to_email: str, username: str, reset_link: str, expires_minutes: int
) -> None:
    """Send a password reset email.

    This is intentionally small + stdlib-only.
    """

    if not _smtp_config_ok():
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
    msg["Subject"] = f"{from_name}: Password reset"
    msg["From"] = f"{from_name} <{from_email}>" if from_name else from_email
    msg["To"] = to_addr

    safe_user = username or "your account"

    body = (
        f"Hello {safe_user},\n\n"
        f"A password reset was requested for your OSPMAE account.\n\n"
        f"Reset your password using this one-time link (valid for {expires_minutes} minutes):\n\n"
        f"{reset_link}\n\n"
        f"If you did not request this, you can ignore this email.\n"
    )

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


def send_new_user_admin_notification_email(
    *,
    username: str,
    email: str | None = None,
    provider_label: str | None = None,
    role: str | None = None,
    admin_url: str | None = None,
) -> None:
    """Notify administrators that a new user was auto-provisioned.

    The recipient is configured with OSPMAE_ADMIN_NOTIFICATION_EMAIL. It may be
    a single email address or a comma-separated list accepted by SMTP.
    """

    to_email = (getattr(settings, "admin_notification_email", "") or "").strip()
    if not to_email:
        return

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
    safe_username = (username or "").strip() or "unknown"
    safe_role = (role or "pending").strip() or "pending"
    source = (provider_label or "SSO").strip() or "SSO"

    subject = f"{from_name}: New user awaiting review - {safe_username}"
    body = (
        "Hello,\n\n"
        f"A new OSPMAE user has been auto-created after signing in with {source}.\n\n"
        f"Username: {safe_username}\n"
        f"Email: {(email or '').strip() or 'not provided'}\n"
        f"Initial role: {safe_role}\n\n"
        "If this user should have access, sign in as an administrator, open the "
        "Admin page, review the account, and change the role or group membership "
        "as appropriate.\n"
    )
    if admin_url:
        body += f"\nAdmin page: {admin_url}\n"
    body += "\nIf this sign-in was unexpected, leave the user pending or disable the account.\n"

    _send_email(to_email=to_email, subject=subject, body=body)


def _send_email(*, to_email: str, subject: str, body: str) -> None:
    if not _smtp_config_ok():
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


def send_account_approved_email(
    *,
    to_email: str,
    username: str | None = None,
    login_url: str | None = None,
) -> None:
    """Notify a pending user that an administrator has granted access."""

    recipient = (to_email or "").strip()
    if not recipient:
        return

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
    safe_username = (username or "").strip()
    subject = f"{from_name}: Your account has been approved"

    greeting = f"Hello {safe_username}," if safe_username else "Hello,"
    body = (
        f"{greeting}\n\n"
        "An administrator has approved your OSPMAE account. You can now sign in "
        "and use the application.\n"
    )
    if login_url:
        body += f"\nSign in: {login_url}\n"

    _send_email(to_email=recipient, subject=subject, body=body)


def send_project_version_published_email(
    *,
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

    _send_email(to_email=to_email, subject=subject, body=body)


def send_project_version_draft_email(
    *,
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

    _send_email(to_email=to_email, subject=subject, body=body)


def send_manifest_shared_email(
    *,
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

    _send_email(to_email=to_email, subject=subject, body=body)


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

    _send_email(to_email=to_email, subject=subject, body=body)


def send_project_question_replied_email(
    *,
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

    _send_email(to_email=to_email, subject=subject, body=body)


def send_email_verification_email(
    *,
    to_email: str,
    username: str | None,
    verification_link: str,
) -> None:
    """Send the one-time mailbox verification link for a self-asserted address."""

    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
    subject = f"{from_name}: Verify your email address"

    safe_user = (username or "").strip() or "your account"
    body = (
        f"Hello {safe_user},\n\n"
        "A verification was requested for this email address on OSPMAE.\n\n"
        "Confirm this mailbox with the one-time link below (valid for 24 hours):\n\n"
        f"{verification_link}\n\n"
        "If you did not request this, you can ignore this email.\n"
    )

    _send_email(to_email=to_email, subject=subject, body=body)
