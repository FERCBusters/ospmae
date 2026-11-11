"""Security notices to an account's owner, ported from KEEN.

Each notice is queued through the e-mail outbox in the caller's transaction,
so it commits with the change it reports. Every completed sign-in also
records its client address against the account; the first sign-in from an
address not seen before sends a notice.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import User, UserLoginIP
from app.services.mailer import queue_email, smtp_configured
from app.services.notification_recipients import notification_email_for_user

# KEEN's events, worded for OSPMAE. KEEN's MCP connection and administrator
# password reset have no OSPMAE counterpart; OSPMAE adds the change of the
# address that receives these notices, which its users can change themselves.
TITLES = {
    "login-ip": "Sign-in from an unfamiliar IP address",
    "password-changed": "Your OSPMAE password was changed",
    "factor-enrolled": "An authenticator was added to your OSPMAE account",
    "factor-removed": "An authenticator was removed from your OSPMAE account",
    "recovery-codes-regenerated": "Your OSPMAE recovery codes were replaced",
    "operator-reset": "Your OSPMAE two-factor authentication was reset by an operator",
    "verified-recovery": "A recovery code was used for your OSPMAE account",
    "verification-ended": (
        "OSPMAE ended a two-factor verification after repeated incorrect codes"
    ),
    "email-verified": "An email address was verified for your OSPMAE account",
    "email-removed": "An email address was removed from your OSPMAE account",
    "notice-address-changed": (
        "Notices for your OSPMAE account now go to a different email address"
    ),
}

UNFAMILIAR_ADDRESS = TITLES["login-ip"]


def _event_detail(event: str, *, email: str | None) -> str:
    """The paragraph a notice adds about its own event, if any."""
    from app.security.mfa import CODE_ATTEMPTS

    if event == "login-ip":
        return (
            "This address has not previously been recorded for a successful "
            "sign-in to this account. A VPN, mobile connection or changing ISP "
            "address can cause this alert."
        )
    if event == "verification-ended":
        return (
            f"Your password was accepted and {CODE_ATTEMPTS} incorrect "
            "authenticator or recovery codes were entered within an hour, so "
            "OSPMAE accepts no code for this account for the next hour; a "
            "security key still signs you in. If this was not you, someone may "
            "know your password: change it and contact your OSPMAE administrator."
        )
    if event == "verified-recovery":
        return (
            "Each recovery code works once. Replace your recovery codes under "
            "Account when few remain."
        )
    if event == "operator-reset":
        return (
            "An operator removed this account's authenticators and recovery "
            "codes, and its signed-in sessions ended. Enrol an authenticator "
            "again under Account."
        )
    if event == "email-verified":
        return (
            f"Address: {email}\n\nA verified address can link a single sign-on "
            "identity that reports it to this account."
        )
    if event == "email-removed":
        return f"Address: {email}"
    if event == "notice-address-changed":
        return (
            f"New address: {email}\n\nThis notice goes to the address that "
            "received this account's notices until now."
        )
    return ""


def enqueue(
    db: Session,
    user: User,
    event: str,
    *,
    ip: str | None,
    email: str | None = None,
    recipient: str | None = None,
) -> bool:
    """Queue a security notice in the caller's transaction.

    ``email`` names the address an address event concerns; ``recipient``
    overrides the account's notification address, for a notice that must
    reach the address being replaced. Returns True when a notice was queued.
    """

    title = TITLES[event]
    to = (recipient or notification_email_for_user(db, user=user) or "").strip()
    if not smtp_configured() or not to:
        return False
    from_name = (settings.smtp_from_name or "OSPMAE").strip() or "OSPMAE"
    installation = (settings.public_base_url or "").strip().rstrip("/")
    lines = [f"{title}.", "", f"Account: {user.username}"]
    if installation:
        lines.append(f"OSPMAE installation: {installation}")
    lines += [
        f"Time (UTC): {datetime.utcnow().isoformat(timespec='seconds')}Z",
        f"IP address: {ip or 'Unavailable (operator action or unknown address)'}",
        "",
    ]
    detail = _event_detail(event, email=email)
    if detail:
        lines += [detail, ""]
    lines.append(
        "If this was you, no action is needed. If you do not recognise this "
        "activity, open your known OSPMAE address directly and contact your "
        "OSPMAE administrator. Review your password and authenticators."
    )
    queue_email(
        db,
        user_id=user.id,
        recipient=to,
        subject=f"{from_name} security: {title}",
        body="\n".join(lines) + "\n",
    )
    return True


def record_login(db: Session, user: User, *, ip: str | None) -> bool:
    """Record a completed sign-in's address in the caller's transaction.

    Returns True when a notice was queued: the address is new for the account
    and mail can be sent. The account/address key is unique, so parallel
    sign-ins from one new address queue a single notice.
    """

    address = (ip or "").strip()
    if not address:
        return False
    created = db.execute(
        insert(UserLoginIP)
        .values(user_id=user.id, address=address, first_seen_at=datetime.utcnow())
        .on_conflict_do_nothing()
        .returning(UserLoginIP.address)
    ).scalar_one_or_none()
    if created is None:
        return False
    return enqueue(db, user, "login-ip", ip=address)
