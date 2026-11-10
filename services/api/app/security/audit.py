from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def log_audit_event(
    db: Session,
    user_id: int | None,
    event_type: str,
    action: str,
    resource_type: str | None = None,
    resource_id: int | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Compatibility shim for older event-style audit calls.

    OSPMAE now mirrors KEEN's audit design:
      * audit_logs stores request-level UI/API metadata from middleware;
      * entity_changelogs stores semantic before/after business changes.

    Existing authentication code still calls these helpers, but the request audit
    middleware records the actual /v1/auth/* request once the response completes.
    Keeping this shim avoids duplicate rows and ensures audit logging can never
    break the request path.
    """

    logger.debug(
        "event-style audit call ignored after Keen-style audit migration: %s/%s user=%s resource=%s:%s details=%s ip=%s ua=%s db=%s",
        event_type,
        action,
        user_id,
        resource_type,
        resource_id,
        details or {},
        ip_address,
        user_agent,
        type(db).__name__,
    )


def log_login_success(
    db: Session,
    user_id: int,
    auth_method: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=user_id,
        event_type="authentication",
        action="login_success",
        details={"auth_method": auth_method},
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_login_failure(
    db: Session,
    username: str,
    reason: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=None,
        event_type="authentication",
        action="login_failure",
        details={"username": username, "reason": reason},
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_logout(
    db: Session,
    user_id: int | None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=user_id,
        event_type="authentication",
        action="logout",
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_password_reset_request(
    db: Session,
    user_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=user_id,
        event_type="password_reset",
        action="reset_requested",
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_password_reset_confirm(
    db: Session,
    user_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=user_id,
        event_type="password_reset",
        action="reset_confirmed",
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_resource_access(
    db: Session,
    user_id: int,
    resource_type: str,
    resource_id: int,
    action: str = "read",
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=user_id,
        event_type="access",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_resource_modify(
    db: Session,
    user_id: int,
    resource_type: str,
    resource_id: int,
    action: str,
    changes: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=user_id,
        event_type="modification",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=changes or {},
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_permission_change(
    db: Session,
    actor_user_id: int,
    target_user_id: int,
    permission: str,
    granted: bool,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=actor_user_id,
        event_type="authorization",
        action="permission_granted" if granted else "permission_revoked",
        resource_type="user",
        resource_id=target_user_id,
        details={"permission": permission},
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_role_change(
    db: Session,
    actor_user_id: int,
    target_user_id: int,
    old_role: str,
    new_role: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=actor_user_id,
        event_type="authorization",
        action="role_changed",
        resource_type="user",
        resource_id=target_user_id,
        details={"old_role": old_role, "new_role": new_role},
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_security_alert(
    db: Session,
    alert_type: str,
    details: dict[str, Any],
    user_id: int | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    log_audit_event(
        db=db,
        user_id=user_id,
        event_type="security_alert",
        action=alert_type,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )
