from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.api.deps import get_request_user, require_admin
from app.api.payloads import (
    AdminProjectOwnershipPayload,
    AdminUserCreatePayload,
    AdminUserUpdatePayload,
    OrganisationMemberPayload,
    OrganisationPayload,
)
from app.core.config import settings
from app.db.models import (
    AuditLog,
    Group,
    GroupPermission,
    Organisation,
    OrganisationMember,
    Permission,
    Project,
    ProjectOwnerGroup,
    User,
    UserEmail,
    UserGroup,
    UserPermission,
)
from app.db.session import get_db
from app.security.auth import create_user
from app.security.permissions import PERM_AUDITTRAIL_READ, has_permission
from app.security.roles import ROLE_PENDING, attach_effective_role, normalize_role
from app.services.entity_changelog import (
    list_entity_changelogs,
    project_changelog_state,
    record_entity_changelog,
)
from app.services.mailer import send_account_approved_email
from app.services.notification_recipients import notification_email_for_user

logger = logging.getLogger(__name__)

router = APIRouter()


def _login_url() -> str | None:
    base_url = (getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
    return f"{base_url}/login.html" if base_url else None


def _notify_if_pending_user_approved(
    db: Session, *, user: User, previous_effective_role: str | None
) -> None:
    """Notify a user only when they transition from pending to non-pending."""

    if (previous_effective_role or "").lower() != ROLE_PENDING:
        return
    current_effective_role = attach_effective_role(db, user)
    if current_effective_role == ROLE_PENDING:
        return
    if not bool(getattr(user, "is_active", False)):
        return

    recipient = notification_email_for_user(db, user=user)
    if not recipient:
        return

    try:
        send_account_approved_email(
            db=db,
            user_id=user.id,
            to_email=recipient,
            username=user.username,
            login_url=_login_url(),
        )
    except Exception:
        # Notification must never break the admin update path.
        pass


def require_audit_access(
    user: User = Depends(get_request_user), db: Session = Depends(get_db)
) -> User:
    eff = attach_effective_role(db, user)
    if eff != "admin" and not has_permission(db, user, PERM_AUDITTRAIL_READ):
        raise HTTPException(status_code=403, detail="Audit access required")
    return user


def _group_to_dict(g: Group) -> dict:
    return {
        "id": g.id,
        "name": g.name,
        "description": g.description,
        "role": g.role,
    }


def _permission_to_dict(p: Permission) -> dict:
    return {
        "id": p.id,
        "code": p.code,
        "description": p.description,
    }


@router.get("/v1/admin/users")
def list_users(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = db.query(User).order_by(User.username.asc()).all()
    out = []
    for u in users:
        eff = attach_effective_role(db, u)
        out.append(
            {
                "id": u.id,
                "username": u.username,
                "email": getattr(u, "email", None),
                "role": u.role,
                "effective_role": eff,
                "is_active": u.is_active,
                "created_at": u.created_at,
                "updated_at": u.updated_at,
                "last_login_at": u.last_login_at,
            }
        )
    return {"items": out}


@router.post("/v1/admin/users")
def create_user_route(
    payload: AdminUserCreatePayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        u = create_user(
            db,
            username=payload.username,
            password=payload.password,
            email=payload.email,
            role=payload.role,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    eff = attach_effective_role(db, u)
    return {
        "id": u.id,
        "username": u.username,
        "email": getattr(u, "email", None),
        "role": u.role,
        "effective_role": eff,
        "is_active": u.is_active,
    }


@router.patch("/v1/admin/users/{user_id}")
def update_user_route(
    user_id: int,
    payload: AdminUserUpdatePayload,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter(User.id == user_id).one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    previous_effective_role = attach_effective_role(db, u)

    new_role = u.role
    if payload.role is not None:
        nr = normalize_role(payload.role)
        if nr is None:
            raise HTTPException(status_code=400, detail="Invalid role")
        new_role = nr

    new_is_active = (
        u.is_active if payload.is_active is None else bool(payload.is_active)
    )

    # Safety: don't allow demoting or deactivating the last active admin, the
    # same guard the delete path applies.
    if (
        (u.role or "").lower() == "admin"
        and bool(u.is_active)
        and (new_role != "admin" or not new_is_active)
    ):
        active_admins = (
            db.query(User.id)
            .filter(User.role == "admin", User.is_active.is_(True))
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=409,
                detail="Cannot demote or deactivate the last active admin user",
            )

    if payload.role is not None:
        u.role = new_role
    if payload.is_active is not None:
        u.is_active = new_is_active

    if payload.email is not None:
        e = (payload.email or "").strip().lower() or None
        # allow clearing email by sending empty string
        if e:
            existing_user = (
                db.query(User).filter(User.email == e, User.id != u.id).one_or_none()
            )
            existing_email = (
                db.query(UserEmail)
                .filter(UserEmail.email_lower == e, UserEmail.user_id != u.id)
                .one_or_none()
            )
            if existing_user or existing_email:
                raise HTTPException(status_code=400, detail="Email already in use")
            row = db.query(UserEmail).filter(UserEmail.email_lower == e).one_or_none()
            if row:
                row.is_primary = True
                row.is_verified = True
                db.add(row)
            else:
                db.add(
                    UserEmail(
                        user_id=u.id,
                        email=e,
                        email_lower=e,
                        source="admin",
                        is_primary=True,
                        is_verified=True,
                    )
                )
            (
                db.query(UserEmail)
                .filter(UserEmail.user_id == u.id, UserEmail.email_lower != e)
                .update({"is_primary": False}, synchronize_session=False)
            )
        u.email = e

    db.add(u)
    db.commit()
    db.refresh(u)
    _notify_if_pending_user_approved(
        db, user=u, previous_effective_role=previous_effective_role
    )
    eff = attach_effective_role(db, u)
    return {
        "id": u.id,
        "username": u.username,
        "email": getattr(u, "email", None),
        "role": u.role,
        "effective_role": eff,
        "is_active": u.is_active,
    }


@router.delete("/v1/admin/users/{user_id}")
def delete_user_route(
    user_id: int,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Hard-delete a user.

    Notes:
      - Cascades will remove sessions, shortcuts, preferences, group links, etc.
      - Projects/frameworks use SET NULL for created_by_user_id.
    """
    if int(user_id) == int(me.id):
        raise HTTPException(status_code=400, detail="You cannot delete your own user")

    u = db.query(User).filter(User.id == user_id).one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    # Safety: don't allow deleting the last active admin.
    if (u.role or "").lower() == "admin" and bool(u.is_active):
        active_admins = (
            db.query(User.id)
            .filter(User.role == "admin", User.is_active.is_(True))
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=409, detail="Cannot delete the last active admin user"
            )

    db.delete(u)
    db.commit()
    return {"status": "ok", "deleted_user_id": user_id}


@router.get("/v1/admin/users/{user_id}/access")
def get_user_access(
    user_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter(User.id == user_id).one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    group_ids = [
        gid
        for (gid,) in db.query(UserGroup.group_id)
        .filter(UserGroup.user_id == user_id)
        .all()
    ]
    permission_ids = [
        pid
        for (pid,) in db.query(UserPermission.permission_id)
        .filter(UserPermission.user_id == user_id)
        .all()
    ]

    groups = db.query(Group).order_by(Group.name.asc()).all()
    perms = db.query(Permission).order_by(Permission.code.asc()).all()

    return {
        "user_id": user_id,
        "group_ids": group_ids,
        "permission_ids": permission_ids,
        "available_groups": [_group_to_dict(g) for g in groups],
        "available_permissions": [_permission_to_dict(p) for p in perms],
    }


@router.put("/v1/admin/users/{user_id}/access")
def set_user_access(
    user_id: int,
    body: dict,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter(User.id == user_id).one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    previous_effective_role = attach_effective_role(db, u)

    raw_group_ids = body.get("group_ids") or []
    raw_permission_ids = body.get("permission_ids") or []

    try:
        group_ids = sorted({int(x) for x in raw_group_ids})[:500]
        permission_ids = sorted({int(x) for x in raw_permission_ids})[:500]
    except Exception as e:
        raise HTTPException(
            status_code=400, detail="group_ids and permission_ids must be integer lists"
        ) from e

    # Safety: stripping the last active admin's own access would lock the
    # installation out; refuse the change and ask for another admin.
    if (
        (u.role or "").lower() == "admin"
        and bool(u.is_active)
        and not permission_ids
        and not group_ids
    ):
        active_admins = (
            db.query(User.id)
            .filter(User.role == "admin", User.is_active.is_(True))
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=409,
                detail="Cannot strip access from the last active admin user",
            )

    if group_ids:
        existing_groups = db.query(Group.id).filter(Group.id.in_(group_ids)).count()
        if existing_groups != len(group_ids):
            raise HTTPException(
                status_code=400, detail="one or more group_ids are invalid"
            )

    if permission_ids:
        existing_perms = (
            db.query(Permission.id).filter(Permission.id.in_(permission_ids)).count()
        )
        if existing_perms != len(permission_ids):
            raise HTTPException(
                status_code=400, detail="one or more permission_ids are invalid"
            )

    db.query(UserGroup).filter(UserGroup.user_id == user_id).delete()
    db.query(UserPermission).filter(UserPermission.user_id == user_id).delete()

    for gid in group_ids:
        db.add(UserGroup(user_id=user_id, group_id=gid))
    for pid in permission_ids:
        db.add(UserPermission(user_id=user_id, permission_id=pid))

    db.commit()
    db.refresh(u)
    _notify_if_pending_user_approved(
        db, user=u, previous_effective_role=previous_effective_role
    )

    return {
        "status": "ok",
        "user_id": user_id,
        "group_ids": group_ids,
        "permission_ids": permission_ids,
    }


@router.get("/v1/admin/groups")
def list_groups(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    items = db.query(Group).order_by(Group.name.asc()).all()

    out = []
    for g in items:
        # Count rows rather than a specific column to avoid schema drift issues
        # (e.g. older databases where the join table may not have a populated id).
        members = db.query(UserGroup).filter(UserGroup.group_id == g.id).count()
        perms = (
            db.query(GroupPermission.id)
            .filter(GroupPermission.group_id == g.id)
            .count()
        )
        out.append(
            {
                **_group_to_dict(g),
                "member_count": members,
                "permission_count": perms,
            }
        )

    return {"items": out}


@router.post("/v1/admin/groups")
def create_group(
    body: dict,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")

    role = normalize_role(body.get("role")) if body.get("role") is not None else None
    if body.get("role") is not None and role is None:
        raise HTTPException(status_code=400, detail="invalid role")

    existing = db.query(Group).filter(Group.name == name).one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="group exists")

    g = Group(
        name=name,
        description=(body.get("description") or "").strip() or None,
        role=role,
    )
    db.add(g)
    db.commit()
    db.refresh(g)

    return _group_to_dict(g)


@router.patch("/v1/admin/groups/{group_id}")
def update_group(
    group_id: int,
    body: dict,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    g = db.query(Group).filter(Group.id == group_id).one_or_none()
    if not g:
        raise HTTPException(status_code=404, detail="group not found")

    pending_members_before = []
    if "role" in body:
        members = (
            db.query(User)
            .join(UserGroup, UserGroup.user_id == User.id)
            .filter(UserGroup.group_id == group_id)
            .all()
        )
        pending_members_before = [
            (member, attach_effective_role(db, member)) for member in members
        ]

    if "name" in body:
        name = (body.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="name cannot be empty")
        existing = (
            db.query(Group)
            .filter(Group.name == name, Group.id != group_id)
            .one_or_none()
        )
        if existing:
            raise HTTPException(status_code=409, detail="group name already exists")
        g.name = name

    if "description" in body:
        g.description = (body.get("description") or "").strip() or None

    if "role" in body:
        raw_role = body.get("role")
        if raw_role is None or str(raw_role).strip() == "":
            g.role = None
        else:
            nr = normalize_role(str(raw_role))
            if nr is None:
                raise HTTPException(status_code=400, detail="invalid role")
            g.role = nr

    db.add(g)
    db.commit()
    db.refresh(g)

    for member, previous_effective_role in pending_members_before:
        db.refresh(member)
        _notify_if_pending_user_approved(
            db, user=member, previous_effective_role=previous_effective_role
        )

    return _group_to_dict(g)


@router.delete("/v1/admin/groups/{group_id}")
def delete_group(
    group_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Hard-delete a group.

    Cascades will remove membership links, group permissions, and project ownership links.
    """
    g = db.query(Group).filter(Group.id == group_id).one_or_none()
    if not g:
        raise HTTPException(status_code=404, detail="group not found")

    db.delete(g)
    db.commit()
    return {"status": "ok", "deleted_group_id": group_id}


@router.get("/v1/admin/groups/{group_id}/permissions")
def get_group_permissions(
    group_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    g = db.query(Group).filter(Group.id == group_id).one_or_none()
    if not g:
        raise HTTPException(status_code=404, detail="group not found")

    permission_ids = [
        pid
        for (pid,) in db.query(GroupPermission.permission_id)
        .filter(GroupPermission.group_id == group_id)
        .all()
    ]
    perms = db.query(Permission).order_by(Permission.code.asc()).all()

    return {
        "group_id": group_id,
        "permission_ids": permission_ids,
        "available_permissions": [_permission_to_dict(p) for p in perms],
    }


@router.put("/v1/admin/groups/{group_id}/permissions")
def set_group_permissions(
    group_id: int,
    body: dict,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    g = db.query(Group).filter(Group.id == group_id).one_or_none()
    if not g:
        raise HTTPException(status_code=404, detail="group not found")

    raw_permission_ids = body.get("permission_ids") or []
    try:
        permission_ids = sorted({int(x) for x in raw_permission_ids})
    except Exception as e:
        raise HTTPException(
            status_code=400, detail="permission_ids must be integer list"
        ) from e

    if permission_ids:
        existing_perms = (
            db.query(Permission.id).filter(Permission.id.in_(permission_ids)).count()
        )
        if existing_perms != len(permission_ids):
            raise HTTPException(
                status_code=400, detail="one or more permission_ids are invalid"
            )

    db.query(GroupPermission).filter(GroupPermission.group_id == group_id).delete()
    for pid in permission_ids:
        db.add(GroupPermission(group_id=group_id, permission_id=pid))
    db.commit()

    return {"status": "ok", "group_id": group_id, "permission_ids": permission_ids}


@router.get("/v1/admin/permissions")
def list_permissions(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    items = db.query(Permission).order_by(Permission.code.asc()).all()
    return {"items": [_permission_to_dict(p) for p in items]}


@router.post("/v1/admin/users/{user_id}/permissions/{permission_id}")
def add_user_permission(
    user_id: int,
    permission_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter(User.id == user_id).one_or_none()
    p = db.query(Permission).filter(Permission.id == permission_id).one_or_none()
    if not u or not p:
        raise HTTPException(status_code=404, detail="user or permission not found")

    existing = (
        db.query(UserPermission)
        .filter(
            UserPermission.user_id == user_id,
            UserPermission.permission_id == permission_id,
        )
        .one_or_none()
    )
    if existing:
        return {"status": "ok", "already_linked": True}

    db.add(UserPermission(user_id=user_id, permission_id=permission_id))
    db.commit()
    return {"status": "ok"}


@router.patch("/v1/admin/projects/{project_id}/ownership")
def update_project_ownership(
    request: Request,
    project_id: int,
    payload: AdminProjectOwnershipPayload,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    project = db.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    before = project_changelog_state(db, project)

    if payload.owner_user_id is not None:
        owner = db.query(User).filter(User.id == payload.owner_user_id).one_or_none()
        if not owner:
            raise HTTPException(status_code=400, detail="owner_user_id does not exist")
        project.created_by_user_id = owner.id
        db.add(project)

    if payload.owner_group_ids is not None:
        ids = [int(x) for x in payload.owner_group_ids]
        existing = (
            {gid for (gid,) in db.query(Group.id).filter(Group.id.in_(ids)).all()}
            if ids
            else set()
        )
        missing = sorted(set(ids) - existing)
        if missing:
            raise HTTPException(status_code=400, detail=f"Unknown group ids: {missing}")

        # Replace links
        db.query(ProjectOwnerGroup).filter(
            ProjectOwnerGroup.project_id == project_id
        ).delete()
        for gid in ids:
            db.add(ProjectOwnerGroup(project_id=project_id, group_id=gid))

    db.flush()
    record_entity_changelog(
        db,
        entity_type="project",
        entity_id=project.id,
        action="updated",
        before=before,
        after=project_changelog_state(db, project),
        user=user,
        request_method=request.method,
        request_path=request.url.path,
    )
    db.commit()
    db.refresh(project)

    return {"ok": True}


@router.get("/v1/admin/audit")
def admin_audit_trail(
    limit: int = 50,
    offset: int = 0,
    username: str | None = None,
    path: str | None = None,
    method: str | None = None,
    status_min: int | None = None,
    status_max: int | None = None,
    _: User = Depends(require_audit_access),
    db: Session = Depends(get_db),
):
    """List KEEN-style internal UI/API request audit trail entries."""

    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))

    qry = db.query(AuditLog)
    qry = qry.filter(
        ~(AuditLog.path.ilike("%/v1/auth%") & AuditLog.path.ilike("%callback%"))
    )
    if username:
        qry = qry.filter(AuditLog.username.ilike(f"%{username.strip()}%"))
    if path:
        qry = qry.filter(AuditLog.path.ilike(f"%{path.strip()}%"))
    if method:
        m = method.strip().upper()
        if m:
            qry = qry.filter(AuditLog.method == m)
    if status_min is not None:
        try:
            qry = qry.filter(AuditLog.status_code >= int(status_min))
        except Exception:
            pass
    if status_max is not None:
        try:
            qry = qry.filter(AuditLog.status_code <= int(status_max))
        except Exception:
            pass

    total = qry.order_by(None).count()
    rows = qry.order_by(desc(AuditLog.ts)).limit(limit).offset(offset).all()
    items = [
        {
            "id": str(row.id),
            "ts": row.ts.isoformat() if row.ts else None,
            "username": row.username,
            "method": row.method,
            "path": row.path,
            "query_string": row.query_string,
            "status_code": row.status_code,
            "duration_ms": row.duration_ms,
            "client_ip": row.client_ip,
            "user_agent": row.user_agent,
            "referer": row.referer,
        }
        for row in rows
    ]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.get("/v1/admin/entity-changelog")
def admin_entity_changelog(
    limit: int = 50,
    offset: int = 0,
    entity_type: str | None = None,
    entity_id: int | None = None,
    username: str | None = None,
    q: str | None = None,
    _: User = Depends(require_audit_access),
    db: Session = Depends(get_db),
):
    """List semantic before/after changelogs for project catalog entities."""

    if entity_type:
        entity_type = entity_type.strip().lower()
        if entity_type not in {"project", "project_version"}:
            raise HTTPException(status_code=400, detail="Invalid entity_type")
    return list_entity_changelogs(
        db,
        entity_type=entity_type,
        entity_id=entity_id,
        username=username,
        q=q,
        limit=limit,
        offset=offset,
    )


def _pending_notification_count(db: Session) -> int:
    from app.db.models import Notification

    return db.query(Notification).filter(Notification.status == "pending").count()


@router.post("/v1/admin/release-feeds/discover-all", status_code=202)
def admin_discover_all_release_feeds(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Fan out initial/steady discovery for every configured release feed.

    Each feed import runs as its own task, so one noisy feed cannot slow the
    rest; discovery marks the newest entry `is_latest` and enqueues a
    dependency scan for it when the scans feature is on.
    """
    from app.core.features import is_enabled
    from app.db.models import Project

    if not is_enabled("release_feed"):
        raise HTTPException(status_code=404, detail="Feature not available")

    projects = (
        db.query(Project)
        .filter(Project.release_rss_feed_url.isnot(None))
        .filter(Project.release_rss_feed_url != "")
        .order_by(Project.id)
        .all()
    )
    enqueued = 0
    if projects:
        from app.tasks.release_feed import discover_project_release_feed

        for project in projects:
            try:
                discover_project_release_feed.delay(project.id)
                enqueued += 1
            except Exception:
                logger.exception(
                    "Failed to enqueue discovery for project_id=%s", project.id
                )
    return {
        "enqueued": enqueued,
        "pending_notifications": _pending_notification_count(db),
    }


@router.get("/v1/admin/notifications")
def admin_notifications(
    limit: int = 50,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """The e-mail outbox: every queued mail's delivery state and failure."""
    from app.db.models import Notification

    limit = max(1, min(int(limit or 50), 200))
    rows = (
        db.query(Notification)
        .order_by(Notification.created_at.desc())
        .limit(limit)
        .all()
    )
    pending = db.query(Notification).filter(Notification.status == "pending").count()
    failed = db.query(Notification).filter(Notification.status == "failed").count()
    return {
        "pending": pending,
        "failed": failed,
        "notifications": [
            {
                "id": str(row.id),
                "user_id": row.user_id,
                "recipient": row.recipient,
                "subject": row.subject,
                "status": row.status,
                "attempts": row.attempts,
                "last_error": row.last_error,
                "created_at": row.created_at,
                "sent_at": row.sent_at,
            }
            for row in rows
        ],
    }


@router.get("/v1/organisations")
def list_organisations(
    _: User = Depends(get_request_user),
    db: Session = Depends(get_db),
):
    """The organisation list the project form and filters offer."""
    from app.db.models import Project

    rows = db.query(Organisation).order_by(Organisation.name).all()
    counts = {
        int(organisation_id): int(total)
        for organisation_id, total in db.query(
            Project.organisation_id, func.count(Project.id)
        )
        .filter(Project.organisation_id.isnot(None))
        .group_by(Project.organisation_id)
        .all()
    }
    return [
        {
            "id": int(row.id),
            "name": row.name,
            "description": row.description,
            "website": row.website,
            "project_count": int(counts.get(row.id, 0)),
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.post("/v1/admin/organisations")
def create_organisation(
    payload: OrganisationPayload,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from app.services.entity_changelog import record_entity_changelog

    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if db.query(Organisation).filter(Organisation.name == name).one_or_none():
        raise HTTPException(status_code=409, detail="Organisation already exists")
    row = Organisation(
        name=name,
        description=payload.description,
        website=payload.website,
        created_by_user_id=me.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    record_entity_changelog(
        db,
        entity_type="organisation",
        entity_id=row.id,
        action="created",
        before=None,
        after={"id": row.id, "name": row.name},
        user=me,
        request_method="POST",
        request_path="/v1/admin/organisations",
    )
    db.commit()
    return {"id": row.id, "name": row.name}


@router.patch("/v1/admin/organisations/{organisation_id}")
def update_organisation(
    organisation_id: int,
    payload: OrganisationPayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = (
        db.query(Organisation).filter(Organisation.id == organisation_id).one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    if payload.name is not None:
        name = payload.name.strip()
        if name and name != row.name:
            clash = (
                db.query(Organisation).filter(Organisation.name == name).one_or_none()
            )
            if clash:
                raise HTTPException(
                    status_code=409, detail="Organisation already exists"
                )
    if payload.name is not None and (payload.name or "").strip():
        row.name = payload.name.strip()
    if payload.description is not None:
        row.description = payload.description or None
    if payload.website is not None:
        row.website = payload.website or None
    db.add(row)
    db.commit()
    return {"id": row.id, "name": row.name}


@router.post("/v1/admin/organisations/{organisation_id}/members")
def add_organisation_member(
    organisation_id: int,
    payload: OrganisationMemberPayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Put a user or group on an organisation's view; exactly one of the two."""
    from app.db.models import Group

    row = (
        db.query(Organisation).filter(Organisation.id == organisation_id).one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    if bool(payload.user_id) == bool(payload.group_id):
        raise HTTPException(
            status_code=400, detail="Provide exactly one of user_id or group_id"
        )
    if (
        payload.user_id
        and not db.query(User).filter(User.id == payload.user_id).one_or_none()
    ):
        raise HTTPException(status_code=404, detail="User not found")
    if (
        payload.group_id
        and not db.query(Group).filter(Group.id == payload.group_id).one_or_none()
    ):
        raise HTTPException(status_code=404, detail="Group not found")
    member = OrganisationMember(
        organisation_id=row.id,
        user_id=payload.user_id,
        group_id=payload.group_id,
        role=payload.role,
    )
    exists = (
        db.query(OrganisationMember)
        .filter(
            OrganisationMember.organisation_id == row.id,
            OrganisationMember.user_id == payload.user_id,
            OrganisationMember.group_id == payload.group_id,
        )
        .one_or_none()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Member already present")
    db.add(member)
    db.commit()
    return {"id": member.id}


@router.delete("/v1/admin/organisations/{organisation_id}/members/{member_id}")
def remove_organisation_member(
    organisation_id: int,
    member_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    member = (
        db.query(OrganisationMember)
        .filter(
            OrganisationMember.id == member_id,
            OrganisationMember.organisation_id == organisation_id,
        )
        .one_or_none()
    )
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    db.delete(member)
    db.commit()
    return {"deleted": True}


@router.get("/v1/admin/organisations/{organisation_id}")
def organisation_detail(
    organisation_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from app.db.models import Group, User

    row = (
        db.query(Organisation).filter(Organisation.id == organisation_id).one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    def _subject(member: OrganisationMember):
        if member.user_id:
            name = (
                db.query(User.username).filter(User.id == member.user_id).scalar()
                or f"user-{member.user_id}"
            )
            kind = "user"
        else:
            name = (
                db.query(Group.name).filter(Group.id == member.group_id).scalar()
                or f"group-{member.group_id}"
            )
            kind = "group"
        return kind, name

    members = []
    for member in (
        db.query(OrganisationMember)
        .filter(OrganisationMember.organisation_id == row.id)
        .order_by(OrganisationMember.created_at.desc())
        .all()
    ):
        kind, name = _subject(member)
        members.append(
            {
                "id": member.id,
                "kind": kind,
                "name": name,
                "user_id": member.user_id,
                "group_id": member.group_id,
                "role": member.role,
            }
        )
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "website": row.website,
        "members": members,
    }
