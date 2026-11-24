from __future__ import annotations

import logging
import uuid
from typing import Annotated, Any

from fastapi import Body, Depends, HTTPException, Query, Request
from mosp.api.routing import Router
from mosp.core.datetime_utils import iso_or_none
from mosp.core.email_address import single_mailbox
from mosp.security.auth import create_user, require_admin, require_authenticated
from mosp.security.client_ip import request_ip
from mosp.security.passwords import hash_password
from mosp.security.permissions import (
    bump_authz_versions,
    group_member_ids,
    has_permission,
    normalize_group_description,
    normalize_group_name,
)
from mosp.security.roles import (
    attach_effective_role,
    count_effective_admins,
    lock_admin_changes,
    normalize_role,
)
from mosp.services import security_notifications
from mosp.services.account import end_password_recognition
from mosp.services.login import sign_in_key
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.api.deps import DbId, OptionalDbId, PageLimit, PageOffset, SearchText
from app.api.payloads import (
    AdminGroupCreatePayload,
    AdminGroupPermissionsUpdatePayload,
    AdminGroupUpdatePayload,
    AdminProjectOwnershipPayload,
    AdminSetPasswordPayload,
    AdminUserAccessUpdatePayload,
    AdminUserCreatePayload,
    AdminUserUpdatePayload,
    OrganisationMemberPayload,
    OrganisationPayload,
)
from app.db.models import (
    AuditLog,
    Group,
    Organisation,
    OrganisationMember,
    Permission,
    Project,
    ProjectOwnerGroup,
    User,
    group_permissions,
    user_groups,
)
from app.db.session import get_db
from app.security.permissions import PERM_AUDITTRAIL_READ
from app.services.entity_changelog import (
    CHANGELOG_ENTITY_TYPES,
    list_entity_changelogs,
    project_changelog_state,
    record_entity_changelog,
)
from app.tasks.notifications import kick_delivery

logger = logging.getLogger(__name__)

router = Router()


def _ensure_an_admin_remains(db: Session, detail: str) -> None:
    """Refuse a pending change that leaves no active administrator, counting
    accounts that hold the role through a group as well as directly."""
    db.flush()
    if count_effective_admins(db) == 0:
        db.rollback()
        raise HTTPException(status_code=409, detail=detail)


def require_audit_access(
    user: User = Depends(require_authenticated), db: Session = Depends(get_db)
) -> User:
    eff = attach_effective_role(db, user)
    if eff != "admin" and not has_permission(db, user, PERM_AUDITTRAIL_READ):
        raise HTTPException(status_code=403, detail="Audit access required")
    return user


def _group_to_dict(g: Group) -> dict:
    return {
        "id": str(g.id),
        "name": g.name,
        "description": g.description,
        "role": g.role,
    }


def _permission_to_dict(p: Permission) -> dict:
    return {
        "id": str(p.id),
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
                "id": str(u.id),
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


def _user_to_dict(db: Session, u: User) -> dict:
    return {
        "id": str(u.id),
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "effective_role": attach_effective_role(db, u),
        "is_active": u.is_active,
    }


def _find(db: Session, model, row_id: uuid.UUID, detail: str):
    row = db.get(model, row_id)
    if row is None:
        raise HTTPException(status_code=404, detail=detail)
    return row


def _end_sessions(user: User) -> None:
    """End every session of the account: the enrolment version moves on, so
    its sessions, pending ceremonies and address proofs end for good."""
    user.mfa_version += 1


@router.post("/v1/admin/users")
def create_user_route(
    payload: AdminUserCreatePayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    email = None
    if payload.email and payload.email.strip():
        email = single_mailbox(payload.email)
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid email address")
    try:
        u = create_user(
            db,
            username=payload.username,
            password=payload.password,
            email=email,
            role=payload.role,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return _user_to_dict(db, u)


@router.patch("/v1/admin/users/{user_id}")
def update_user_route(
    user_id: uuid.UUID,
    payload: AdminUserUpdatePayload,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = _find(db, User, user_id, "User not found")
    if u.id == me.id and payload.is_active is False:
        raise HTTPException(
            status_code=400, detail="You cannot deactivate your own account"
        )

    # Safety: don't allow demoting or deactivating the last active admin, the
    # same guard every path that can remove an administrator applies.
    lock_admin_changes(db)

    if payload.email is not None:
        email = None
        if payload.email.strip():
            email = single_mailbox(payload.email)
            if email is None:
                raise HTTPException(status_code=400, detail="Invalid email address")
        u.email = email

    if payload.role is not None and payload.role != u.role:
        u.role = payload.role
        bump_authz_versions(db, [u.id])
    if payload.is_active is False and u.is_active:
        # As in KEEN, deactivation ends the account's sessions for good: they
        # do not return if the account is activated again.
        _end_sessions(u)
    if payload.is_active is not None:
        u.is_active = bool(payload.is_active)

    _ensure_an_admin_remains(
        db, "Cannot demote or deactivate the last active admin user"
    )
    db.commit()
    db.refresh(u)
    return _user_to_dict(db, u)


@router.post("/v1/admin/users/{user_id}/password")
def set_user_password_route(
    user_id: uuid.UUID,
    payload: AdminSetPasswordPayload,
    request: Request,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """An administrator's password reset, as KEEN's.

    The account's sessions and every browser's recognition end, its
    sign-in throttle starts afresh, and its owner is mailed a notice.
    """
    target = (
        db.query(User)
        .filter(User.id == user_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        target.password_hash = hash_password(
            payload.new_password, username=target.username
        )
    except ValueError as problem:
        raise HTTPException(status_code=400, detail=str(problem)) from problem
    # Every session ends, whichever way it was signed in: a reset answers a
    # suspected takeover, and a session opened through a provider is as much
    # part of one as a password session.
    _end_sessions(target)
    key = sign_in_key(db, target.username)
    security_notifications.enqueue(db, target, "password-reset", ip=request_ip(request))
    db.commit()
    end_password_recognition(str(target.id), key=key)
    # Sends the notice now when mail is configured; the beat schedule
    # delivers it otherwise.
    kick_delivery()
    return {"ok": True}


@router.delete("/v1/admin/users/{user_id}")
def delete_user_route(
    user_id: uuid.UUID,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Hard-delete a user.

    Cascades remove shortcuts, preferences, group links, subscriptions and
    the account's question threads; projects, frameworks, organisations and
    manifests keep their rows with their author columns set to NULL.
    """
    if user_id == me.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own user")
    u = _find(db, User, user_id, "User not found")

    # Safety: don't allow deleting the last active admin.
    lock_admin_changes(db)
    db.delete(u)
    _ensure_an_admin_remains(db, "Cannot delete the last active admin user")
    db.commit()
    return {"status": "ok", "deleted_user_id": str(user_id)}


@router.get("/v1/admin/users/{user_id}/access")
def get_user_access(
    user_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = _find(db, User, user_id, "User not found")
    groups = db.query(Group).order_by(Group.name.asc()).all()
    perms = db.query(Permission).order_by(Permission.code.asc()).all()
    return {
        "user_id": str(u.id),
        "group_ids": sorted(str(g.id) for g in u.groups),
        "permission_ids": sorted(str(p.id) for p in u.permissions),
        "available_groups": [_group_to_dict(g) for g in groups],
        "available_permissions": [_permission_to_dict(p) for p in perms],
    }


def _rows(db: Session, model, ids: list[uuid.UUID], detail: str) -> list:
    rows = db.query(model).filter(model.id.in_(ids)).all() if ids else []
    if len(rows) != len(ids):
        raise HTTPException(status_code=400, detail=detail)
    return rows


@router.put("/v1/admin/users/{user_id}/access")
def set_user_access(
    user_id: uuid.UUID,
    body: AdminUserAccessUpdatePayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = _find(db, User, user_id, "User not found")
    group_ids = sorted(set(body.group_ids))
    permission_ids = sorted(set(body.permission_ids))

    # Safety: stripping the last active admin's own access would lock the
    # installation out; refuse the change and ask for another admin.
    lock_admin_changes(db)
    u.groups = _rows(db, Group, group_ids, "one or more group_ids are invalid")
    u.permissions = _rows(
        db, Permission, permission_ids, "one or more permission_ids are invalid"
    )
    bump_authz_versions(db, [u.id])

    # An account that is an administrator through a group stays one, or
    # another administrator exists.
    _ensure_an_admin_remains(db, "Cannot strip access from the last active admin user")
    db.commit()
    return {
        "status": "ok",
        "user_id": str(u.id),
        "group_ids": [str(g) for g in group_ids],
        "permission_ids": [str(p) for p in permission_ids],
    }


@router.get("/v1/admin/groups")
def list_groups(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    out = []
    for g in db.query(Group).order_by(Group.name.asc()).all():
        members = db.query(user_groups).filter(user_groups.c.group_id == g.id).count()
        perms = (
            db.query(group_permissions)
            .filter(group_permissions.c.group_id == g.id)
            .count()
        )
        out.append(
            {**_group_to_dict(g), "member_count": members, "permission_count": perms}
        )
    return {"items": out}


def _group_role(raw) -> str | None:
    """A group's role: admin or normal, or none."""
    if raw is None or str(raw).strip() == "":
        return None
    role = normalize_role(str(raw))
    if role not in ("admin", "normal"):
        raise HTTPException(status_code=400, detail="invalid role")
    return role


@router.post("/v1/admin/groups")
def create_group(
    body: AdminGroupCreatePayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    name = normalize_group_name(body.name)
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    role = _group_role(body.role)
    if db.query(Group).filter(Group.name == name).one_or_none():
        raise HTTPException(status_code=409, detail="group exists")
    g = Group(
        name=name,
        description=normalize_group_description(body.description),
        role=role,
    )
    db.add(g)
    db.commit()
    db.refresh(g)
    return _group_to_dict(g)


@router.patch("/v1/admin/groups/{group_id}")
def update_group(
    group_id: uuid.UUID,
    payload: AdminGroupUpdatePayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    g = _find(db, Group, group_id, "group not found")
    body = payload.model_dump(exclude_unset=True)

    if "name" in body:
        name = normalize_group_name(payload.name or "")
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
        g.description = normalize_group_description(body.get("description"))

    if "role" in body:
        lock_admin_changes(db)
        g.role = _group_role(body.get("role"))
        bump_authz_versions(db, group_member_ids(db, g.id))
        _ensure_an_admin_remains(db, "This group gives the last active admin its role")
    db.commit()
    db.refresh(g)
    return _group_to_dict(g)


@router.delete("/v1/admin/groups/{group_id}")
def delete_group(
    group_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Hard-delete a group. Cascades remove membership links and group
    permissions."""
    g = _find(db, Group, group_id, "group not found")
    lock_admin_changes(db)
    bump_authz_versions(db, group_member_ids(db, g.id))
    db.delete(g)
    _ensure_an_admin_remains(db, "This group gives the last active admin its role")
    db.commit()
    return {"status": "ok", "deleted_group_id": str(group_id)}


@router.get("/v1/admin/groups/{group_id}/permissions")
def get_group_permissions(
    group_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    g = _find(db, Group, group_id, "group not found")
    perms = db.query(Permission).order_by(Permission.code.asc()).all()
    return {
        "group_id": str(g.id),
        "permission_ids": sorted(str(p.id) for p in g.permissions),
        "available_permissions": [_permission_to_dict(p) for p in perms],
    }


@router.put("/v1/admin/groups/{group_id}/permissions")
def set_group_permissions(
    group_id: uuid.UUID,
    body: AdminGroupPermissionsUpdatePayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    g = _find(db, Group, group_id, "group not found")
    permission_ids = sorted(set(body.permission_ids))
    g.permissions = _rows(
        db, Permission, permission_ids, "one or more permission_ids are invalid"
    )
    bump_authz_versions(db, group_member_ids(db, g.id))
    db.commit()
    return {
        "status": "ok",
        "group_id": str(g.id),
        "permission_ids": [str(p) for p in permission_ids],
    }


@router.get("/v1/admin/permissions")
def list_permissions(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    items = db.query(Permission).order_by(Permission.code.asc()).all()
    return {"items": [_permission_to_dict(p) for p in items]}


@router.post("/v1/admin/users/{user_id}/permissions/{permission_id}")
def add_user_permission(
    user_id: uuid.UUID,
    permission_id: uuid.UUID,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.get(User, user_id)
    p = db.get(Permission, permission_id)
    if not u or not p:
        raise HTTPException(status_code=404, detail="user or permission not found")
    if p in u.permissions:
        return {"status": "ok", "already_linked": True}
    u.permissions.append(p)
    bump_authz_versions(db, [u.id])
    db.commit()
    return {"status": "ok"}


@router.get("/v1/admin/audit")
def admin_audit_trail(
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    username: str | None = None,
    path: str | None = None,
    method: str | None = None,
    status_min: Annotated[int | None, Query(ge=100, le=599)] = None,
    status_max: Annotated[int | None, Query(ge=100, le=599)] = None,
    _: User = Depends(require_audit_access),
    db: Session = Depends(get_db),
):
    """List KEEN-style internal UI/API request audit trail entries."""

    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))

    # Sign-in callbacks are listed too: their query values are recorded as
    # REDACTED, so the row shows that a sign-in completed and nothing more.
    qry = db.query(AuditLog)
    if username:
        qry = qry.filter(AuditLog.username.icontains(username.strip(), autoescape=True))
    if path:
        qry = qry.filter(AuditLog.path.icontains(path.strip(), autoescape=True))
    if method:
        m = method.strip().upper()
        if m:
            qry = qry.filter(AuditLog.method == m)
    if status_min is not None:
        qry = qry.filter(AuditLog.status_code >= status_min)
    if status_max is not None:
        qry = qry.filter(AuditLog.status_code <= status_max)

    total = qry.order_by(None).count()
    rows = qry.order_by(desc(AuditLog.ts)).limit(limit).offset(offset).all()
    items = [
        {
            "id": str(row.id),
            "ts": iso_or_none(row.ts),
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
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    entity_type: str | None = None,
    entity_id: OptionalDbId = None,
    username: str | None = None,
    q: SearchText = None,
    _: User = Depends(require_audit_access),
    db: Session = Depends(get_db),
):
    """List semantic before/after changelogs for project catalogue entities."""

    if entity_type:
        entity_type = entity_type.strip().lower()
        if entity_type not in CHANGELOG_ENTITY_TYPES:
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


@router.get("/v1/admin/features")
def admin_features(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Installation feature switches with their stored and deployment settings."""
    from app.core import features

    return features.state(db).admin()


@router.put("/v1/admin/features")
def update_admin_features(
    payload: dict[str, Any] = Body(...),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Save feature switches against the configuration version they started from."""
    from app.core import features

    return features.update(db, user, payload.get("version"), payload.get("changes"))


@router.get("/v1/admin/notifications")
def admin_notifications(
    limit: PageLimit = 50,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Both mail outboxes, newest first: project notices (OSPMAE's) and account
    security notices (mosp's), with each message's delivery state and failure."""
    from app.db.models import Notification, SecurityNotification

    limit = max(1, min(int(limit or 50), 200))
    outboxes = (("project", Notification), ("security", SecurityNotification))
    rows = sorted(
        (
            (kind, row)
            for kind, model in outboxes
            for row in db.query(model)
            .order_by(model.created_at.desc())
            .limit(limit)
            .all()
        ),
        key=lambda item: item[1].created_at,
        reverse=True,
    )[:limit]

    def counted(status: str) -> int:
        return sum(
            db.query(model).filter(model.status == status).count()
            for _, model in outboxes
        )

    return {
        "pending": counted("pending"),
        "failed": counted("failed"),
        "notifications": [
            {
                "id": str(row.id),
                "kind": kind,
                "user_id": str(row.user_id) if row.user_id else None,
                "recipient": row.recipient,
                "subject": row.subject,
                "status": row.status,
                "attempts": row.attempts,
                "last_error": row.last_error,
                "created_at": row.created_at,
                "sent_at": row.sent_at,
            }
            for kind, row in rows
        ],
    }


@router.patch("/v1/admin/projects/{project_id}/ownership")
def update_project_ownership(
    request: Request,
    project_id: DbId,
    payload: AdminProjectOwnershipPayload,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    project = db.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    before = project_changelog_state(db, project)

    if payload.owner_user_id is not None:
        owner = db.get(User, payload.owner_user_id)
        if not owner:
            raise HTTPException(status_code=400, detail="owner_user_id does not exist")
        project.created_by_user_id = owner.id
        db.add(project)

    if payload.owner_group_ids is not None:
        ids = list(dict.fromkeys(payload.owner_group_ids))
        existing = (
            {gid for (gid,) in db.query(Group.id).filter(Group.id.in_(ids)).all()}
            if ids
            else set()
        )
        missing = sorted(str(gid) for gid in set(ids) - existing)
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
    from app.services.scan_queue import launch_release_discovery

    if not is_enabled("release_feed", db):
        raise HTTPException(status_code=404, detail="Feature not available")

    projects = (
        db.query(Project)
        .filter(Project.release_rss_feed_url.isnot(None))
        .filter(Project.release_rss_feed_url != "")
        .filter(Project.track_branch.is_(False))
        .order_by(Project.id)
        .all()
    )
    enqueued = sum(launch_release_discovery(project.id) for project in projects)
    return {
        "enqueued": enqueued,
        "pending_notifications": _pending_notification_count(db),
    }


@router.get("/v1/organisations")
def list_organisations(
    _: User = Depends(require_authenticated),
    db: Session = Depends(get_db),
):
    """The organisation list the project form and filters offer."""
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
    organisation_id: DbId,
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
    organisation_id: DbId,
    payload: OrganisationMemberPayload,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Put a user or group on an organisation's view; exactly one of the two."""
    row = (
        db.query(Organisation).filter(Organisation.id == organisation_id).one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    if bool(payload.user_id) == bool(payload.group_id):
        raise HTTPException(
            status_code=400, detail="Provide exactly one of user_id or group_id"
        )
    if payload.user_id and db.get(User, payload.user_id) is None:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.group_id and db.get(Group, payload.group_id) is None:
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
    organisation_id: DbId,
    member_id: DbId,
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
    organisation_id: DbId,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
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
                "user_id": str(member.user_id) if member.user_id else None,
                "group_id": str(member.group_id) if member.group_id else None,
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
