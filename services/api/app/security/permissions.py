from __future__ import annotations

from sqlalchemy import and_, exists
from sqlalchemy.orm import Session

from app.db.models import GroupPermission, Permission, User, UserGroup, UserPermission
from app.security.roles import (
    ROLE_ADMIN,
    ROLE_ARCHITECT,
    ROLE_CONTRIBUTOR,
    ROLE_ENGINEER,
    ROLE_FRAMEWORK_ADMIN,
    ROLE_MAINTAINER,
    ROLE_PENDING,
    ROLE_PRODUCT_OWNER,
    attach_effective_role,
)

# Permission codes used by the API
PERM_PROJECT_WRITE = "project.write"
PERM_FRAMEWORK_WRITE = "framework.write"
PERM_MANIFEST_EXPORT = "manifest.export"
PERM_PROJECT_QUESTION = "project.question"
PERM_PROJECT_ANSWER = "project.answer"
PERM_PROJECT_DIFF = "project.diff"
PERM_AUDITTRAIL_READ = "audittrail.read"

ROLE_DEFAULT_PERMISSIONS = {
    ROLE_ADMIN: {"*"},
    # Framework admins can create/edit frameworks and framework nodes.
    ROLE_FRAMEWORK_ADMIN: {PERM_FRAMEWORK_WRITE},
    # Maintainers can create/edit projects and answer questions for projects they own/share by group.
    ROLE_MAINTAINER: {PERM_PROJECT_WRITE, PERM_PROJECT_ANSWER},
    # Contributors can compare projects and answer questions for projects owned by their group.
    ROLE_CONTRIBUTOR: {PERM_PROJECT_DIFF, PERM_PROJECT_ANSWER},
    # Engineers can compare projects and ask questions.
    ROLE_ENGINEER: {PERM_PROJECT_DIFF, PERM_PROJECT_QUESTION},
    # Product owners can save/export manifests and ask questions.
    ROLE_PRODUCT_OWNER: {PERM_MANIFEST_EXPORT, PERM_PROJECT_QUESTION},
    # Architects can save/export manifests and ask questions.
    ROLE_ARCHITECT: {PERM_MANIFEST_EXPORT, PERM_PROJECT_QUESTION},
}


DEFAULT_PERMISSION_SEED = [
    {
        "code": PERM_PROJECT_WRITE,
        "description": "Create and edit projects, versions, and framework mappings",
    },
    {
        "code": PERM_FRAMEWORK_WRITE,
        "description": "Create and edit frameworks and framework node taxonomies",
    },
    {
        "code": PERM_MANIFEST_EXPORT,
        "description": "Export and save project manifests (JSON/XLSX/Markdown)",
    },
    {
        "code": PERM_PROJECT_QUESTION,
        "description": "Ask questions against a project",
    },
    {
        "code": PERM_PROJECT_ANSWER,
        "description": "Answer questions against a project (subject to project ownership/group checks)",
    },
    {
        "code": PERM_PROJECT_DIFF,
        "description": "Generate comparison diffs between projects",
    },
    {
        "code": PERM_AUDITTRAIL_READ,
        "description": "View request audit logs and semantic entity changelogs",
    },
]


def seed_default_permissions(db: Session) -> None:
    """Idempotently seed baseline permission rows used by this application."""
    existing_codes = {
        code
        for (code,) in db.query(Permission.code)
        .filter(Permission.code.in_([p["code"] for p in DEFAULT_PERMISSION_SEED]))
        .all()
    }
    changed = False
    for item in DEFAULT_PERMISSION_SEED:
        if item["code"] in existing_codes:
            continue
        db.add(Permission(code=item["code"], description=item.get("description")))
        changed = True
    if changed:
        db.commit()


def _has_direct_permission(db: Session, user_id: int, code: str) -> bool:
    return (
        db.query(
            exists().where(
                and_(
                    UserPermission.user_id == user_id,
                    UserPermission.permission_id == Permission.id,
                    Permission.code == code,
                )
            )
        ).scalar()
        is True
    )


def _has_group_permission(db: Session, user_id: int, code: str) -> bool:
    return (
        db.query(
            exists().where(
                and_(
                    UserGroup.user_id == user_id,
                    UserGroup.group_id == GroupPermission.group_id,
                    GroupPermission.permission_id == Permission.id,
                    Permission.code == code,
                )
            )
        ).scalar()
        is True
    )


def has_permission(db: Session, user: User, code: str) -> bool:
    """Return True if the user has the given permission code."""

    effective_role = attach_effective_role(db, user)
    if effective_role == ROLE_PENDING:
        return False
    if effective_role == ROLE_ADMIN:
        return True

    role_codes = ROLE_DEFAULT_PERMISSIONS.get(effective_role, set())
    if "*" in role_codes or code in role_codes:
        return True

    if _has_direct_permission(db, user.id, code):
        return True

    if _has_group_permission(db, user.id, code):
        return True

    return False
