"""Who a project belongs to, and what follows from it.

A project is owned by the account that created it and by its owner groups;
an administrator stands in for either. Ownership decides who may read a
draft version, and (with the project.write permission) who may change the
project. Every route asks here, so the rule is written once.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException
from mosp.security.roles import ROLE_ADMIN, attach_effective_role
from sqlalchemy.orm import Session

from app.db.models import Project, ProjectOwnerGroup, ProjectVersion, User, user_groups

VERSION_NOT_FOUND = "Project version not found"


def user_group_ids(db: Session, user_id: uuid.UUID) -> set[uuid.UUID]:
    return {
        gid
        for (gid,) in db.query(user_groups.c.group_id)
        .filter(user_groups.c.user_id == user_id)
        .all()
        if gid is not None
    }


def project_owner_group_ids(db: Session, project_id: int) -> set[uuid.UUID]:
    return {
        gid
        for (gid,) in db.query(ProjectOwnerGroup.group_id)
        .filter(ProjectOwnerGroup.project_id == project_id)
        .all()
        if gid is not None
    }


def is_admin(db: Session, user: User) -> bool:
    return attach_effective_role(db, user) == ROLE_ADMIN


def owns_project(db: Session, user: User, project: Project) -> bool:
    """Administrator, creator, or member of one of the project's owner groups."""
    if is_admin(db, user):
        return True
    if project.created_by_user_id == user.id:
        return True
    return bool(user_group_ids(db, user.id) & project_owner_group_ids(db, project.id))


def can_view_drafts(db: Session, user: User, project: Project) -> bool:
    """Drafts are read by those the project belongs to, and nobody else."""
    return owns_project(db, user, project)


def draft_hidden(db: Session, user: User, project: Project, version) -> bool:
    """Whether this version is a draft the reader may not see."""
    return bool(getattr(version, "is_draft", False)) and not can_view_drafts(
        db, user, project
    )


def version_not_found() -> HTTPException:
    """The answer for a version that does not exist and for a draft the
    reader may not see: the two are told apart by nobody without draft
    rights, so a version id says nothing about unpublished releases."""
    return HTTPException(status_code=404, detail=VERSION_NOT_FOUND)


def ensure_version_visible(
    db: Session, user: User, project: Project, version: ProjectVersion | None
) -> ProjectVersion:
    if version is None or draft_hidden(db, user, project, version):
        raise version_not_found()
    return version
