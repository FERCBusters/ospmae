from __future__ import annotations

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.db.models import Group, User, UserGroup

ROLE_ADMIN = "admin"
ROLE_FRAMEWORK_ADMIN = "framework_admin"
ROLE_MAINTAINER = "maintainer"
ROLE_CONTRIBUTOR = "contributor"
ROLE_ENGINEER = "engineer"
ROLE_PRODUCT_OWNER = "product_owner"
ROLE_ARCHITECT = "architect"
ROLE_VIEWER = "viewer"
ROLE_INHERIT = "inherit"

# Used when resolving a role from multiple group memberships (when user.role == inherit).
# Higher number wins.
_ROLE_PRECEDENCE = {
    ROLE_VIEWER: 1,
    ROLE_ENGINEER: 2,
    ROLE_PRODUCT_OWNER: 3,
    ROLE_ARCHITECT: 4,
    ROLE_CONTRIBUTOR: 5,
    ROLE_MAINTAINER: 6,
    ROLE_FRAMEWORK_ADMIN: 6,  # Same precedence tier as maintainer.
    ROLE_ADMIN: 7,
}


def canonicalize_role(role: str | None) -> str | None:
    if role is None:
        return None
    v = str(role).strip().lower()
    if not v:
        return None
    if v in {
        ROLE_ADMIN,
        ROLE_FRAMEWORK_ADMIN,
        ROLE_MAINTAINER,
        ROLE_CONTRIBUTOR,
        ROLE_ENGINEER,
        ROLE_PRODUCT_OWNER,
        ROLE_ARCHITECT,
        ROLE_VIEWER,
        ROLE_INHERIT,
    }:
        return v
    return None


def normalize_role(role: str | None) -> str | None:
    return canonicalize_role(role)


def _group_role_priority_expr():
    col = func.lower(func.trim(Group.role))
    return case(
        (col == ROLE_ADMIN, _ROLE_PRECEDENCE[ROLE_ADMIN]),
        (col == ROLE_FRAMEWORK_ADMIN, _ROLE_PRECEDENCE[ROLE_FRAMEWORK_ADMIN]),
        (col == ROLE_MAINTAINER, _ROLE_PRECEDENCE[ROLE_MAINTAINER]),
        (col == ROLE_CONTRIBUTOR, _ROLE_PRECEDENCE[ROLE_CONTRIBUTOR]),
        (col == ROLE_ENGINEER, _ROLE_PRECEDENCE[ROLE_ENGINEER]),
        (col == ROLE_PRODUCT_OWNER, _ROLE_PRECEDENCE[ROLE_PRODUCT_OWNER]),
        (col == ROLE_ARCHITECT, _ROLE_PRECEDENCE[ROLE_ARCHITECT]),
        (col == ROLE_VIEWER, _ROLE_PRECEDENCE[ROLE_VIEWER]),
        else_=-1,
    )


def resolve_group_role(db: Session, user_id: int) -> str | None:
    max_rank = (
        db.query(func.max(_group_role_priority_expr()))
        .select_from(UserGroup)
        .join(Group, Group.id == UserGroup.group_id)
        .filter(UserGroup.user_id == user_id)
        .scalar()
    )

    if max_rank is None or int(max_rank) < 0:
        return None

    rank_to_role = {v: k for k, v in _ROLE_PRECEDENCE.items()}
    return rank_to_role.get(int(max_rank))


def attach_effective_role(db: Session, user: User) -> str:
    """Attach and return the user's effective role.

    - If user.role is set to any role other than 'inherit', it wins.
    - If user.role is 'inherit' (or missing), we resolve the highest role from group memberships.
    """

    direct = canonicalize_role(user.role)
    if direct and direct != ROLE_INHERIT:
        setattr(user, "effective_role", direct)
        return direct

    group_role = resolve_group_role(db, user.id)
    if group_role:
        setattr(user, "effective_role", group_role)
        return group_role

    setattr(user, "effective_role", ROLE_VIEWER)
    return ROLE_VIEWER
