from __future__ import annotations

from sqlalchemy import text
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


def resolve_group_role(db: Session, user_id: int) -> str | None:
    """The highest role among the groups an account belongs to.

    The role returned is one a group actually holds. Maintainer and
    framework administrator share a precedence tier, and neither role's
    permissions contain the other's: when an account's groups hold both, it
    resolves to maintainer, whose writes are scoped to the projects its groups
    own, and framework management is granted to such an account explicitly
    (a direct role, or the framework.write permission on a group).
    """
    held = {
        role
        for (raw,) in db.query(Group.role)
        .join(UserGroup, UserGroup.group_id == Group.id)
        .filter(UserGroup.user_id == user_id)
        .all()
        if (role := canonicalize_role(raw)) in _ROLE_PRECEDENCE
    }
    if not held:
        return None
    return max(held, key=lambda role: (_ROLE_PRECEDENCE[role], role == ROLE_MAINTAINER))


# One number for the advisory lock every administrator-affecting change takes.
_ADMIN_CHANGE_LOCK = 0x4F53504D4145


def lock_admin_changes(db: Session) -> None:
    """Serialise changes that can remove an administrator.

    Held to the end of the transaction, so two changes that would each leave
    the other account as the last administrator cannot both pass their check.
    """
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _ADMIN_CHANGE_LOCK})


def active_admin_count(db: Session) -> int:
    """Active accounts that are administrators in effect: by their own role,
    or by inheriting it from a group."""
    db.flush()
    admin_groups = [
        group_id
        for group_id, raw in db.query(Group.id, Group.role).all()
        if canonicalize_role(raw) == ROLE_ADMIN
    ]
    inheriting = (
        {
            user_id
            for (user_id,) in db.query(UserGroup.user_id)
            .filter(UserGroup.group_id.in_(admin_groups))
            .all()
        }
        if admin_groups
        else set()
    )
    count = 0
    for user_id, raw in (
        db.query(User.id, User.role).filter(User.is_active.is_(True)).all()
    ):
        direct = canonicalize_role(raw)
        if direct == ROLE_ADMIN:
            count += 1
        elif direct in (None, ROLE_INHERIT) and user_id in inheriting:
            count += 1
    return count


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
