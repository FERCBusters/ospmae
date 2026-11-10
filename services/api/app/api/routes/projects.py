from __future__ import annotations

import csv
import io
import json
import logging
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from openpyxl import Workbook
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, selectinload

from app.api.payloads import (
    ManifestClonePayload,
    ManifestCreatePayload,
    ManifestSharingUpdatePayload,
    ProjectCreatePayload,
    ProjectSubscriptionUpdatePayload,
    ProjectUpdatePayload,
    ProjectVersionCreatePayload,
    ProjectVersionFrameworkNodesPayload,
    ProjectVersionUpdatePayload,
    clean_release_feed_ignore_patterns,
)
from app.core.config import settings
from app.core.features import require_feature
from app.db.models import (
    DependencyPackage,
    DependencyVersion,
    DependencyVulnerability,
    Framework,
    FrameworkNode,
    Group,
    Manifest,
    ManifestProject,
    ManifestProjectFrameworkNode,
    Project,
    ProjectOwnerGroup,
    ProjectSubscription,
    ProjectVersion,
    ProjectVersionDependency,
    ProjectVersionFrameworkNode,
    User,
    UserGroup,
)
from app.db.session import get_db
from app.security.auth import get_current_user
from app.security.permissions import (
    PERM_MANIFEST_EXPORT,
    PERM_PROJECT_DIFF,
    PERM_PROJECT_WRITE,
    has_permission,
)
from app.security.repo_credentials import (
    RepoTokenUnavailable,
    default_username,
    encrypt_token,
)
from app.security.roles import ROLE_ADMIN, attach_effective_role
from app.services.branch_tracking import (
    DEFAULT_POLL_INTERVAL_HOURS,
    ensure_branch_version,
    is_tracking,
    mark_scan_queued,
    scan_in_flight,
)
from app.services.entity_changelog import (
    list_entity_changelogs,
    project_changelog_state,
    project_version_changelog_state,
    record_entity_changelog,
)
from app.services.mailer import send_manifest_shared_email
from app.services.notification_recipients import (
    notification_email_for_user,
    notification_emails_for_users,
)
from app.services.versioning import (
    is_semantically_newer,
    parse_semanticish_version,
    set_latest_version,
)

router = APIRouter()

logger = logging.getLogger(__name__)


def _can_view_drafts(db: Session, user: User, project: Project) -> bool:
    """Drafts are visible to admins and project owners (user or group)."""

    effective_role = attach_effective_role(db, user)
    if effective_role == ROLE_ADMIN:
        return True

    if project.created_by_user_id == user.id:
        return True

    user_groups = _user_group_ids(db, user.id)
    owner_groups = _project_owner_group_ids(db, project.id)
    return bool(user_groups and owner_groups and user_groups.intersection(owner_groups))


def _is_subscribed(db: Session, *, user_id: int, project_id: int) -> bool:
    return (
        db.query(ProjectSubscription.id)
        .filter(ProjectSubscription.user_id == user_id)
        .filter(ProjectSubscription.project_id == project_id)
        .one_or_none()
        is not None
    )


def _subscriber_emails(
    db: Session, *, project_id: int, kind: str = "new_versions"
) -> list[str]:
    """Return subscriber primary email addresses for a notification kind."""

    q = (
        db.query(User)
        .join(ProjectSubscription, ProjectSubscription.user_id == User.id)
        .filter(ProjectSubscription.project_id == project_id)
        .filter(User.is_active.is_(True))
    )

    if kind == "questions":
        q = q.filter(ProjectSubscription.notify_questions.is_(True))
    else:
        q = q.filter(ProjectSubscription.notify_new_versions.is_(True))

    return notification_emails_for_users(db, users=q.all())


def _owner_emails(db: Session, *, project: Project) -> list[str]:
    users: dict[int, User] = {}

    if project.created_by_user_id:
        owner = (
            db.query(User)
            .filter(User.id == project.created_by_user_id)
            .filter(User.is_active.is_(True))
            .one_or_none()
        )
        if owner:
            users[owner.id] = owner

    owner_group_ids = _project_owner_group_ids(db, project.id)
    if owner_group_ids:
        group_users = (
            db.query(User)
            .join(UserGroup, UserGroup.user_id == User.id)
            .filter(UserGroup.group_id.in_(sorted(owner_group_ids)))
            .filter(User.is_active.is_(True))
            .all()
        )
        users.update({user.id: user for user in group_users})

    return notification_emails_for_users(db, users=list(users.values()))


def _public_project_url(project_id: int) -> str | None:
    base = str(getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
    if not base:
        return None
    return f"{base}/project.html?id={int(project_id)}"


def _notify_subscribers_published(
    db: Session, *, project: Project, version: ProjectVersion
) -> None:
    # Drafts never notify subscribers.
    if bool(getattr(version, "is_draft", False)):
        return

    from app.services.mailer import send_project_version_published_email
    from app.tasks.notifications import kick_delivery

    url = _public_project_url(project.id)
    try:
        for email in _subscriber_emails(db, project_id=project.id):
            try:
                send_project_version_published_email(
                    db=db,
                    to_email=email,
                    project_name=project.display_name,
                    version=version.version,
                    project_url=url,
                )
            except Exception:
                # Email failures should not break API flows.
                pass
    except Exception:
        pass
    kick_delivery()


def _notify_owners_draft(
    db: Session, *, project: Project, version: ProjectVersion, source: str
) -> None:
    from app.services.mailer import send_project_version_draft_email
    from app.tasks.notifications import kick_delivery

    url = _public_project_url(project.id)
    try:
        for email in _owner_emails(db, project=project):
            try:
                send_project_version_draft_email(
                    db=db,
                    to_email=email,
                    project_name=project.display_name,
                    version=version.version,
                    project_url=url,
                    source=source,
                )
            except Exception:
                pass
    except Exception:
        pass
    kick_delivery()


def _normalize_csv_ints(value: str | None) -> list[int]:
    if not value:
        return []
    out: list[int] = []
    seen = set()
    for chunk in value.split(","):
        token = chunk.strip()
        if not token:
            continue
        try:
            num = int(token)
        except Exception:
            continue
        if num <= 0 or num in seen:
            continue
        seen.add(num)
        out.append(num)
        if len(out) >= 1000:
            # Bound the IN-clause any CSV filter can build.
            break
    return out


_EXCEL_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _excel_safe_cell(value: str) -> str:
    """Prevent spreadsheet/CSV formula injection when opened in Excel.

    If a cell begins with one of =+-@ (or a leading tab), prefix with a single quote.
    """

    s = str(value or "")
    if not s:
        return s
    if s[:1] in _EXCEL_FORMULA_PREFIXES or s.startswith("	"):
        return "'" + s
    return s


def _clean_tag_list(values) -> list[str]:
    if not values:
        return []
    if isinstance(values, str):
        values = [x.strip() for x in values.split(",") if x.strip()]
    out: list[str] = []
    seen = set()
    for raw in values:
        v = str(raw or "").strip()
        if not v:
            continue
        k = v.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(v)
    return out


def _require_write_access(db: Session, user: User) -> None:
    if not has_permission(db, user, PERM_PROJECT_WRITE):
        raise HTTPException(
            status_code=403, detail="Maintainer or admin access is required"
        )


def _require_diff_access(db: Session, user: User) -> None:
    if not has_permission(db, user, PERM_PROJECT_DIFF):
        raise HTTPException(
            status_code=403, detail="Contributor, engineer, or admin access is required"
        )


def _require_manifest_access(db: Session, user: User) -> None:
    if not has_permission(db, user, PERM_MANIFEST_EXPORT):
        raise HTTPException(
            status_code=403,
            detail="Architect, product owner, or admin access is required",
        )


def _user_group_ids(db: Session, user_id: int) -> set[int]:
    return {
        int(gid)
        for (gid,) in db.query(UserGroup.group_id)
        .filter(UserGroup.user_id == user_id)
        .all()
        if gid is not None
    }


def _project_owner_group_ids(db: Session, project_id: int) -> set[int]:
    return {
        int(gid)
        for (gid,) in db.query(ProjectOwnerGroup.group_id)
        .filter(ProjectOwnerGroup.project_id == project_id)
        .all()
        if gid is not None
    }


def _ensure_project_manage_access(db: Session, user: User, project: Project) -> None:
    _require_write_access(db, user)

    # Admin can always manage. Every other role -- maintainer included -- is
    # restricted to projects they (or one of their groups) created, so a
    # granted project.write permission never widens object scope.
    effective_role = attach_effective_role(db, user)
    if effective_role == ROLE_ADMIN:
        return

    if project.created_by_user_id == user.id:
        return

    user_groups = _user_group_ids(db, user.id)
    owner_groups = _project_owner_group_ids(db, project.id)
    if user_groups and owner_groups and user_groups.intersection(owner_groups):
        return

    raise HTTPException(
        status_code=403,
        detail="You can only edit or delete projects created by you or one of your groups.",
    )


def _can_run_dependency_discovery(db: Session, user: User, project: Project) -> bool:
    effective_role = attach_effective_role(db, user)
    if effective_role == ROLE_ADMIN:
        return True
    if project.created_by_user_id == user.id:
        return True

    user_groups = _user_group_ids(db, user.id)
    owner_groups = _project_owner_group_ids(db, project.id)
    return bool(user_groups and owner_groups and user_groups.intersection(owner_groups))


def _set_project_owner_groups(
    db: Session, project: Project, owner_group_ids: set[int]
) -> None:
    db.query(ProjectOwnerGroup).filter(
        ProjectOwnerGroup.project_id == project.id
    ).delete(synchronize_session=False)
    for gid in sorted(owner_group_ids):
        db.add(ProjectOwnerGroup(project_id=project.id, group_id=gid))


def _sort_versions(versions: list[ProjectVersion]) -> list[ProjectVersion]:
    return sorted(
        versions,
        key=lambda v: (
            (
                2
                if bool(getattr(v, "is_draft", False))
                else (1 if bool(getattr(v, "is_latest", False)) else 0)
            ),
            v.release_date or datetime.min,
            v.created_at or datetime.min,
            v.id,
        ),
        reverse=True,
    )


def _best_automatic_latest_version(
    versions: list[ProjectVersion],
) -> ProjectVersion | None:
    if not versions:
        return None

    parseable: list[tuple[Any, ProjectVersion]] = []
    for version in versions:
        parsed = parse_semanticish_version(getattr(version, "version", None))
        if parsed is not None:
            parseable.append((parsed, version))

    if parseable:
        return max(
            parseable,
            key=lambda pair: (
                pair[0],
                pair[1].release_date or datetime.min,
                pair[1].created_at or datetime.min,
                pair[1].id,
            ),
        )[1]

    return _sort_versions(versions)[0]


def _latest_version(project: Project) -> ProjectVersion | None:
    versions = [
        v for v in (project.versions or []) if not bool(getattr(v, "is_draft", False))
    ]
    if not versions:
        return None

    explicit = [v for v in versions if bool(getattr(v, "is_latest", False))]
    if explicit:
        return _sort_versions(explicit)[0]

    return _best_automatic_latest_version(versions)


def _ensure_project_has_latest(db: Session, project_id: int) -> None:
    versions = (
        db.query(ProjectVersion)
        .filter(ProjectVersion.project_id == project_id)
        .filter(ProjectVersion.is_draft.is_(False))
        .all()
    )
    if not versions:
        return
    if any(bool(v.is_latest) for v in versions):
        return
    chosen = _best_automatic_latest_version(versions)
    if chosen is not None:
        set_latest_version(db, project_id, chosen.id)


def _published_latest_for_comparison(
    db: Session, project_id: int, exclude_version_id: int | None = None
) -> ProjectVersion | None:
    query = (
        db.query(ProjectVersion)
        .filter(ProjectVersion.project_id == project_id)
        .filter(ProjectVersion.is_draft.is_(False))
    )
    if exclude_version_id is not None:
        query = query.filter(ProjectVersion.id != int(exclude_version_id))
    versions = query.all()
    if not versions:
        return None
    explicit = [v for v in versions if bool(getattr(v, "is_latest", False))]
    if explicit:
        return _sort_versions(explicit)[0]
    return _best_automatic_latest_version(versions)


def _should_auto_promote_latest(
    db: Session,
    project_id: int,
    candidate_version: str,
    *,
    candidate_version_id: int | None = None,
) -> bool:
    current = _published_latest_for_comparison(
        db, project_id, exclude_version_id=candidate_version_id
    )
    if current is None:
        return True

    newer = is_semantically_newer(candidate_version, getattr(current, "version", None))
    # If either version cannot be parsed safely, keep the current Latest marker
    # unless the user explicitly asks to promote the candidate.
    return newer is True


def _serialize_project(
    project: Project,
    *,
    latest_version: ProjectVersion | None,
    capability_paths: list[str] | None = None,
) -> dict:
    owner_group_ids = [
        int(link.group_id)
        for link in (project.owner_group_links or [])
        if link.group_id is not None
    ]
    return {
        "id": project.id,
        "machine_name": project.machine_name,
        "display_name": project.display_name,
        "organisation": project.organisation,
        "organisation_id": getattr(project, "organisation_id", None),
        "project_type": project.project_type,
        "license": project.license,
        "programming_languages": _clean_tag_list(
            getattr(project, "programming_languages", []) or []
        ),
        "capability": project.capability,
        "link_to_app": project.link_to_app,
        "release_rss_feed_url": getattr(project, "release_rss_feed_url", None),
        "release_rss_ignore_patterns": clean_release_feed_ignore_patterns(
            getattr(project, "release_rss_ignore_patterns", []) or []
        ),
        "track_branch": project.track_branch,
        "tracked_repo_url": project.tracked_repo_url,
        "tracked_branch": project.tracked_branch,
        "branch_poll_interval_hours": project.branch_poll_interval_hours,
        "branch_last_polled_at": project.branch_last_polled_at,
        # The token is write-only: only whether one is saved is reported.
        "repo_private": bool(project.repo_private),
        "repo_token_host": project.repo_token_host,
        "repo_token_username": project.repo_token_username,
        "repo_token_set": bool(project.repo_token_encrypted),
        "supported_profiles": _clean_tag_list(project.supported_profiles),
        "supported_formats": _clean_tag_list(project.supported_formats),
        "supported_issuance_protocols": _clean_tag_list(
            project.supported_issuance_protocols
        ),
        "supported_key_managements": _clean_tag_list(project.supported_key_managements),
        "supported_presentation_protocols": _clean_tag_list(
            project.supported_presentation_protocols
        ),
        "supported_signing_algorithms": _clean_tag_list(
            project.supported_signing_algorithms
        ),
        "latest_version": (
            _serialize_version(latest_version) if latest_version else None
        ),
        "capability_paths": capability_paths or [],
        "created_by_user_id": project.created_by_user_id,
        "owner_group_ids": owner_group_ids,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    }


def _serialize_version(version: ProjectVersion | None) -> dict | None:
    if not version:
        return None
    return {
        "id": version.id,
        "project_id": version.project_id,
        "version": version.version,
        "release_date": version.release_date,
        "status": version.status,
        "is_draft": bool(getattr(version, "is_draft", False)),
        "is_latest": bool(getattr(version, "is_latest", False)),
        "link_to_source_code": version.link_to_source_code,
        "notes": version.notes,
        "dependency_discovery_status": getattr(
            version, "dependency_discovery_status", "not_run"
        ),
        "dependency_discovery_started_at": getattr(
            version, "dependency_discovery_started_at", None
        ),
        "dependency_discovery_finished_at": getattr(
            version, "dependency_discovery_finished_at", None
        ),
        "dependency_discovery_error": getattr(
            version, "dependency_discovery_error", None
        ),
        "dependency_last_commit": getattr(version, "dependency_last_commit", None),
        "dependency_count": int(getattr(version, "dependency_count", 0) or 0),
        "vulnerability_count": int(getattr(version, "vulnerability_count", 0) or 0),
        "created_at": version.created_at,
        "updated_at": version.updated_at,
    }


def _ensure_framework(db: Session, framework_id: int | None) -> Framework:
    # Seed defaults (UWRA) if missing.
    from app.db.capability_taxonomy import ensure_default_frameworks

    ensure_default_frameworks(db)

    if framework_id is not None:
        fw = db.query(Framework).filter(Framework.id == framework_id).one_or_none()
        if not fw:
            raise HTTPException(status_code=404, detail="Framework not found")
        return fw

    # Default: UWRA (or first available).
    fw = db.query(Framework).filter(Framework.machine_name == "uwra").one_or_none()
    if fw:
        return fw

    fw = db.query(Framework).order_by(Framework.id.asc()).first()
    if not fw:
        raise HTTPException(status_code=500, detail="No frameworks are configured")
    return fw


def _fetch_capabilities(db: Session, framework_id: int) -> list[FrameworkNode]:
    return (
        db.query(FrameworkNode)
        .filter(FrameworkNode.framework_id == framework_id)
        .order_by(
            FrameworkNode.level.asc(),
            FrameworkNode.sort_order.asc(),
            FrameworkNode.display_name.asc(),
        )
        .all()
    )


def _capability_maps(nodes: list[FrameworkNode]):
    by_id = {n.id: n for n in nodes}
    children: dict[int | None, list[FrameworkNode]] = defaultdict(list)
    for n in nodes:
        children[n.parent_id].append(n)
    for pid in children:
        children[pid].sort(key=lambda n: (n.sort_order, n.display_name.lower(), n.id))
    return by_id, children


def _capability_paths(nodes: list[FrameworkNode]) -> dict[int, str]:
    by_id = {n.id: n for n in nodes}

    def path_for(node: FrameworkNode) -> str:
        parts = [node.display_name]
        parent_id = node.parent_id
        safety = 0
        while parent_id and parent_id in by_id and safety < 24:
            p = by_id[parent_id]
            parts.append(p.display_name)
            parent_id = p.parent_id
            safety += 1
        parts.reverse()
        return " > ".join(parts)

    return {n.id: path_for(n) for n in nodes}


def _descendant_ids(
    start_ids: list[int], children_map: dict[int | None, list[FrameworkNode]]
) -> set[int]:
    out = set()
    stack = list(start_ids)
    while stack:
        current = stack.pop()
        if current in out:
            continue
        out.add(current)
        for child in children_map.get(current, []):
            stack.append(child.id)
    return out


def _get_project_query(
    db: Session,
    q: str | None,
    framework: Framework,
    capability_ids: list[int] | None = None,
    project_ids: list[int] | None = None,
    languages: list[str] | None = None,
    statuses: list[str] | None = None,
) -> Any:
    query = db.query(Project).options(
        selectinload(Project.versions),
        selectinload(Project.owner_group_links),
    )

    if q:
        q_trim = q.strip()
        if q_trim:
            like = f"%{q_trim}%"
            query = query.filter(
                or_(
                    Project.display_name.ilike(like),
                    Project.machine_name.ilike(like),
                    Project.organisation.ilike(like),
                    Project.project_type.ilike(like),
                    Project.license.ilike(like),
                    Project.capability.ilike(like),
                )
            )

    if project_ids:
        query = query.filter(Project.id.in_(project_ids))

    if capability_ids:
        nodes = _fetch_capabilities(db, framework.id)
        by_id, children_map = _capability_maps(nodes)

        # Expand to include descendants (including the selected nodes themselves).
        criterion_ids = _descendant_ids(capability_ids, children_map)

        if criterion_ids:
            # IMPORTANT:
            # We cannot apply `.distinct()` to a full Project row here because the Project model includes
            # Postgres `json` columns (not jsonb), and Postgres cannot DISTINCT across `json` (no equality operator).
            # Instead, compute distinct project IDs in a subquery and filter the main query.
            from sqlalchemy import select

            project_ids_subq = (
                db.query(Project.id)
                .join(ProjectVersion, ProjectVersion.project_id == Project.id)
                .join(
                    ProjectVersionFrameworkNode,
                    ProjectVersionFrameworkNode.project_version_id == ProjectVersion.id,
                )
                .join(
                    FrameworkNode,
                    FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
                )
                .filter(ProjectVersion.is_latest.is_(True))
                .filter(FrameworkNode.framework_id == framework.id)
                .filter(
                    ProjectVersionFrameworkNode.framework_node_id.in_(criterion_ids)
                )
                .distinct()
                .subquery()
            )

            query = query.filter(Project.id.in_(select(project_ids_subq.c.id)))
    if languages:
        langs = _clean_tag_list(languages)
        if langs:
            clauses = [Project.programming_languages.contains([lang]) for lang in langs]
            query = query.filter(or_(*clauses))

    if statuses:
        sts = _clean_tag_list(statuses)
        if sts:
            # Filter to projects whose latest version status matches one of the selected statuses.
            from sqlalchemy import select

            sts_l = [s.lower() for s in sts if s]
            if sts_l:
                project_ids_subq = (
                    db.query(Project.id)
                    .join(ProjectVersion, ProjectVersion.project_id == Project.id)
                    .filter(ProjectVersion.is_latest.is_(True))
                    .filter(func.lower(ProjectVersion.status).in_(sts_l))
                    .distinct()
                    .subquery()
                )
                query = query.filter(Project.id.in_(select(project_ids_subq.c.id)))

    return query


def _capability_paths_for_versions(
    db: Session,
    framework_id: int,
    version_ids: list[int],
) -> dict[int, list[str]]:
    if not version_ids:
        return {}

    nodes = _fetch_capabilities(db, framework_id)
    paths_by_id = _capability_paths(nodes)

    rows = (
        db.query(ProjectVersionFrameworkNode)
        .join(
            FrameworkNode,
            FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
        )
        .filter(ProjectVersionFrameworkNode.project_version_id.in_(version_ids))
        .filter(FrameworkNode.framework_id == framework_id)
        .all()
    )

    grouped: dict[int, list[str]] = defaultdict(list)
    for row in rows:
        path = paths_by_id.get(row.framework_node_id)
        if path:
            grouped[row.project_version_id].append(path)

    for vid, arr in grouped.items():
        grouped[vid] = sorted(set(arr), key=lambda x: x.lower())

    return grouped


def _ensure_project(db: Session, project_id: int) -> Project:
    project = (
        db.query(Project)
        .options(
            selectinload(Project.versions), selectinload(Project.owner_group_links)
        )
        .filter(Project.id == project_id)
        .one_or_none()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _ensure_version(db: Session, version_id: int) -> ProjectVersion:
    version = (
        db.query(ProjectVersion).filter(ProjectVersion.id == version_id).one_or_none()
    )
    if not version:
        raise HTTPException(status_code=404, detail="Project version not found")
    return version


def _ensure_node_ids(db: Session, framework_id: int, node_ids: list[int]) -> list[int]:
    cleaned = sorted({int(x) for x in (node_ids or []) if int(x) > 0})
    if not cleaned:
        return []

    existing = {
        i
        for (i,) in (
            db.query(FrameworkNode.id)
            .filter(FrameworkNode.framework_id == framework_id)
            .filter(FrameworkNode.id.in_(cleaned))
            .all()
        )
    }
    missing = [i for i in cleaned if i not in existing]
    if missing:
        raise HTTPException(
            status_code=400, detail=f"Invalid node ids for this framework: {missing}"
        )
    return cleaned


def _selected_capability_tree(
    nodes: list[FrameworkNode], selected_ids: set[int]
) -> list[dict]:
    by_id, children_map = _capability_maps(nodes)

    include_ids: set[int] = set(selected_ids)
    for sid in list(selected_ids):
        current = by_id.get(sid)
        guard = 0
        while current and current.parent_id and guard < 24:
            include_ids.add(current.parent_id)
            current = by_id.get(current.parent_id)
            guard += 1

    items = {
        n.id: {
            "id": n.id,
            "key": n.key,
            "display_name": n.display_name,
            "parent_id": n.parent_id,
            "level": n.level,
            "sort_order": n.sort_order,
            "selected": n.id in selected_ids,
            "children": [],
        }
        for n in nodes
        if n.id in include_ids
    }

    roots: list[dict] = []
    for n in nodes:
        if n.id not in items:
            continue
        payload = items[n.id]
        if payload["parent_id"] and payload["parent_id"] in items:
            items[payload["parent_id"]]["children"].append(payload)  # type: ignore[index,attr-defined]  # parent chains self-validate above
        else:
            roots.append(payload)

    def sort_children(node: dict):
        node["children"].sort(
            key=lambda x: (x["sort_order"], x["display_name"].lower(), x["id"])
        )
        for child in node["children"]:
            sort_children(child)

    roots.sort(key=lambda x: (x["sort_order"], x["display_name"].lower(), x["id"]))
    for root in roots:
        sort_children(root)
    return roots


@router.get("/v1/projects")
async def list_projects(
    q: str | None = Query(default=None),
    framework_id: int | None = Query(default=None),
    node_ids: str | None = Query(default=None),
    # Backwards-compatible alias (treated as node_ids)
    capability_ids: str | None = Query(default=None),
    project_ids: str | None = Query(default=None),
    languages: str | None = Query(default=None),
    programming_languages: str | None = Query(default=None),
    statuses: str | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    framework = _ensure_framework(db, framework_id)

    selected = _normalize_csv_ints(node_ids or capability_ids)
    project_id_list = _normalize_csv_ints(project_ids)
    selected_langs = _clean_tag_list(languages or programming_languages)
    selected_statuses = _clean_tag_list(statuses)

    query = _get_project_query(
        db,
        q,
        framework,
        capability_ids=selected,
        project_ids=project_id_list,
        languages=selected_langs,
        statuses=selected_statuses,
    )

    projects = query.order_by(Project.display_name.asc()).all()

    version_ids = [v.id for c in projects for v in c.versions]
    capability_paths_by_version = _capability_paths_for_versions(
        db, framework.id, version_ids
    )

    items = []
    for c in projects:
        latest = _latest_version(c)
        cap_paths = capability_paths_by_version.get(latest.id, []) if latest else []
        items.append(
            _serialize_project(c, latest_version=latest, capability_paths=cap_paths)
        )

    return {
        "framework": {
            "id": framework.id,
            "machine_name": framework.machine_name,
            "display_name": framework.display_name,
        },
        "items": items,
    }


def _resolve_organisation(
    db: Session, payload: ProjectCreatePayload
) -> tuple[str | None, int | None]:
    """Attach every project to an Organisation record.

    A payload naming a known organisation reuses its row; a payload naming a
    not-yet-recorded name creates that record on first use, so the catalogue
    never keeps a project outside the FK relationship while legacy clients
    that only send the plain-text name keep working.
    """
    from app.db.models import Organisation

    if payload.organisation_id is not None:
        row = (
            db.query(Organisation)
            .filter(Organisation.id == int(payload.organisation_id))
            .one_or_none()
        )
        if row is None:
            raise HTTPException(status_code=400, detail="Unknown organisation_id")
        return row.name, int(row.id)

    name = (payload.organisation or "").strip()
    if not name:
        return None, None
    row = db.query(Organisation).filter(Organisation.name == name).one_or_none()
    if row is None:
        row = Organisation(name=name)
        db.add(row)
        db.flush()
    return row.name, int(row.id)


def _require_branch_tracking_fields(project: Project) -> None:
    if project.track_branch and not (
        project.tracked_repo_url and project.tracked_branch
    ):
        raise HTTPException(
            status_code=422,
            detail="Tracking a branch needs a repository URL and a branch name",
        )


_REPO_ACCESS_FIELDS = (
    "repo_private",
    "repo_token",
    "repo_token_host",
    "repo_token_username",
)


def _apply_repo_access(project: Project, changes: dict) -> None:
    """Apply a request's private-repository settings to a project.

    A token is bound to the host it is entered for: changing the host needs
    the token entered again, so a saved token never follows a host it was
    not typed for. Making the repository public deletes the token.
    """

    requested = changes.get("repo_private")
    private = bool(project.repo_private if requested is None else requested)
    if not private:
        project.repo_private = False
        project.repo_token_host = None
        project.repo_token_username = None
        project.repo_token_encrypted = None
        project.repo_token_updated_at = None
        return

    token = changes.get("repo_token")
    host = changes.get("repo_token_host", project.repo_token_host)
    if not host:
        raise HTTPException(
            status_code=422, detail="Enter the host the access token is for"
        )
    if host != project.repo_token_host and not token and project.repo_token_encrypted:
        raise HTTPException(
            status_code=422,
            detail="Enter the access token again for the new host",
        )
    username = changes.get("repo_token_username", project.repo_token_username)
    if not username and default_username(host) is None:
        raise HTTPException(
            status_code=422,
            detail=f"Enter the account name the token belongs to on {host}",
        )
    if token:
        try:
            project.repo_token_encrypted = encrypt_token(token)
        except RepoTokenUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        project.repo_token_updated_at = datetime.utcnow()
    if not project.repo_token_encrypted:
        raise HTTPException(
            status_code=422,
            detail="Enter an access token for the private repository",
        )
    project.repo_private = True
    project.repo_token_host = host
    project.repo_token_username = username or None


def _start_branch_scan(
    db: Session, request: Request, user: User, project: Project
) -> None:
    """Bring the tracked branch's version up to date and scan its head now.

    Saving the tracking settings is the maintainer's request for a scan; the
    poller then re-scans every branch_poll_interval_hours from this point.
    """

    from app.core.features import is_enabled

    now = datetime.utcnow()
    version, created = ensure_branch_version(db, project)
    if created:
        record_entity_changelog(
            db,
            entity_type="project_version",
            entity_id=version.id,
            action="created",
            before=None,
            after=project_version_changelog_state(db, version),
            user=user,
            request_method=request.method,
            request_path=request.url.path,
        )
    launch = (
        is_enabled("dependency_scans", db)
        and settings.dependency_discovery_enabled
        and not scan_in_flight(version, now)
    )
    if launch:
        mark_scan_queued(version)
    project.branch_last_polled_at = now
    db.commit()

    if launch:
        try:
            from app.tasks.dependency_discovery import (
                discover_project_version_dependencies,
            )

            discover_project_version_dependencies.delay(version.id)
        except Exception:
            # The queued-discovery dispatcher picks it up on its next beat.
            logger.exception(
                "Failed to enqueue branch scan for project_id=%s", project.id
            )


@router.post("/v1/projects")
def create_project(
    request: Request,
    payload: ProjectCreatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_write_access(db, user)

    exists = (
        db.query(Project.id)
        .filter(Project.machine_name == payload.machine_name.strip())
        .one_or_none()
    )
    if exists:
        raise HTTPException(status_code=409, detail="machine_name already exists")

    organisation_name, organisation_id = _resolve_organisation(db, payload)

    project = Project(
        machine_name=payload.machine_name.strip(),
        display_name=payload.display_name.strip(),
        organisation=organisation_name,
        organisation_id=organisation_id,
        project_type=payload.project_type,
        license=payload.license,
        programming_languages=_clean_tag_list(payload.programming_languages),
        capability=payload.capability,
        link_to_app=payload.link_to_app,
        release_rss_feed_url=(payload.release_rss_feed_url or None),
        release_rss_ignore_patterns=clean_release_feed_ignore_patterns(
            payload.release_rss_ignore_patterns  # type: ignore[arg-type]
        ),
        supported_profiles=_clean_tag_list(payload.supported_profiles),
        supported_formats=_clean_tag_list(payload.supported_formats),
        supported_issuance_protocols=_clean_tag_list(
            payload.supported_issuance_protocols
        ),
        supported_key_managements=_clean_tag_list(payload.supported_key_managements),
        supported_presentation_protocols=_clean_tag_list(
            payload.supported_presentation_protocols
        ),
        supported_signing_algorithms=_clean_tag_list(
            payload.supported_signing_algorithms
        ),
        track_branch=bool(payload.track_branch),
        tracked_repo_url=payload.tracked_repo_url,
        tracked_branch=payload.tracked_branch,
        branch_poll_interval_hours=(
            payload.branch_poll_interval_hours or DEFAULT_POLL_INTERVAL_HOURS
        ),
        created_by_user_id=user.id,
    )
    _require_branch_tracking_fields(project)
    _apply_repo_access(
        project,
        payload.model_dump(include=set(_REPO_ACCESS_FIELDS), exclude_unset=True),
    )
    if is_tracking(project):
        # Committed with the project, so the poller never sees a tracked
        # branch that this request is about to scan as overdue.
        project.branch_last_polled_at = datetime.utcnow()

    db.add(project)
    db.commit()
    db.refresh(project)

    creator_group_ids = _user_group_ids(db, user.id)
    if creator_group_ids:
        _set_project_owner_groups(db, project, creator_group_ids)
        db.commit()
        db.refresh(project)

    record_entity_changelog(
        db,
        entity_type="project",
        entity_id=project.id,
        action="created",
        before=None,
        after=project_changelog_state(db, project),
        user=user,
        request_method=request.method,
        request_path=request.url.path,
    )
    db.commit()

    if is_tracking(project):
        _start_branch_scan(db, request, user, project)
        db.refresh(project)
        latest = _latest_version(project)
        return _serialize_project(project, latest_version=latest, capability_paths=[])

    if str(payload.release_rss_feed_url or "").strip():
        from app.core.features import is_enabled
        from app.tasks.release_feed import discover_project_release_feed

        if is_enabled("release_feed", db):
            try:
                discover_project_release_feed.delay(project.id)
            except Exception:
                logger.exception(
                    "Failed to enqueue initial release discovery for project_id=%s",
                    project.id,
                )

    return _serialize_project(project, latest_version=None, capability_paths=[])


@router.get(
    "/v1/projects/compare", dependencies=[Depends(require_feature("comparisons"))]
)
def compare_projects(
    left_project_id: int = Query(..., ge=1),
    right_project_id: int = Query(..., ge=1),
    left_version_id: int | None = Query(None, ge=1),
    right_version_id: int | None = Query(None, ge=1),
    framework_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate a unified diff between two projects (and optionally specific versions).

    Used by contributor/engineer roles for comparison workflows.
    """
    _require_diff_access(db, user)

    left_project = (
        db.query(Project)
        .options(selectinload(Project.owner_group_links))
        .filter(Project.id == left_project_id)
        .one_or_none()
    )
    right_project = (
        db.query(Project)
        .options(selectinload(Project.owner_group_links))
        .filter(Project.id == right_project_id)
        .one_or_none()
    )
    if not left_project or not right_project:
        raise HTTPException(status_code=404, detail="Project not found")

    can_view_drafts = _can_view_drafts(db, user, left_project) and _can_view_drafts(
        db, user, right_project
    )

    def pick_version(project_id: int, version_id: int | None) -> ProjectVersion | None:
        if version_id:
            version = (
                db.query(ProjectVersion)
                .filter(
                    ProjectVersion.id == version_id,
                    ProjectVersion.project_id == project_id,
                )
                .one_or_none()
            )
            if (
                version
                and bool(getattr(version, "is_draft", False))
                and not can_view_drafts
            ):
                # Drafts stay invisible to the comparison endpoint unless the
                # caller can view drafts of both sides, matching every other
                # version-reading route.
                return None
            return version
        query = db.query(ProjectVersion).filter(ProjectVersion.project_id == project_id)
        if not can_view_drafts:
            query = query.filter(ProjectVersion.is_draft == False)  # noqa: E712
        return query.order_by(
            ProjectVersion.is_latest.desc(),
            ProjectVersion.release_date.desc().nullslast(),
            ProjectVersion.id.desc(),
        ).first()

    left_version = pick_version(left_project_id, left_version_id)
    right_version = pick_version(right_project_id, right_version_id)

    framework = _ensure_framework(db, framework_id)
    cap_nodes = _fetch_capabilities(db, framework.id)
    cap_paths = _capability_paths(cap_nodes)

    def version_cap_paths(version: ProjectVersion | None) -> list[str]:
        if not version:
            return []
        ids = [
            int(cid)
            for (cid,) in (
                db.query(ProjectVersionFrameworkNode.framework_node_id)
                .join(
                    FrameworkNode,
                    FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
                )
                .filter(
                    ProjectVersionFrameworkNode.project_version_id == version.id,
                    FrameworkNode.framework_id == framework.id,
                )
                .all()
            )
            if cid is not None
        ]
        out = [cap_paths.get(cid, str(cid)) for cid in ids if cid in cap_paths]
        out.sort()
        return out

    left_obj = _serialize_project(
        left_project,
        latest_version=left_version,
        capability_paths=version_cap_paths(left_version),
    )
    right_obj = _serialize_project(
        right_project,
        latest_version=right_version,
        capability_paths=version_cap_paths(right_version),
    )

    left_text = json.dumps(left_obj, indent=2, sort_keys=True, default=str).splitlines(
        keepends=True
    )
    right_text = json.dumps(
        right_obj, indent=2, sort_keys=True, default=str
    ).splitlines(keepends=True)

    import difflib

    diff = "".join(
        difflib.unified_diff(
            left_text,
            right_text,
            fromfile=f"project:{left_project_id}",
            tofile=f"project:{right_project_id}",
        )
    )

    return {
        "left": left_obj,
        "right": right_obj,
        "diff": diff,
    }


@router.get("/v1/projects/{project_id}")
def get_project(
    project_id: int,
    framework_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    framework = _ensure_framework(db, framework_id)
    project = _ensure_project(db, project_id)
    can_view_drafts = _can_view_drafts(db, user, project)
    versions_all = _sort_versions(project.versions)
    versions = (
        versions_all
        if can_view_drafts
        else [v for v in versions_all if not bool(getattr(v, "is_draft", False))]
    )

    version_ids = [v.id for v in versions]
    capability_paths_by_version = _capability_paths_for_versions(
        db, framework.id, version_ids
    )

    # Latest published version (drafts never count as latest).
    latest_published = _latest_version(project)

    return {
        "framework": {
            "id": framework.id,
            "machine_name": framework.machine_name,
            "display_name": framework.display_name,
        },
        **_serialize_project(
            project,
            latest_version=latest_published,
            capability_paths=(
                capability_paths_by_version.get(latest_published.id, [])
                if latest_published
                else []
            ),
        ),
        "can_view_drafts": bool(can_view_drafts),
        "is_subscribed": bool(
            _is_subscribed(db, user_id=user.id, project_id=project.id)
        ),
        "versions": [
            {
                **_serialize_version(v),  # type: ignore[dict-item]  # values are JSON-serialised
                "capability_paths": capability_paths_by_version.get(v.id, []),
            }
            for v in versions
        ],
    }


@router.get("/v1/projects/{project_id}/versions")
def list_project_versions(
    project_id: int,
    framework_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    framework = _ensure_framework(db, framework_id)
    project = _ensure_project(db, project_id)
    can_view_drafts = _can_view_drafts(db, user, project)
    versions_all = _sort_versions(project.versions)
    versions = (
        versions_all
        if can_view_drafts
        else [v for v in versions_all if not bool(getattr(v, "is_draft", False))]
    )

    version_ids = [v.id for v in versions]
    capability_paths_by_version = _capability_paths_for_versions(
        db, framework.id, version_ids
    )

    return {
        "framework": {
            "id": framework.id,
            "machine_name": framework.machine_name,
            "display_name": framework.display_name,
        },
        "can_view_drafts": bool(can_view_drafts),
        "items": [
            {
                **_serialize_version(v),  # type: ignore[dict-item]  # values are JSON-serialised
                "capability_paths": capability_paths_by_version.get(v.id, []),
            }
            for v in versions
        ],
    }


@router.get("/v1/projects/{project_id}/changelog")
def get_project_changelog(
    project_id: int,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _ensure_project(db, project_id)
    return list_entity_changelogs(
        db,
        entity_type="project",
        entity_id=project_id,
        limit=limit,
        offset=offset,
    )


@router.get("/v1/project-versions/{version_id}/changelog")
def get_project_version_changelog(
    version_id: int,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    version = _ensure_version(db, version_id)
    project = _ensure_project(db, version.project_id)
    if bool(getattr(version, "is_draft", False)) and not _can_view_drafts(
        db, user, project
    ):
        raise HTTPException(status_code=403, detail="Draft version is not accessible")
    return list_entity_changelogs(
        db,
        entity_type="project_version",
        entity_id=version_id,
        limit=limit,
        offset=offset,
    )


@router.put("/v1/projects/{project_id}")
def update_project(
    request: Request,
    project_id: int,
    payload: ProjectUpdatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = _ensure_project(db, project_id)
    _ensure_project_manage_access(db, user, project)
    before = project_changelog_state(db, project)

    updates = payload.model_dump(exclude_unset=True)
    rss_changed = "release_rss_feed_url" in updates
    before_feed_url = str(project.release_rss_feed_url or "").strip()
    before_tracking = (
        is_tracking(project),
        project.tracked_repo_url,
        project.tracked_branch,
    )
    if updates.get("branch_poll_interval_hours", 0) is None:
        # The interval always has a value; an explicit null keeps the stored one.
        updates.pop("branch_poll_interval_hours")
    if "track_branch" in updates:
        updates["track_branch"] = bool(updates["track_branch"])
    repo_access = {
        key: updates.pop(key) for key in _REPO_ACCESS_FIELDS if key in updates
    }
    if repo_access:
        _apply_repo_access(project, repo_access)

    if "organisation" in updates or "organisation_id" in updates:
        org_name, org_id = _resolve_organisation(db, payload)
        if "organisation" in updates:
            updates["organisation"] = org_name
            updates["organisation_id"] = org_id
        elif org_id is not None:
            from app.db.models import Organisation

            org = db.query(Organisation).filter(Organisation.id == org_id).one()
            updates["organisation_id"] = org_id
            updates["organisation"] = org.name

    for key, value in updates.items():
        if key in {
            "supported_profiles",
            "supported_formats",
            "supported_issuance_protocols",
            "supported_key_managements",
            "supported_presentation_protocols",
            "supported_signing_algorithms",
            "programming_languages",
        }:
            value = _clean_tag_list(value)
        elif key == "release_rss_ignore_patterns":
            value = clean_release_feed_ignore_patterns(value)
        setattr(project, key, value)

    _require_branch_tracking_fields(project)
    tracking_target_changed = is_tracking(project) and before_tracking != (
        True,
        project.tracked_repo_url,
        project.tracked_branch,
    )
    if tracking_target_changed:
        # Claimed before commit: the poller's compare-and-set loses to this
        # request, which scans the new target itself below.
        project.branch_last_polled_at = datetime.utcnow()

    # If the release feed URL changed, reset polling state so the worker can baseline.
    if rss_changed:
        project.release_rss_last_entry_id = None
        project.release_rss_last_checked_at = None
        project.release_rss_last_etag = None
        project.release_rss_last_modified = None

    db.add(project)
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

    # Starting to track a branch, or pointing tracking at another repository
    # or branch, scans the new head straight away.
    if tracking_target_changed:
        _start_branch_scan(db, request, user, project)
        db.refresh(project)

    # A newly attached release feed starts full discovery (see
    # discover_project_release_feed): the maintainer has told the catalogue
    # nothing yet, so the whole feed is imported rather than only the newest
    # staged draft entry.
    if (
        rss_changed
        and str(project.release_rss_feed_url or "").strip()
        and not before_feed_url
        and not project.track_branch
    ):
        from app.core.features import is_enabled
        from app.tasks.release_feed import discover_project_release_feed

        if is_enabled("release_feed", db):
            try:
                discover_project_release_feed.delay(project.id)
            except Exception:
                logger.exception(
                    "Failed to enqueue initial release discovery for project_id=%s",
                    project.id,
                )

    latest = _latest_version(project)
    capability_paths = []
    if latest:
        fw = _ensure_framework(db, None)
        capability_paths = _capability_paths_for_versions(db, fw.id, [latest.id]).get(
            latest.id, []
        )
    return _serialize_project(
        project, latest_version=latest, capability_paths=capability_paths
    )


@router.delete("/v1/projects/{project_id}")
def delete_project(
    request: Request,
    project_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = _ensure_project(db, project_id)
    _ensure_project_manage_access(db, user, project)
    before = project_changelog_state(db, project)

    db.delete(project)
    record_entity_changelog(
        db,
        entity_type="project",
        entity_id=project_id,
        action="deleted",
        before=before,
        after=None,
        user=user,
        request_method=request.method,
        request_path=request.url.path,
    )
    db.commit()
    return Response(status_code=204)


@router.get("/v1/projects/{project_id}/subscription")
def get_project_subscription(
    project_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _ensure_project(db, project_id)

    sub = (
        db.query(ProjectSubscription)
        .filter(ProjectSubscription.project_id == project_id)
        .filter(ProjectSubscription.user_id == user.id)
        .one_or_none()
    )

    if not sub:
        return {
            "subscribed": False,
            "notify_new_versions": False,
            "notify_questions": False,
        }

    return {
        "subscribed": True,
        "notify_new_versions": bool(getattr(sub, "notify_new_versions", True)),
        "notify_questions": bool(getattr(sub, "notify_questions", False)),
    }


@router.post("/v1/projects/{project_id}/subscription")
def subscribe_to_project(
    project_id: int,
    payload: ProjectSubscriptionUpdatePayload | None = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _ensure_project(db, project_id)

    if not notification_email_for_user(db, user=user):
        raise HTTPException(
            status_code=400,
            detail="You must have an email address available (from your account or SSO) to subscribe.",
        )

    # Backwards compatible default: subscribing without payload means "new versions" only.
    notify_new_versions = True
    notify_questions = False
    if payload is not None:
        if payload.notify_new_versions is not None:
            notify_new_versions = bool(payload.notify_new_versions)
        if payload.notify_questions is not None:
            notify_questions = bool(payload.notify_questions)

    # If the user deselects all options, remove the subscription.
    if not notify_new_versions and not notify_questions:
        db.query(ProjectSubscription).filter(
            ProjectSubscription.project_id == project_id,
            ProjectSubscription.user_id == user.id,
        ).delete(synchronize_session=False)
        db.commit()
        return {
            "subscribed": False,
            "notify_new_versions": False,
            "notify_questions": False,
        }

    existing = (
        db.query(ProjectSubscription)
        .filter(ProjectSubscription.project_id == project_id)
        .filter(ProjectSubscription.user_id == user.id)
        .one_or_none()
    )

    if not existing:
        existing = ProjectSubscription(
            project_id=project_id,
            user_id=user.id,
            notify_new_versions=notify_new_versions,
            notify_questions=notify_questions,
        )
        db.add(existing)
    else:
        existing.notify_new_versions = notify_new_versions
        existing.notify_questions = notify_questions
        db.add(existing)

    db.commit()

    return {
        "subscribed": True,
        "notify_new_versions": notify_new_versions,
        "notify_questions": notify_questions,
    }


@router.delete("/v1/projects/{project_id}/subscription")
def unsubscribe_from_project(
    project_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _ensure_project(db, project_id)
    db.query(ProjectSubscription).filter(
        ProjectSubscription.project_id == project_id,
        ProjectSubscription.user_id == user.id,
    ).delete(synchronize_session=False)
    db.commit()
    return Response(status_code=204)


@router.post("/v1/projects/{project_id}/versions")
def create_project_version(
    request: Request,
    project_id: int,
    payload: ProjectVersionCreatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = _ensure_project(db, project_id)
    _ensure_project_manage_access(db, user, project)

    version_name = payload.version.strip()
    existing = (
        db.query(ProjectVersion.id)
        .filter(
            ProjectVersion.project_id == project_id,
            ProjectVersion.version == version_name,
        )
        .one_or_none()
    )
    if existing:
        raise HTTPException(
            status_code=409, detail="Version already exists for this project"
        )

    previous_latest = _latest_version(project)

    is_draft = bool(payload.is_draft) if payload.is_draft is not None else False
    # Drafts can never be the project's latest public release. Non-draft
    # versions are auto-promoted only when newer than the current published
    # latest; users can still explicitly mark any published version as Latest.
    requested_latest = payload.is_latest
    is_latest = False if is_draft else bool(requested_latest is True)

    version = ProjectVersion(
        project_id=project_id,
        version=version_name,
        release_date=payload.release_date,
        status=payload.status,
        link_to_source_code=payload.link_to_source_code,
        notes=payload.notes,
        is_latest=is_latest,
        is_draft=is_draft,
    )

    auto_discovery = bool(
        _can_run_dependency_discovery(db, user, project)
        and getattr(settings, "dependency_discovery_enabled", True)
        and getattr(settings, "dependency_discovery_auto_enqueue", True)
        and str(payload.link_to_source_code or "").strip()
    )
    if auto_discovery:
        version.dependency_discovery_status = "queued"
        version.dependency_discovery_error = None
        version.dependency_discovery_started_at = None
        version.dependency_discovery_finished_at = None
        version.dependency_last_commit = None
        version.dependency_count = 0
        version.vulnerability_count = 0

    db.add(version)
    db.flush()

    # Inherit capability mappings from the previous latest version by default.
    if previous_latest:
        inherited_capability_ids = (
            db.query(ProjectVersionFrameworkNode.framework_node_id)
            .filter(
                ProjectVersionFrameworkNode.project_version_id == previous_latest.id
            )
            .all()
        )
        for (framework_node_id,) in inherited_capability_ids:
            db.add(
                ProjectVersionFrameworkNode(
                    project_version_id=version.id,
                    framework_node_id=framework_node_id,
                )
            )

    if is_latest:
        set_latest_version(db, project_id, version.id)
    elif (
        not is_draft
        and requested_latest is None
        and _should_auto_promote_latest(
            db, project_id, version.version, candidate_version_id=version.id
        )
    ):
        set_latest_version(db, project_id, version.id)
    else:
        _ensure_project_has_latest(db, project_id)

    db.flush()
    db.refresh(version)
    record_entity_changelog(
        db,
        entity_type="project_version",
        entity_id=version.id,
        action="created",
        before=None,
        after=project_version_changelog_state(db, version),
        user=user,
        request_method=request.method,
        request_path=request.url.path,
    )
    db.commit()
    db.refresh(version)

    # Notify subscribers for published releases only.
    if not is_draft:
        _notify_subscribers_published(db, project=project, version=version)

    if auto_discovery:
        try:
            from app.tasks.dependency_discovery import (
                discover_project_version_dependencies,
            )

            discover_project_version_dependencies.delay(version.id)
        except Exception:
            # If the broker is unavailable, Celery beat will dispatch queued jobs later.
            pass

    return _serialize_version(version)


@router.put("/v1/project-versions/{version_id}")
def update_project_version(
    request: Request,
    version_id: int,
    payload: ProjectVersionUpdatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    version = _ensure_version(db, version_id)
    project = _ensure_project(db, version.project_id)
    _ensure_project_manage_access(db, user, project)

    old_link = str(version.link_to_source_code or "").strip()
    old_is_draft = bool(getattr(version, "is_draft", False))
    before = project_version_changelog_state(db, version)

    updates = payload.model_dump(exclude_unset=True)
    if "version" in updates and updates["version"]:
        updates["version"] = updates["version"].strip()
        duplicate = (
            db.query(ProjectVersion.id)
            .filter(
                ProjectVersion.project_id == version.project_id,
                ProjectVersion.version == updates["version"],
                ProjectVersion.id != version.id,
            )
            .one_or_none()
        )
        if duplicate:
            raise HTTPException(
                status_code=409, detail="Version already exists for this project"
            )

    is_latest_update = (
        updates.pop("is_latest", None) if "is_latest" in updates else None
    )
    is_draft_update = updates.pop("is_draft", None) if "is_draft" in updates else None

    for key, value in updates.items():
        setattr(version, key, value)

    if is_draft_update is not None:
        version.is_draft = bool(is_draft_update)

    new_link = str(version.link_to_source_code or "").strip()
    auto_discovery = bool(
        _can_run_dependency_discovery(db, user, project)
        and getattr(settings, "dependency_discovery_enabled", True)
        and getattr(settings, "dependency_discovery_auto_enqueue", True)
        and new_link
        and new_link != old_link
    )
    if auto_discovery:
        version.dependency_discovery_status = "queued"
        version.dependency_discovery_error = None
        version.dependency_discovery_started_at = None
        version.dependency_discovery_finished_at = None
        version.dependency_last_commit = None
        version.dependency_count = 0
        version.vulnerability_count = 0

    db.add(version)
    db.flush()

    # Drafts can never be latest.
    if bool(getattr(version, "is_draft", False)):
        version.is_latest = False
        db.add(version)
        db.flush()
        _ensure_project_has_latest(db, version.project_id)
    else:
        transitioned_from_draft = old_is_draft and not bool(
            getattr(version, "is_draft", False)
        )

        if is_latest_update is True:
            set_latest_version(db, version.project_id, version.id)
        elif is_latest_update is False:
            version.is_latest = False
            db.add(version)
            db.flush()
            _ensure_project_has_latest(db, version.project_id)
        elif transitioned_from_draft and _should_auto_promote_latest(
            db,
            version.project_id,
            version.version,
            candidate_version_id=version.id,
        ):
            set_latest_version(db, version.project_id, version.id)

    db.flush()
    db.refresh(version)
    record_entity_changelog(
        db,
        entity_type="project_version",
        entity_id=version.id,
        action="updated",
        before=before,
        after=project_version_changelog_state(db, version),
        user=user,
        request_method=request.method,
        request_path=request.url.path,
    )
    db.commit()
    db.refresh(version)

    # If we just published a draft, notify subscribers.
    if old_is_draft and not bool(getattr(version, "is_draft", False)):
        try:
            project = _ensure_project(db, version.project_id)
            _notify_subscribers_published(db, project=project, version=version)
        except Exception:
            pass

    if auto_discovery:
        try:
            from app.tasks.dependency_discovery import (
                discover_project_version_dependencies,
            )

            discover_project_version_dependencies.delay(version.id)
        except Exception:
            pass

    return _serialize_version(version)


@router.delete("/v1/project-versions/{version_id}")
def delete_project_version(
    request: Request,
    version_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    version = _ensure_version(db, version_id)
    project = _ensure_project(db, version.project_id)
    _ensure_project_manage_access(db, user, project)

    project_id = version.project_id
    before = project_version_changelog_state(db, version)
    db.delete(version)
    db.flush()
    _ensure_project_has_latest(db, project_id)
    record_entity_changelog(
        db,
        entity_type="project_version",
        entity_id=version_id,
        action="deleted",
        before=before,
        after=None,
        user=user,
        request_method=request.method,
        request_path=request.url.path,
    )
    db.commit()
    return Response(status_code=204)


@router.get("/v1/project-versions/{version_id}/framework-nodes")
def get_project_version_framework_nodes(
    version_id: int,
    framework_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    version = _ensure_version(db, version_id)
    project = _ensure_project(db, version.project_id)
    if bool(getattr(version, "is_draft", False)) and not _can_view_drafts(
        db, user, project
    ):
        raise HTTPException(status_code=403, detail="Draft version is not accessible")

    framework = _ensure_framework(db, framework_id)

    nodes = _fetch_capabilities(db, framework.id)
    by_id = {n.id: n for n in nodes}
    path_map = _capability_paths(nodes)

    selected_ids = {
        nid
        for (nid,) in (
            db.query(ProjectVersionFrameworkNode.framework_node_id)
            .join(
                FrameworkNode,
                FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
            )
            .filter(ProjectVersionFrameworkNode.project_version_id == version_id)
            .filter(FrameworkNode.framework_id == framework.id)
            .all()
        )
    }

    selected = []
    for nid in sorted(selected_ids):
        node = by_id.get(nid)
        if not node:
            continue
        selected.append(
            {
                "id": node.id,
                "key": node.key,
                "display_name": node.display_name,
                "parent_id": node.parent_id,
                "level": node.level,
                "path": path_map.get(node.id, node.display_name),
            }
        )

    return {
        "version_id": version_id,
        "framework": {
            "id": framework.id,
            "machine_name": framework.machine_name,
            "display_name": framework.display_name,
        },
        "node_ids": sorted(selected_ids),
        "nodes": selected,
    }


# Backwards-compatible alias (treated as framework-nodes)
@router.get("/v1/project-versions/{version_id}/capabilities")
def get_project_version_capabilities(
    version_id: int,
    framework_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return get_project_version_framework_nodes(
        version_id=version_id,
        framework_id=framework_id,
        db=db,
        user=user,
    )


@router.put("/v1/project-versions/{version_id}/framework-nodes")
def set_project_version_framework_nodes(
    request: Request,
    version_id: int,
    payload: ProjectVersionFrameworkNodesPayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    version = _ensure_version(db, version_id)
    project = _ensure_project(db, version.project_id)
    _ensure_project_manage_access(db, user, project)
    before = project_version_changelog_state(db, version)

    framework = _ensure_framework(db, payload.framework_id)
    node_ids = _ensure_node_ids(db, framework.id, payload.node_ids)

    # Remove existing mappings for this framework only.
    existing_ids = (
        db.query(ProjectVersionFrameworkNode.id)
        .join(
            FrameworkNode,
            FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
        )
        .filter(ProjectVersionFrameworkNode.project_version_id == version_id)
        .filter(FrameworkNode.framework_id == framework.id)
        .all()
    )
    if existing_ids:
        db.query(ProjectVersionFrameworkNode).filter(
            ProjectVersionFrameworkNode.id.in_([i for (i,) in existing_ids])
        ).delete(synchronize_session=False)

    for node_id in node_ids:
        db.add(
            ProjectVersionFrameworkNode(
                project_version_id=version_id,
                framework_node_id=node_id,
            )
        )

    db.flush()
    record_entity_changelog(
        db,
        entity_type="project_version",
        entity_id=version_id,
        action="updated",
        before=before,
        after=project_version_changelog_state(db, version_id),
        user=user,
        request_method=request.method,
        request_path=request.url.path,
    )
    db.commit()

    return get_project_version_framework_nodes(
        version_id=version_id,
        framework_id=framework.id,
        db=db,
        user=user,
    )


# Backwards-compatible alias (payload.framework_id is optional; defaults to UWRA)
@router.put("/v1/project-versions/{version_id}/capabilities")
def set_project_version_capabilities(
    request: Request,
    version_id: int,
    payload: ProjectVersionFrameworkNodesPayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # If caller sent legacy payload shape, try to interpret.
    fw_id = getattr(payload, "framework_id", None)
    if fw_id is None:
        fw = _ensure_framework(db, None)
        payload.framework_id = fw.id

    return set_project_version_framework_nodes(
        request=request,
        version_id=version_id,
        payload=payload,
        db=db,
        user=user,
    )


@router.get("/v1/projects/{project_id}/graph")
def get_project_graph(
    project_id: int,
    framework_id: int | None = Query(default=None),
    version_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    framework = _ensure_framework(db, framework_id)
    project = _ensure_project(db, project_id)

    can_view_drafts = _can_view_drafts(db, user, project)
    versions_all = _sort_versions(project.versions)
    versions = (
        versions_all
        if can_view_drafts
        else [v for v in versions_all if not bool(getattr(v, "is_draft", False))]
    )

    target_version = None
    if version_id is not None:
        any_match = next((v for v in versions_all if v.id == version_id), None)
        if (
            any_match
            and bool(getattr(any_match, "is_draft", False))
            and not can_view_drafts
        ):
            raise HTTPException(
                status_code=403, detail="Draft version is not accessible"
            )
        target_version = next((v for v in versions if v.id == version_id), None)
        if not target_version:
            raise HTTPException(status_code=404, detail="Version not found for project")
    else:
        target_version = _latest_version(project) or (versions[0] if versions else None)

    if not target_version:
        return {
            "framework": {
                "id": framework.id,
                "machine_name": framework.machine_name,
                "display_name": framework.display_name,
            },
            "project": {
                "id": project.id,
                "display_name": project.display_name or project.machine_name,
            },
            "version": None,
            "nodes": [
                {
                    "id": f"project:{project.id}",
                    "label": project.display_name or project.machine_name,
                    "group": "project",
                    "level": 0,
                    "selected": True,
                }
            ],
            "links": [],
            "capability_tree": [],
        }

    selected_ids = {
        int(cid)
        for (cid,) in (
            db.query(ProjectVersionFrameworkNode.framework_node_id)
            .join(
                FrameworkNode,
                FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
            )
            .filter(
                ProjectVersionFrameworkNode.project_version_id == target_version.id,
                FrameworkNode.framework_id == framework.id,
            )
            .all()
        )
        if cid is not None
    }

    nodes = _fetch_capabilities(db, framework.id)
    selected_tree = _selected_capability_tree(nodes, selected_ids)

    graph_nodes = [
        {
            "id": f"project:{project.id}",
            "label": project.display_name or project.machine_name,
            "group": "project",
            "level": 0,
            "selected": True,
        },
        {
            "id": f"version:{target_version.id}",
            "label": target_version.version,
            "group": "version",
            "level": 1,
            "selected": True,
        },
    ]
    graph_links = [
        {
            "source": f"project:{project.id}",
            "target": f"version:{target_version.id}",
            "value": 1,
        }
    ]

    def add_tree_nodes(parent_graph_id: str, tree_nodes: list[dict]):
        for node in tree_nodes:
            graph_id = f"node:{node['id']}"
            graph_nodes.append(
                {
                    "id": graph_id,
                    "label": node["display_name"],
                    "group": "framework_node",
                    "level": int(node.get("level", 0)) + 2,
                    "selected": bool(node.get("selected", False)),
                }
            )
            graph_links.append(
                {"source": parent_graph_id, "target": graph_id, "value": 1}
            )
            add_tree_nodes(graph_id, node.get("children", []))

    add_tree_nodes(f"version:{target_version.id}", selected_tree)

    return {
        "framework": {
            "id": framework.id,
            "machine_name": framework.machine_name,
            "display_name": framework.display_name,
        },
        "project": {
            "id": project.id,
            "display_name": project.display_name or project.machine_name,
        },
        "version": _serialize_version(target_version),
        "nodes": graph_nodes,
        "links": graph_links,
        "capability_tree": selected_tree,
    }


def _manifest_dependencies_for_versions(
    db: Session,
    version_ids: list[int],
    *,
    include_vulnerabilities: bool = True,
) -> dict[int, list[dict[str, Any]]]:
    """Return dependency + vulnerability details per project version id.

    Output structure is designed to be embedded directly into manifest rows.
    Each dependency has a nested list of vulnerabilities (if requested).
    """

    if not version_ids:
        return {}

    cleaned = sorted({int(v) for v in version_ids if int(v) > 0})
    if not cleaned:
        return {}

    rows = (
        db.query(
            ProjectVersionDependency.project_version_id,
            DependencyPackage.ecosystem,
            DependencyPackage.name,
            DependencyPackage.normalized_name,
            DependencyVersion.version,
            DependencyVersion.id.label("dependency_version_id"),
            ProjectVersionDependency.is_indirect,
            ProjectVersionDependency.source_files,
            func.count(DependencyVulnerability.id).label("vuln_count"),
        )
        .join(
            DependencyVersion, DependencyVersion.dependency_id == DependencyPackage.id
        )
        .join(
            ProjectVersionDependency,
            ProjectVersionDependency.dependency_version_id == DependencyVersion.id,
        )
        .outerjoin(
            DependencyVulnerability,
            DependencyVulnerability.dependency_version_id == DependencyVersion.id,
        )
        .filter(ProjectVersionDependency.project_version_id.in_(cleaned))
        .group_by(
            ProjectVersionDependency.project_version_id,
            DependencyPackage.ecosystem,
            DependencyPackage.name,
            DependencyPackage.normalized_name,
            DependencyVersion.version,
            DependencyVersion.id,
            ProjectVersionDependency.is_indirect,
            ProjectVersionDependency.source_files,
        )
        .order_by(
            ProjectVersionDependency.project_version_id.asc(),
            DependencyPackage.ecosystem.asc(),
            DependencyPackage.normalized_name.asc(),
            DependencyVersion.version.asc(),
        )
        .all()
    )

    deps_by_version: dict[int, list[dict[str, Any]]] = defaultdict(list)

    # Index so we can attach vulnerabilities efficiently.
    dep_index: dict[tuple[int, int], dict[str, Any]] = {}

    for r in rows:
        pv_id = int(r.project_version_id)
        dep_ver_id = int(r.dependency_version_id)
        item = {
            "ecosystem": str(r.ecosystem or ""),
            "package": str(r.name or ""),
            "normalized_name": str(r.normalized_name or ""),
            "version": str(r.version or ""),
            "dependency_version_id": dep_ver_id,
            "is_indirect": bool(r.is_indirect),
            "source_files": list(r.source_files or []),
            "vulnerability_count": int(r.vuln_count or 0),
            "vulnerabilities": [],
        }
        deps_by_version[pv_id].append(item)
        dep_index[(pv_id, dep_ver_id)] = item

    if include_vulnerabilities and dep_index:
        vuln_rows = (
            db.query(
                ProjectVersionDependency.project_version_id,
                DependencyPackage.ecosystem,
                DependencyPackage.name,
                DependencyPackage.normalized_name,
                DependencyVersion.version,
                DependencyVersion.id.label("dependency_version_id"),
                DependencyVulnerability.scanner,
                DependencyVulnerability.vulnerability_id,
                DependencyVulnerability.severity,
                DependencyVulnerability.title,
                DependencyVulnerability.fixed_version,
                DependencyVulnerability.references,
                DependencyVulnerability.created_at,
            )
            .join(
                DependencyVersion,
                DependencyVersion.dependency_id == DependencyPackage.id,
            )
            .join(
                ProjectVersionDependency,
                ProjectVersionDependency.dependency_version_id == DependencyVersion.id,
            )
            .join(
                DependencyVulnerability,
                DependencyVulnerability.dependency_version_id == DependencyVersion.id,
            )
            .filter(ProjectVersionDependency.project_version_id.in_(cleaned))
            .order_by(
                ProjectVersionDependency.project_version_id.asc(),
                DependencyPackage.ecosystem.asc(),
                DependencyPackage.normalized_name.asc(),
                DependencyVulnerability.vulnerability_id.asc(),
            )
            .all()
        )

        for r in vuln_rows:
            pv_id = int(r.project_version_id)
            dep_ver_id = int(r.dependency_version_id)
            parent = dep_index.get((pv_id, dep_ver_id))
            if parent is None:
                continue
            parent["vulnerabilities"].append(
                {
                    "scanner": str(r.scanner or "legacy"),
                    "vulnerability_id": str(r.vulnerability_id or ""),
                    "severity": (str(r.severity).upper() if r.severity else None),
                    "title": r.title,
                    "fixed_version": r.fixed_version,
                    "references": list(r.references or []),
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
            )

        # Ensure counts reflect nested vulnerability arrays (and not just DB counts)
        for (_pv_id, _dep_id), dep in dep_index.items():
            dep["vulnerability_count"] = int(len(dep.get("vulnerabilities") or []))

    # Stable ordering within each project version
    for pv_id, arr in deps_by_version.items():
        deps_by_version[pv_id] = sorted(
            arr,
            key=lambda d: (
                str(d.get("ecosystem") or "").lower(),
                str(d.get("normalized_name") or d.get("package") or "").lower(),
                str(d.get("version") or "").lower(),
            ),
        )

    return deps_by_version


def _collect_manifest_rows(
    db: Session,
    *,
    framework: Framework,
    q: str | None,
    capability_ids: list[int],
    project_ids: list[int] | None = None,
    languages: list[str] | None = None,
    statuses: list[str] | None = None,
) -> list[dict]:
    query = _get_project_query(
        db,
        q=q,
        framework=framework,
        capability_ids=capability_ids,
        project_ids=project_ids,
        languages=languages,
        statuses=statuses,
    )
    projects = query.order_by(
        Project.display_name.asc(), Project.machine_name.asc()
    ).all()

    latest_versions: dict[int, ProjectVersion | None] = {
        c.id: _latest_version(c) for c in projects
    }
    version_ids = [v.id for v in latest_versions.values() if v]

    deps_by_version = _manifest_dependencies_for_versions(
        db, version_ids, include_vulnerabilities=True
    )

    nodes = _fetch_capabilities(db, framework.id)
    capability_paths = _capability_paths(nodes)

    capability_pairs_by_version: dict[int, list[tuple[int, str]]] = defaultdict(list)
    if version_ids:
        raw_rows = (
            db.query(
                ProjectVersionFrameworkNode.project_version_id,
                ProjectVersionFrameworkNode.framework_node_id,
            )
            .join(
                FrameworkNode,
                FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
            )
            .filter(
                ProjectVersionFrameworkNode.project_version_id.in_(version_ids),
                FrameworkNode.framework_id == framework.id,
            )
            .all()
        )
        for version_id, framework_node_id in raw_rows:
            path = capability_paths.get(framework_node_id)
            if not path:
                continue
            capability_pairs_by_version[int(version_id)].append(
                (int(framework_node_id), path)
            )

    for version_id, pairs in capability_pairs_by_version.items():
        dedup: dict[int, str] = {}
        for capability_id, path in pairs:
            dedup[capability_id] = path
        capability_pairs_by_version[version_id] = sorted(
            dedup.items(), key=lambda item: item[1].lower()
        )

    rows: list[dict] = []
    for comp in projects:
        latest = latest_versions.get(comp.id)
        capability_pairs = (
            capability_pairs_by_version.get(latest.id, []) if latest else []
        )
        deps = deps_by_version.get(latest.id, []) if latest else []
        dep_vuln_total = sum(int(d.get("vulnerability_count") or 0) for d in deps)

        rows.append(
            {
                "project_id": comp.id,
                "machine_name": comp.machine_name,
                "display_name": comp.display_name,
                "organisation": comp.organisation,
                "project_type": comp.project_type,
                "license": comp.license,
                "programming_languages": _clean_tag_list(
                    getattr(comp, "programming_languages", []) or []
                ),
                "latest_version_id": latest.id if latest else None,
                "latest_version": latest.version if latest else None,
                "latest_release_date": (
                    latest.release_date.isoformat()
                    if latest and latest.release_date
                    else None
                ),
                "capability_ids": [cid for cid, _ in capability_pairs],
                "capabilities": [path for _, path in capability_pairs],
                "capability_pairs": [
                    {
                        "capability_id": cid,
                        "capability_path": path,
                    }
                    for cid, path in capability_pairs
                ],
                "dependency_count": len(deps),
                "vulnerability_count": dep_vuln_total,
                "dependencies": deps,
                "supported_profiles": _clean_tag_list(comp.supported_profiles),
                "supported_formats": _clean_tag_list(comp.supported_formats),
                "link_to_app": comp.link_to_app,
                "created_at": comp.created_at.isoformat() if comp.created_at else None,
                "updated_at": comp.updated_at.isoformat() if comp.updated_at else None,
            }
        )

    return rows


def _manifest_rows_from_saved(db: Session, manifest: Manifest) -> list[dict]:
    rows: list[dict] = []
    version_ids = [
        int(item.project_version_id)  # type: ignore[arg-type]
        for item in (manifest.items or [])
        if getattr(item, "project_version_id", None)
    ]
    deps_by_version = _manifest_dependencies_for_versions(
        db, version_ids, include_vulnerabilities=True
    )
    for item in manifest.items or []:
        capability_pairs = [
            {
                "capability_id": cap.framework_node_id,
                "capability_path": cap.node_path,
            }
            for cap in (item.node_mappings or [])
            if cap.node_path
        ]
        capability_pairs.sort(key=lambda x: str(x["capability_path"]).lower())

        deps = (
            deps_by_version.get(int(item.project_version_id or 0), [])
            if getattr(item, "project_version_id", None)
            else []
        )
        dep_vuln_total = sum(int(d.get("vulnerability_count") or 0) for d in deps)

        rows.append(
            {
                "project_id": item.project_id,
                "machine_name": item.machine_name,
                "display_name": item.display_name,
                "organisation": item.organisation,
                "project_type": item.project_type,
                "license": item.license,
                "latest_version_id": item.project_version_id,
                "latest_version": item.latest_version,
                "latest_release_date": (
                    item.latest_release_date.isoformat()
                    if item.latest_release_date
                    else None
                ),
                "capability_ids": [
                    int(cp["capability_id"])  # type: ignore[arg-type]  # filtered to int above
                    for cp in capability_pairs
                    if cp.get("capability_id") is not None
                    and isinstance(cp.get("capability_id"), int)
                ],
                "capabilities": [str(cp["capability_path"]) for cp in capability_pairs],
                "capability_pairs": capability_pairs,
                "dependency_count": len(deps),
                "vulnerability_count": dep_vuln_total,
                "dependencies": deps,
                "supported_profiles": _clean_tag_list(item.supported_profiles),
                "supported_formats": _clean_tag_list(item.supported_formats),
                "link_to_app": item.link_to_app,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "updated_at": (
                    manifest.updated_at.isoformat() if manifest.updated_at else None
                ),
            }
        )
    return rows


def _manifest_json_payload(rows: list[dict]) -> dict[str, Any]:
    return {"items": rows}


def _manifest_markdown(rows: list[dict]) -> str:
    def esc(value: Any) -> str:
        # Escape table delimiter for Markdown table cells.
        # Use a raw string to avoid Python's "invalid escape sequence" warning.
        return str(value if value is not None else "").replace("|", r"\|")

    # Primary project table.
    lines = [
        "| Project | Organisation | Type | Version | Capability IDs | Dependency Count | Vulnerability Count |",
        "|---|---|---|---|---|---:|---:|",
    ]
    for row in rows:
        comp_name = (
            row.get("display_name")
            or row.get("machine_name")
            or f"Project {row.get('project_id', '?')}"
        )
        capability_id_list = (
            ", ".join(str(cid) for cid in row.get("capability_ids", [])) or "—"
        )
        cells = [
            comp_name,
            row.get("organisation") or "—",
            row.get("project_type") or "—",
            row.get("latest_version") or "—",
            capability_id_list,
            row.get("dependency_count") or 0,
            row.get("vulnerability_count") or 0,
        ]
        lines.append("| " + " | ".join(esc(c) for c in cells) + " |")

    # Capability matrix.
    project_labels = [
        (
            row.get("project_id"),
            row.get("display_name")
            or row.get("machine_name")
            or f"Project {row.get('project_id', '?')}",
        )
        for row in rows
        if row.get("project_id") is not None
    ]
    project_labels.sort(key=lambda item: str(item[1]).lower())
    project_ids_order = [cid for cid, _ in project_labels]
    project_name_by_id = {cid: name for cid, name in project_labels}

    capability_to_projects: dict[str, set[int]] = defaultdict(set)
    for row in rows:
        cid = row.get("project_id")
        if cid is None:
            continue
        for path in row.get("capabilities", []):
            capability_to_projects[str(path)].add(int(cid))

    lines.append("")
    lines.append("## Capability Matrix")
    if not project_ids_order or not capability_to_projects:
        lines.append("No capability mappings available.")
    else:
        header = ["Capability Path"] + [
            project_name_by_id[cid] for cid in project_ids_order
        ]
        lines.append("| " + " | ".join(esc(h) for h in header) + " |")
        lines.append("| " + " | ".join(["---"] * len(header)) + " |")

        for capability_path in sorted(
            capability_to_projects.keys(), key=lambda s: s.lower()
        ):
            marks = []
            members = capability_to_projects[capability_path]
            for comp_id in project_ids_order:
                marks.append("✅" if comp_id in members else "—")
            row_cells = [capability_path] + marks
            lines.append("| " + " | ".join(esc(cell) for cell in row_cells) + " |")

    # Dependencies + per-dependency vulnerability detail.
    lines.append("")
    lines.append("## Dependencies")

    any_deps = any((row.get("dependencies") or []) for row in rows)
    if not any_deps:
        lines.append("No dependency data available.")
        return "\n".join(lines)

    for row in rows:
        deps = row.get("dependencies") or []
        if not deps:
            continue

        proj_name = (
            row.get("display_name")
            or row.get("machine_name")
            or f"Project {row.get('project_id', '?')}"
        )
        ver = row.get("latest_version") or "—"
        lines.append("")
        lines.append(f"### {esc(proj_name)} — {esc(ver)}")

        lines.append(
            f"{int(row.get('dependency_count') or len(deps))} dependencies; {int(row.get('vulnerability_count') or 0)} vulnerabilities"
        )

        lines.append(
            "| Ecosystem | Package | Version | Indirect | Vulnerability ID | Severity | Title | Fixed Version | References |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|")

        for dep in deps:
            base = [
                dep.get("ecosystem") or "",
                dep.get("package") or "",
                dep.get("version") or "",
                "yes" if dep.get("is_indirect") else "no",
            ]
            vulns = dep.get("vulnerabilities") or []
            if vulns:
                for v in vulns:
                    refs = ", ".join(
                        str(r) for r in (v.get("references") or []) if str(r).strip()
                    )
                    cells = base + [
                        v.get("vulnerability_id") or "",
                        v.get("severity") or "",
                        v.get("title") or "",
                        v.get("fixed_version") or "",
                        refs or "",
                    ]
                    lines.append("| " + " | ".join(esc(c) for c in cells) + " |")
            else:
                cells = base + ["—", "—", "—", "—", "—"]
                lines.append("| " + " | ".join(esc(c) for c in cells) + " |")

    return "\n".join(lines)


def _manifest_xlsx(rows: list[dict]) -> bytes:
    wb = Workbook()
    ws_projects = wb.active
    ws_projects.title = "Projects"

    project_headers = [
        "project_id",
        "machine_name",
        "display_name",
        "organisation",
        "project_type",
        "license",
        "programming_languages",
        "latest_version",
        "latest_version_id",
        "latest_release_date",
        "capability_ids",
        "supported_profiles",
        "supported_formats",
        "link_to_app",
        "dependency_count",
        "vulnerability_count",
        "created_at",
        "updated_at",
    ]
    ws_projects.append(project_headers)

    for row in rows:
        ws_projects.append(
            [
                row.get("project_id"),
                row.get("machine_name") or "",
                row.get("display_name") or "",
                row.get("organisation") or "",
                row.get("project_type") or "",
                row.get("license") or "",
                "; ".join(row.get("programming_languages", []) or []),
                row.get("latest_version") or "",
                row.get("latest_version_id") or "",
                row.get("latest_release_date") or "",
                "; ".join(str(x) for x in row.get("capability_ids", [])),
                "; ".join(row.get("supported_profiles", []) or []),
                "; ".join(row.get("supported_formats", []) or []),
                row.get("link_to_app") or "",
                int(row.get("dependency_count") or 0),
                int(row.get("vulnerability_count") or 0),
                row.get("created_at") or "",
                row.get("updated_at") or "",
            ]
        )

    ws_map = wb.create_sheet("CapabilityMappings")
    map_headers = [
        "project_id",
        "project_name",
        "version_id",
        "capability_id",
        "capability_path",
    ]
    ws_map.append(map_headers)

    capability_lookup: dict[int, str] = {}
    for row in rows:
        project_id = row.get("project_id")
        project_name = row.get("display_name") or row.get("machine_name") or ""
        version_id = row.get("latest_version_id")
        for cp in row.get("capability_pairs", []) or []:
            capability_id = cp.get("capability_id")
            capability_path = cp.get("capability_path") or ""
            if capability_id:
                capability_lookup[int(capability_id)] = capability_path
            ws_map.append(
                [
                    project_id,
                    project_name,
                    version_id,
                    capability_id or "",
                    capability_path,
                ]
            )

    ws_caps = wb.create_sheet("Capabilities")
    ws_caps.append(["capability_id", "capability_path"])
    for capability_id in sorted(capability_lookup.keys()):
        ws_caps.append([capability_id, capability_lookup[capability_id]])

    ws_deps = wb.create_sheet("Dependencies")
    ws_deps.append(
        [
            "project_id",
            "project_name",
            "version_id",
            "ecosystem",
            "package",
            "normalized_name",
            "dependency_version",
            "is_indirect",
            "source_files",
            "vulnerability_count",
        ]
    )

    ws_vulns = wb.create_sheet("DependencyVulnerabilities")
    ws_vulns.append(
        [
            "project_id",
            "project_name",
            "version_id",
            "ecosystem",
            "package",
            "dependency_version",
            "dependency_version_id",
            "scanner",
            "vulnerability_id",
            "severity",
            "title",
            "fixed_version",
            "references",
            "created_at",
        ]
    )

    for row in rows:
        project_id = row.get("project_id")
        project_name = row.get("display_name") or row.get("machine_name") or ""
        version_id = row.get("latest_version_id")
        for dep in row.get("dependencies", []) or []:
            ws_deps.append(
                [
                    project_id,
                    project_name,
                    version_id,
                    dep.get("ecosystem") or "",
                    dep.get("package") or "",
                    dep.get("normalized_name") or "",
                    dep.get("version") or "",
                    bool(dep.get("is_indirect")),
                    "; ".join(str(x) for x in (dep.get("source_files") or [])),
                    int(dep.get("vulnerability_count") or 0),
                ]
            )

            for v in dep.get("vulnerabilities", []) or []:
                ws_vulns.append(
                    [
                        project_id,
                        project_name,
                        version_id,
                        dep.get("ecosystem") or "",
                        dep.get("package") or "",
                        dep.get("version") or "",
                        dep.get("dependency_version_id") or "",
                        v.get("scanner") or "",
                        v.get("vulnerability_id") or "",
                        v.get("severity") or "",
                        v.get("title") or "",
                        v.get("fixed_version") or "",
                        "; ".join(
                            str(r)
                            for r in (v.get("references") or [])
                            if str(r).strip()
                        ),
                        v.get("created_at") or "",
                    ]
                )

    # Spreadsheet/CSV formula injection hardening: escape leading =+-@
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                try:
                    v = cell.value
                    if isinstance(v, str):
                        cell.value = _excel_safe_cell(v)
                except Exception:
                    pass

    buffer = BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def _manifest_response(rows: list[dict], *, fmt: str, name: str) -> Response:
    safe_name = (name or "project-manifest").strip() or "project-manifest"
    safe_name = "".join(
        ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in safe_name
    )

    if fmt == "json":
        # Ensure datetimes (eg vulnerability created_at) are JSON-serialisable.
        body = json.dumps(jsonable_encoder(_manifest_json_payload(rows)), indent=2)
        headers = {"Content-Disposition": f'attachment; filename="{safe_name}.json"'}
        return Response(content=body, media_type="application/json", headers=headers)

    if fmt in {"xlsx", "spreadsheet"}:
        headers = {"Content-Disposition": f'attachment; filename="{safe_name}.xlsx"'}
        return Response(
            content=_manifest_xlsx(rows),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers=headers,
        )

    if fmt == "csv":
        # Backward-compatible fallback. Spreadsheet (xlsx) is preferred.
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["project_id", "machine_name", "display_name", "capabilities"])
        for row in rows:
            writer.writerow(
                [
                    row.get("project_id"),
                    _excel_safe_cell(row.get("machine_name") or ""),
                    _excel_safe_cell(row.get("display_name") or ""),
                    _excel_safe_cell("; ".join(row.get("capabilities", []))),
                ]
            )
        headers = {"Content-Disposition": f'attachment; filename="{safe_name}.csv"'}
        return Response(
            content=output.getvalue(), media_type="text/csv", headers=headers
        )

    if fmt == "markdown":
        body = _manifest_markdown(rows)
        headers = {"Content-Disposition": f'attachment; filename="{safe_name}.md"'}
        return Response(content=body, media_type="text/markdown", headers=headers)

    raise HTTPException(
        status_code=400,
        detail="format must be one of: json, xlsx, spreadsheet, csv, markdown",
    )


def _can_access_manifest(db: Session, user: User, manifest: Manifest) -> bool:
    """Return True if the user can VIEW/EXPORT the manifest."""
    effective_role = attach_effective_role(db, user)
    if effective_role == ROLE_ADMIN:
        return True

    if manifest.created_by_user_id == user.id:
        return True

    if bool(getattr(manifest, "is_public", False)):
        return True

    if manifest.owner_group_id is None:
        return False

    return manifest.owner_group_id in _user_group_ids(db, user.id)


def _can_manage_manifest(db: Session, user: User, manifest: Manifest) -> bool:
    """Return True if the user can edit/share/delete the manifest."""
    effective_role = attach_effective_role(db, user)
    if effective_role == ROLE_ADMIN:
        return True
    return manifest.created_by_user_id == user.id


def _ensure_manifest_manage(db: Session, user: User, manifest_id: int) -> Manifest:
    manifest = (
        db.query(Manifest)
        .options(
            selectinload(Manifest.items).selectinload(ManifestProject.node_mappings),
            selectinload(Manifest.owner_group),
            selectinload(Manifest.created_by_user),
            selectinload(Manifest.framework),
        )
        .filter(Manifest.id == manifest_id)
        .one_or_none()
    )
    if not manifest:
        raise HTTPException(status_code=404, detail="Manifest not found")
    if not _can_manage_manifest(db, user, manifest):
        raise HTTPException(
            status_code=403, detail="You do not have permission to modify this manifest"
        )
    return manifest


def _ensure_manifest_access(db: Session, user: User, manifest_id: int) -> Manifest:
    manifest = (
        db.query(Manifest)
        .options(
            selectinload(Manifest.items).selectinload(ManifestProject.node_mappings),
            selectinload(Manifest.owner_group),
            selectinload(Manifest.created_by_user),
            selectinload(Manifest.framework),
        )
        .filter(Manifest.id == manifest_id)
        .one_or_none()
    )
    if not manifest:
        raise HTTPException(status_code=404, detail="Manifest not found")
    if not _can_access_manifest(db, user, manifest):
        raise HTTPException(
            status_code=403, detail="You do not have access to this manifest"
        )
    return manifest


def _save_manifest_snapshot(
    db: Session,
    *,
    user: User,
    framework: Framework,
    name: str,
    description: str | None,
    q: str | None,
    capability_ids: list[int],
    project_ids: list[int],
    owner_group_id: int | None,
) -> Manifest:
    valid_owner_group_id: int | None = None
    user_groups = _user_group_ids(db, user.id)
    if owner_group_id is not None:
        if (
            owner_group_id not in user_groups
            and attach_effective_role(db, user) != ROLE_ADMIN
        ):
            raise HTTPException(
                status_code=403,
                detail="Cannot assign manifest to a group you are not part of",
            )
        group_exists = (
            db.query(Group.id).filter(Group.id == owner_group_id).one_or_none()
        )
        if not group_exists:
            raise HTTPException(status_code=400, detail="owner_group_id does not exist")
        valid_owner_group_id = owner_group_id

    rows = _collect_manifest_rows(
        db,
        framework=framework,
        q=q,
        capability_ids=capability_ids,
        project_ids=project_ids,
    )

    manifest = Manifest(
        name=(name or "").strip() or "project-manifest",
        description=(description or "").strip() or None,
        created_by_user_id=user.id,
        owner_group_id=valid_owner_group_id,
        framework_id=framework.id,
        filters_json={
            "q": (q or "").strip() or None,
            "framework_id": framework.id,
            "node_ids": capability_ids,
            "project_ids": project_ids,
        },
    )
    db.add(manifest)
    db.flush()

    for row in rows:
        item = ManifestProject(
            manifest_id=manifest.id,
            project_id=row.get("project_id"),
            project_version_id=row.get("latest_version_id"),
            machine_name=row.get("machine_name") or "",
            display_name=row.get("display_name") or row.get("machine_name") or "",
            organisation=row.get("organisation"),
            project_type=row.get("project_type"),
            license=row.get("license"),
            latest_version=row.get("latest_version"),
            latest_release_date=(
                datetime.fromisoformat(row["latest_release_date"])
                if row.get("latest_release_date")
                else None
            ),
            supported_profiles=row.get("supported_profiles") or [],
            supported_formats=row.get("supported_formats") or [],
            link_to_app=row.get("link_to_app"),
        )
        db.add(item)
        db.flush()

        for cp in row.get("capability_pairs", []):
            capability_id = cp.get("capability_id")
            db.add(
                ManifestProjectFrameworkNode(
                    manifest_project_id=item.id,
                    framework_node_id=int(capability_id) if capability_id else None,
                    node_path=str(cp.get("capability_path") or ""),
                )
            )

    db.commit()
    return _ensure_manifest_access(db, user, manifest.id)


@router.get(
    "/v1/projects/{project_id}/manifest/export",
    dependencies=[Depends(require_feature("manifests"))],
)
def export_project_manifest(
    project_id: int,
    format: str = Query(default="json"),
    fmt: str | None = Query(default=None),
    name: str = Query(default=None),
    framework_id: int | None = Query(default=None),
    version_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export a manifest for a single project (optionally for a specific version).

    This is used by the project details page to export manifests for the currently selected version.
    """

    _require_manifest_access(db, user)

    framework = _ensure_framework(db, framework_id)
    project = _ensure_project(db, project_id)

    can_view_drafts = _can_view_drafts(db, user, project)
    versions_all = _sort_versions(project.versions)
    versions = (
        versions_all
        if can_view_drafts
        else [v for v in versions_all if not bool(getattr(v, "is_draft", False))]
    )

    target_version: ProjectVersion | None = None
    if version_id is not None:
        any_match = next(
            (v for v in versions_all if int(v.id) == int(version_id)), None
        )
        if (
            any_match
            and bool(getattr(any_match, "is_draft", False))
            and not can_view_drafts
        ):
            raise HTTPException(
                status_code=403, detail="Draft version is not accessible"
            )
        target_version = next(
            (v for v in versions if int(v.id) == int(version_id)), None
        )
        if not target_version:
            raise HTTPException(status_code=404, detail="Version not found for project")
    else:
        target_version = _latest_version(project) or (versions[0] if versions else None)

    if not target_version:
        raise HTTPException(status_code=404, detail="Project has no versions")

    # Capability paths for this version within this framework.
    nodes = _fetch_capabilities(db, framework.id)
    capability_paths = _capability_paths(nodes)

    raw_rows = (
        db.query(ProjectVersionFrameworkNode.framework_node_id)
        .join(
            FrameworkNode,
            FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
        )
        .filter(ProjectVersionFrameworkNode.project_version_id == target_version.id)
        .filter(FrameworkNode.framework_id == framework.id)
        .all()
    )

    pairs: dict[int, str] = {}
    for (framework_node_id,) in raw_rows:
        path = capability_paths.get(framework_node_id)
        if not path:
            continue
        pairs[int(framework_node_id)] = path

    capability_pairs = sorted(pairs.items(), key=lambda item: item[1].lower())

    deps_by_version = _manifest_dependencies_for_versions(
        db, [int(target_version.id)], include_vulnerabilities=True
    )
    deps = deps_by_version.get(int(target_version.id), [])
    dep_vuln_total = sum(int(d.get("vulnerability_count") or 0) for d in deps)

    row = {
        "project_id": project.id,
        "machine_name": project.machine_name,
        "display_name": project.display_name,
        "organisation": project.organisation,
        "project_type": project.project_type,
        "license": project.license,
        "programming_languages": _clean_tag_list(
            getattr(project, "programming_languages", []) or []
        ),
        "latest_version_id": target_version.id,
        "latest_version": target_version.version,
        "latest_release_date": (
            target_version.release_date.isoformat()
            if target_version.release_date
            else None
        ),
        "capability_ids": [cid for cid, _ in capability_pairs],
        "capabilities": [path for _, path in capability_pairs],
        "capability_pairs": [
            {"capability_id": cid, "capability_path": path}
            for cid, path in capability_pairs
        ],
        "dependency_count": len(deps),
        "vulnerability_count": dep_vuln_total,
        "dependencies": deps,
        "supported_profiles": _clean_tag_list(project.supported_profiles),
        "supported_formats": _clean_tag_list(project.supported_formats),
        "link_to_app": project.link_to_app,
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "updated_at": project.updated_at.isoformat() if project.updated_at else None,
    }

    effective_format = (fmt or format or "json").strip().lower()
    default_name = f"{project.machine_name}-{target_version.version}".strip("-")
    export_name = (
        name or default_name or "project-manifest"
    ).strip() or "project-manifest"
    return _manifest_response([row], fmt=effective_format, name=export_name)


@router.post(
    "/v1/projects/{project_id}/manifest/save",
    dependencies=[Depends(require_feature("manifests"))],
)
def save_project_manifest(
    project_id: int,
    payload: ManifestCreatePayload,
    framework_id: int | None = Query(default=None),
    version_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Save a manifest snapshot for a single project/version.

    This powers the project details page "Save" action and stores the manifest
    so it appears under "Saved manifests".
    """

    _require_manifest_access(db, user)

    effective_framework_id = payload.framework_id or framework_id
    framework = _ensure_framework(db, effective_framework_id)
    project = _ensure_project(db, project_id)

    can_view_drafts = _can_view_drafts(db, user, project)
    versions_all = _sort_versions(project.versions)
    versions = (
        versions_all
        if can_view_drafts
        else [v for v in versions_all if not bool(getattr(v, "is_draft", False))]
    )

    target_version: ProjectVersion | None = None
    if version_id is not None:
        any_match = next(
            (v for v in versions_all if int(v.id) == int(version_id)), None
        )
        if (
            any_match
            and bool(getattr(any_match, "is_draft", False))
            and not can_view_drafts
        ):
            raise HTTPException(
                status_code=403, detail="Draft version is not accessible"
            )
        target_version = next(
            (v for v in versions if int(v.id) == int(version_id)), None
        )
        if not target_version:
            raise HTTPException(status_code=404, detail="Version not found for project")
    else:
        target_version = _latest_version(project) or (versions[0] if versions else None)

    if not target_version:
        raise HTTPException(status_code=404, detail="Project has no versions")

    # Capability paths for this version within this framework.
    nodes = _fetch_capabilities(db, framework.id)
    capability_paths = _capability_paths(nodes)

    raw_rows = (
        db.query(ProjectVersionFrameworkNode.framework_node_id)
        .join(
            FrameworkNode,
            FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
        )
        .filter(ProjectVersionFrameworkNode.project_version_id == target_version.id)
        .filter(FrameworkNode.framework_id == framework.id)
        .all()
    )

    pairs: dict[int, str] = {}
    for (framework_node_id,) in raw_rows:
        path = capability_paths.get(framework_node_id)
        if not path:
            continue
        pairs[int(framework_node_id)] = path

    capability_pairs = sorted(pairs.items(), key=lambda item: item[1].lower())

    # Owner group handling (same rules as /v1/manifests)
    valid_owner_group_id: int | None = None
    user_groups = _user_group_ids(db, user.id)
    if payload.owner_group_id is not None:
        if (
            payload.owner_group_id not in user_groups
            and attach_effective_role(db, user) != ROLE_ADMIN
        ):
            raise HTTPException(
                status_code=403,
                detail="Cannot assign manifest to a group you are not part of",
            )
        group_exists = (
            db.query(Group.id).filter(Group.id == payload.owner_group_id).one_or_none()
        )
        if not group_exists:
            raise HTTPException(status_code=400, detail="owner_group_id does not exist")
        valid_owner_group_id = int(payload.owner_group_id)

    default_name = f"{project.machine_name}-{target_version.version}".strip("-")
    manifest = Manifest(
        name=(payload.name or default_name or "project-manifest").strip()
        or "project-manifest",
        description=(payload.description or "").strip() or None,
        created_by_user_id=user.id,
        owner_group_id=valid_owner_group_id,
        framework_id=framework.id,
        filters_json={
            "framework_id": framework.id,
            "project_ids": [int(project.id)],
            "project_version_ids": [int(target_version.id)],
        },
    )
    db.add(manifest)
    db.flush()

    item = ManifestProject(
        manifest_id=manifest.id,
        project_id=project.id,
        project_version_id=target_version.id,
        machine_name=project.machine_name,
        display_name=project.display_name or project.machine_name or "",
        organisation=project.organisation,
        project_type=project.project_type,
        license=project.license,
        latest_version=target_version.version,
        latest_release_date=target_version.release_date,
        supported_profiles=_clean_tag_list(project.supported_profiles),
        supported_formats=_clean_tag_list(project.supported_formats),
        link_to_app=project.link_to_app,
    )
    db.add(item)
    db.flush()

    for capability_id, capability_path in capability_pairs:
        db.add(
            ManifestProjectFrameworkNode(
                manifest_project_id=item.id,
                framework_node_id=int(capability_id) if capability_id else None,
                node_path=str(capability_path or ""),
            )
        )

    db.commit()
    manifest = _ensure_manifest_access(db, user, manifest.id)

    return {
        "id": manifest.id,
        "name": manifest.name,
        "description": manifest.description,
        "created_at": manifest.created_at,
        "updated_at": manifest.updated_at,
        "framework_id": manifest.framework_id,
        "owner_group_id": manifest.owner_group_id,
        "item_count": len(manifest.items or []),
    }


@router.get(
    "/v1/manifests/export", dependencies=[Depends(require_feature("manifests"))]
)
def export_manifest(
    format: str = Query(default="json"),
    fmt: str | None = Query(default=None),
    name: str = Query(default="project-manifest"),
    q: str | None = Query(default=None),
    framework_id: int | None = Query(default=None),
    node_ids: str | None = Query(default=None),
    capability_ids: str | None = Query(default=None),
    project_ids: str | None = Query(default=None),
    languages: str | None = Query(default=None),
    programming_languages: str | None = Query(default=None),
    statuses: str | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)

    framework = _ensure_framework(db, framework_id)
    selected_capability_ids = _normalize_csv_ints(node_ids or capability_ids)
    selected_project_ids = _normalize_csv_ints(project_ids)
    selected_langs = _clean_tag_list(languages or programming_languages)
    selected_statuses = _clean_tag_list(statuses)

    selected_capability_ids = _ensure_node_ids(
        db, framework.id, selected_capability_ids
    )

    effective_format = (fmt or format or "json").strip().lower()
    rows = _collect_manifest_rows(
        db,
        framework=framework,
        q=q,
        capability_ids=selected_capability_ids,
        project_ids=selected_project_ids,
        languages=selected_langs,
        statuses=selected_statuses,
    )
    return _manifest_response(rows, fmt=effective_format, name=name)


@router.post("/v1/manifests", dependencies=[Depends(require_feature("manifests"))])
def save_manifest(
    payload: ManifestCreatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)

    framework = _ensure_framework(db, payload.framework_id)
    capability_ids = _ensure_node_ids(db, framework.id, payload.node_ids)
    project_ids = sorted({int(x) for x in payload.project_ids if int(x) > 0})

    manifest = _save_manifest_snapshot(
        db,
        user=user,
        framework=framework,
        name=payload.name,
        description=payload.description,
        q=payload.q,
        capability_ids=capability_ids,
        project_ids=project_ids,
        owner_group_id=payload.owner_group_id,
    )

    return {
        "id": manifest.id,
        "name": manifest.name,
        "description": manifest.description,
        "created_at": manifest.created_at,
        "updated_at": manifest.updated_at,
        "framework_id": manifest.framework_id,
        "owner_group_id": manifest.owner_group_id,
        "item_count": len(manifest.items or []),
    }


@router.get("/v1/manifests", dependencies=[Depends(require_feature("manifests"))])
def list_manifests(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)

    effective_role = attach_effective_role(db, user)
    query = db.query(Manifest).options(
        selectinload(Manifest.items),
        selectinload(Manifest.owner_group),
        selectinload(Manifest.created_by_user),
        selectinload(Manifest.framework),
    )

    if effective_role != ROLE_ADMIN:
        user_groups = _user_group_ids(db, user.id)
        conditions = [
            Manifest.created_by_user_id == user.id,
            Manifest.is_public.is_(True),
        ]
        if user_groups:
            conditions.append(Manifest.owner_group_id.in_(user_groups))
        query = query.filter(or_(*conditions))

    manifests = query.order_by(
        Manifest.updated_at.desc(), Manifest.created_at.desc()
    ).all()

    return {
        "items": [
            {
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "created_at": m.created_at,
                "updated_at": m.updated_at,
                "created_by_user_id": m.created_by_user_id,
                "created_by_username": (
                    m.created_by_user.username if m.created_by_user else None
                ),
                "framework_id": m.framework_id,
                "framework_machine_name": (
                    m.framework.machine_name if m.framework else None
                ),
                "framework_display_name": (
                    m.framework.display_name if m.framework else None
                ),
                "owner_group_id": m.owner_group_id,
                "owner_group_name": m.owner_group.name if m.owner_group else None,
                "item_count": len(m.items or []),
                "is_public": bool(getattr(m, "is_public", False)),
                "filters_json": m.filters_json or {},
                "node_count": len((m.filters_json or {}).get("node_ids") or []),
                "project_count": len((m.filters_json or {}).get("project_ids") or []),
                "can_manage": _can_manage_manifest(db, user, m),
                "can_delete": _can_manage_manifest(db, user, m),
                "can_clone": (not _can_manage_manifest(db, user, m))
                and _can_access_manifest(db, user, m),
            }
            for m in manifests
        ]
    }


@router.get(
    "/v1/manifests/{manifest_id}", dependencies=[Depends(require_feature("manifests"))]
)
def get_manifest(
    manifest_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)
    manifest = _ensure_manifest_manage(db, user, manifest_id)

    rows = _manifest_rows_from_saved(db, manifest)
    return {
        "id": manifest.id,
        "name": manifest.name,
        "description": manifest.description,
        "created_at": manifest.created_at,
        "updated_at": manifest.updated_at,
        "created_by_user_id": manifest.created_by_user_id,
        "created_by_username": (
            manifest.created_by_user.username if manifest.created_by_user else None
        ),
        "framework_id": manifest.framework_id,
        "framework_machine_name": (
            manifest.framework.machine_name if manifest.framework else None
        ),
        "framework_display_name": (
            manifest.framework.display_name if manifest.framework else None
        ),
        "owner_group_id": manifest.owner_group_id,
        "owner_group_name": manifest.owner_group.name if manifest.owner_group else None,
        "is_public": bool(getattr(manifest, "is_public", False)),
        # Back-compat: expose filters in both keys.
        "filters_json": manifest.filters_json or {},
        "filters": manifest.filters_json or {},
        "can_manage": _can_manage_manifest(db, user, manifest),
        "can_delete": _can_manage_manifest(db, user, manifest),
        "can_clone": (not _can_manage_manifest(db, user, manifest))
        and _can_access_manifest(db, user, manifest),
        "items": rows,
    }


@router.delete(
    "/v1/manifests/{manifest_id}", dependencies=[Depends(require_feature("manifests"))]
)
def delete_manifest(
    manifest_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)
    manifest = _ensure_manifest_manage(db, user, manifest_id)
    db.delete(manifest)
    db.commit()
    return Response(status_code=204)


@router.get(
    "/v1/manifests/{manifest_id}/export",
    dependencies=[Depends(require_feature("manifests"))],
)
def export_saved_manifest(
    manifest_id: int,
    format: str = Query(default="json"),
    fmt: str | None = Query(default=None),
    name: str | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)
    manifest = _ensure_manifest_access(db, user, manifest_id)
    rows = _manifest_rows_from_saved(db, manifest)
    export_name = name or manifest.name or f"manifest-{manifest.id}"
    effective_format = (fmt or format or "json").strip().lower()
    return _manifest_response(rows, fmt=effective_format, name=export_name)


def _notify_group_manifest_shared(
    db: Session,
    *,
    shared_by: User,
    manifest: Manifest,
    group_id: int,
) -> None:
    # Only notify active users in the group who can access manifests.
    group = db.query(Group).filter(Group.id == group_id).one_or_none()
    group_name = group.name if group else None

    user_ids = [
        int(uid)
        for (uid,) in db.query(UserGroup.user_id)
        .filter(UserGroup.group_id == group_id)
        .all()
        if uid is not None
    ]
    if not user_ids:
        return

    users = (
        db.query(User)
        .filter(User.id.in_(user_ids))
        .filter(User.is_active.is_(True))
        .all()
    )

    # Build link (optional)
    base = (getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
    url = f"{base}/manifests.html?id={manifest.id}" if base else None

    sent = 0
    for u in users:
        if u.id == shared_by.id:
            continue
        if not has_permission(db, u, PERM_MANIFEST_EXPORT):
            continue
        email = notification_email_for_user(db, user=u)
        if not email:
            continue
        try:
            send_manifest_shared_email(
                db=db,
                user_id=u.id,
                to_email=email,
                manifest_name=manifest.name or f"manifest-{manifest.id}",
                shared_by_username=shared_by.username,
                group_name=group_name,
                manifest_url=url,
            )
            sent += 1
        except Exception:
            logger.exception("Failed to send manifest shared email to %s", email)

    if sent:
        logger.info(
            "Sent %s manifest share notifications for manifest_id=%s", sent, manifest.id
        )


@router.patch(
    "/v1/manifests/{manifest_id}/sharing",
    dependencies=[Depends(require_feature("manifests"))],
)
def update_manifest_sharing(
    manifest_id: int,
    payload: ManifestSharingUpdatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)
    manifest = _ensure_manifest_manage(db, user, manifest_id)

    old_group_id = manifest.owner_group_id
    old_is_public: bool = bool(getattr(manifest, "is_public", False))  # noqa: F841 - kept for the changelog summary below

    fields_set: set[str] = set(getattr(payload, "model_fields_set", set()))

    # Group sharing (owner_group_id)
    if "owner_group_id" in fields_set:
        new_group_id = payload.owner_group_id
        if new_group_id is not None:
            # Only allow sharing to groups the user is a member of (unless admin).
            user_groups = _user_group_ids(db, user.id)
            if (
                int(new_group_id) not in user_groups
                and attach_effective_role(db, user) != ROLE_ADMIN
            ):
                raise HTTPException(
                    status_code=403,
                    detail="Cannot share with a group you are not part of",
                )
            exists = (
                db.query(Group.id).filter(Group.id == int(new_group_id)).one_or_none()
            )
            if not exists:
                raise HTTPException(
                    status_code=400, detail="owner_group_id does not exist"
                )
            manifest.owner_group_id = int(new_group_id)
        else:
            manifest.owner_group_id = None

    # Public flag
    if "is_public" in fields_set and payload.is_public is not None:
        manifest.is_public = bool(payload.is_public)

    db.commit()
    db.refresh(manifest)

    # Notify group if newly shared (or changed group)
    new_group_id = manifest.owner_group_id
    if new_group_id is not None and new_group_id != old_group_id:
        _notify_group_manifest_shared(
            db, shared_by=user, manifest=manifest, group_id=int(new_group_id)
        )

    return {
        "id": manifest.id,
        "name": manifest.name,
        "description": manifest.description,
        "created_at": manifest.created_at,
        "updated_at": manifest.updated_at,
        "created_by_user_id": manifest.created_by_user_id,
        "created_by_username": (
            manifest.created_by_user.username if manifest.created_by_user else None
        ),
        "framework_id": manifest.framework_id,
        "owner_group_id": manifest.owner_group_id,
        "owner_group_name": manifest.owner_group.name if manifest.owner_group else None,
        "is_public": bool(getattr(manifest, "is_public", False)),
        "can_manage": _can_manage_manifest(db, user, manifest),
    }


@router.post(
    "/v1/manifests/{manifest_id}/clone",
    dependencies=[Depends(require_feature("manifests"))],
)
def clone_manifest(
    manifest_id: int,
    payload: ManifestClonePayload | None = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_manifest_access(db, user)
    src = _ensure_manifest_access(db, user, manifest_id)

    # Clone to private manifest owned by the current user.
    name_override = (payload.name if payload else None) if payload else None
    desc_override = payload.description if payload else None

    base_name = (name_override or src.name or f"manifest-{src.id}").strip()
    if not base_name:
        base_name = f"manifest-{src.id}"

    new_name = base_name
    if not name_override:
        new_name = f"{base_name} (copy)"
    new_name = new_name[:200]

    new_manifest = Manifest(
        name=new_name,
        description=(desc_override if desc_override is not None else src.description),
        created_by_user_id=user.id,
        owner_group_id=None,
        framework_id=src.framework_id,
        is_public=False,
        filters_json=dict(src.filters_json or {}),
    )
    db.add(new_manifest)
    db.flush()

    for item in src.items or []:
        cloned_item = ManifestProject(
            manifest_id=new_manifest.id,
            project_id=item.project_id,
            project_version_id=item.project_version_id,
            machine_name=item.machine_name,
            display_name=item.display_name,
            organisation=item.organisation,
            project_type=item.project_type,
            license=item.license,
            latest_version=item.latest_version,
            latest_release_date=item.latest_release_date,
            supported_profiles=list(item.supported_profiles or []),
            supported_formats=list(item.supported_formats or []),
            link_to_app=item.link_to_app,
        )
        db.add(cloned_item)
        db.flush()

        for nm in item.node_mappings or []:
            db.add(
                ManifestProjectFrameworkNode(
                    manifest_project_id=cloned_item.id,
                    framework_node_id=nm.framework_node_id,
                    node_path=nm.node_path or "",
                )
            )

    db.commit()

    return {
        "id": new_manifest.id,
        "name": new_manifest.name,
        "description": new_manifest.description,
        "created_at": new_manifest.created_at,
        "updated_at": new_manifest.updated_at,
        "framework_id": new_manifest.framework_id,
    }
