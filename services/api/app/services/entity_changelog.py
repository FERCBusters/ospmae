from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from app.db.models import (
    EntityChangelog,
    FrameworkNode,
    Project,
    ProjectOwnerGroup,
    ProjectVersion,
    ProjectVersionFrameworkNode,
    User,
)

_CHANGE_FIELD_LABELS = {
    "capability": "Capability",
    "capability_nodes": "Framework mappings",
    "organisation": "Organisation",
    "dependency_count": "Dependency count",
    "display_name": "Display name",
    "is_draft": "Draft status",
    "is_latest": "Latest version",
    "license": "License",
    "link_to_app": "Homepage / app URL",
    "link_to_source_code": "Source code URL",
    "machine_name": "Machine name",
    "notes": "Notes",
    "owner_group_ids": "Owner groups",
    "programming_languages": "Programming languages",
    "project_type": "Project type",
    "release_date": "Release date",
    "release_rss_feed_url": "Release RSS feed",
    "release_rss_ignore_patterns": "Release feed ignore patterns",
    "track_branch": "Tracks a branch",
    "tracked_repo_url": "Tracked repository",
    "tracked_branch": "Tracked branch",
    "branch_poll_interval_hours": "Branch re-scan interval (hours)",
    "repo_private": "Private repository",
    "repo_token_host": "Access token host",
    "repo_token_username": "Access token account",
    "repo_token_updated_at": "Access token saved",
    "status": "Status",
    "supported_formats": "Supported formats",
    "supported_issuance_protocols": "Issuance protocols",
    "supported_key_managements": "Key management",
    "supported_presentation_protocols": "Presentation protocols",
    "supported_profiles": "Supported profiles",
    "supported_signing_algorithms": "Signing algorithms",
    "version": "Version",
    "vulnerability_count": "Vulnerability count",
}

_ENTITY_LABELS = {
    "project": "Project",
    "project_version": "Project version",
    "organisation": "Organisation",
}


def _clean_scalar(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {
            str(k): _clean_scalar(v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, (list, tuple, set)):
        return [_clean_scalar(v) for v in value]
    return value


def _norm(value: Any) -> Any:
    value = _clean_scalar(value)
    if isinstance(value, list):
        if all(isinstance(x, dict) for x in value):
            return sorted(
                value,
                key=lambda x: (
                    str(
                        x.get("path")
                        or x.get("display_name")
                        or x.get("key")
                        or x.get("id")
                        or ""
                    ),
                    str(x.get("framework") or ""),
                ),
            )
        return value
    if value == "":
        return None
    return value


def _field_label(field: str) -> str:
    return _CHANGE_FIELD_LABELS.get(field, field.replace("_", " ").title())


def _truncate_db_text(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) <= max_len:
        return text
    if max_len <= 1:
        return text[:max_len]
    return text[: max_len - 1].rstrip() + "…"


def diff_states(
    before: dict[str, Any] | None, after: dict[str, Any] | None
) -> list[dict[str, Any]]:
    before = before or {}
    after = after or {}
    skip = {"id", "display", "created_at", "updated_at"}
    fields = sorted((set(before.keys()) | set(after.keys())) - skip)
    changes: list[dict[str, Any]] = []
    for field in fields:
        old = _norm(before.get(field))
        new = _norm(after.get(field))
        if old == new:
            continue
        changes.append(
            {
                "field": field,
                "label": _field_label(field),
                "before": old,
                "after": new,
            }
        )
    return changes


def _entity_display(
    entity_type: str, state: dict[str, Any] | None
) -> tuple[str | None, str | None]:
    state = state or {}
    if entity_type == "project_version":
        ref = state.get("version")
        title = state.get("display") or state.get("version")
    else:
        ref = state.get("machine_name") or state.get("display_name")
        title = state.get("display_name") or state.get("machine_name")
    return (_truncate_db_text(ref, 160), _truncate_db_text(title, 512))


def _summarise(entity_type: str, action: str, changes: list[dict[str, Any]]) -> str:
    label = _ENTITY_LABELS.get(entity_type, entity_type.replace("_", " ").title())
    if action == "created":
        return f"{label} created"
    if action == "deleted":
        return f"{label} deleted"
    if not changes:
        return f"{label} saved with no semantic changes"
    names = [str(c.get("label") or c.get("field")) for c in changes[:4]]
    suffix = "" if len(changes) <= 4 else f" and {len(changes) - 4} more"
    return f"Updated {', '.join(names)}{suffix}"


def record_entity_changelog(
    db: Session,
    *,
    entity_type: str,
    entity_id: int,
    action: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    user: User | None = None,
    request_method: str | None = None,
    request_path: str | None = None,
) -> EntityChangelog | None:
    entity_type = str(entity_type or "").strip().lower()
    if entity_type not in _ENTITY_LABELS:
        raise ValueError(f"Unsupported changelog entity_type: {entity_type}")

    clean_before = _clean_scalar(before) if before is not None else None
    clean_after = _clean_scalar(after) if after is not None else None
    if action == "updated":
        changes = diff_states(clean_before, clean_after)
        if not changes:
            return None
    elif action == "created":
        changes = diff_states(None, clean_after)
    elif action == "deleted":
        changes = diff_states(clean_before, None)
    else:
        changes = diff_states(clean_before, clean_after)
        if not changes:
            return None

    display_state = clean_after or clean_before or {}
    entity_ref, entity_title = _entity_display(entity_type, display_state)
    entry = EntityChangelog(
        entity_type=entity_type,
        entity_id=int(entity_id),
        entity_ref=entity_ref,
        entity_title=entity_title,
        action=action,
        summary=_summarise(entity_type, action, changes),
        before_state=clean_before,
        after_state=clean_after,
        changes=changes,
        changed_by_user_id=getattr(user, "id", None),
        changed_by_username=getattr(user, "username", None),
        request_method=request_method or None,
        request_path=request_path or None,
        changed_at=datetime.utcnow(),
    )
    db.add(entry)
    db.flush()
    return entry


def _owner_group_ids(db: Session, project_id: int) -> list[int]:
    return [
        int(gid)
        for (gid,) in (
            db.query(ProjectOwnerGroup.group_id)
            .filter(ProjectOwnerGroup.project_id == int(project_id))
            .order_by(ProjectOwnerGroup.group_id.asc())
            .all()
        )
        if gid is not None
    ]


def project_changelog_state(
    db: Session, project_or_id: Project | int
) -> dict[str, Any] | None:
    project: Project | None
    if isinstance(project_or_id, Project):
        project = project_or_id
    else:
        project_id = int(project_or_id)
        project = db.query(Project).filter(Project.id == project_id).one_or_none()
    if project is None:
        return None
    return {
        "id": int(project.id),
        "machine_name": project.machine_name,
        "display_name": project.display_name,
        "organisation": project.organisation,
        "project_type": project.project_type,
        "license": project.license,
        "programming_languages": list(project.programming_languages or []),
        "capability": project.capability,
        "link_to_app": project.link_to_app,
        "release_rss_feed_url": project.release_rss_feed_url,
        "release_rss_ignore_patterns": list(
            getattr(project, "release_rss_ignore_patterns", None) or []
        ),
        "track_branch": project.track_branch,
        "tracked_repo_url": project.tracked_repo_url,
        "tracked_branch": project.tracked_branch,
        "branch_poll_interval_hours": project.branch_poll_interval_hours,
        # The token itself is never recorded; when it was saved is.
        "repo_private": bool(project.repo_private),
        "repo_token_host": project.repo_token_host,
        "repo_token_username": project.repo_token_username,
        "repo_token_updated_at": (
            project.repo_token_updated_at.isoformat()
            if project.repo_token_updated_at
            else None
        ),
        "supported_profiles": list(project.supported_profiles or []),
        "supported_formats": list(project.supported_formats or []),
        "supported_issuance_protocols": list(
            project.supported_issuance_protocols or []
        ),
        "supported_key_managements": list(project.supported_key_managements or []),
        "supported_presentation_protocols": list(
            project.supported_presentation_protocols or []
        ),
        "supported_signing_algorithms": list(
            project.supported_signing_algorithms or []
        ),
        "owner_group_ids": _owner_group_ids(db, project.id),
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "updated_at": project.updated_at.isoformat() if project.updated_at else None,
    }


def _version_framework_nodes(db: Session, version_id: int) -> list[dict[str, Any]]:
    rows = (
        db.query(FrameworkNode)
        .join(
            ProjectVersionFrameworkNode,
            ProjectVersionFrameworkNode.framework_node_id == FrameworkNode.id,
        )
        .filter(ProjectVersionFrameworkNode.project_version_id == int(version_id))
        .order_by(
            FrameworkNode.framework_id.asc(),
            FrameworkNode.level.asc(),
            FrameworkNode.sort_order.asc(),
            FrameworkNode.display_name.asc(),
        )
        .all()
    )
    out: list[dict[str, Any]] = []
    for node in rows:
        fw = node.framework
        out.append(
            {
                "id": int(node.id),
                "framework": getattr(fw, "machine_name", None),
                "key": node.key,
                "display_name": node.display_name,
            }
        )
    return out


def project_version_changelog_state(
    db: Session, version_or_id: ProjectVersion | int
) -> dict[str, Any] | None:
    version: ProjectVersion | None
    if isinstance(version_or_id, ProjectVersion):
        version = version_or_id
    else:
        version_id = int(version_or_id)
        version = (
            db.query(ProjectVersion)
            .filter(ProjectVersion.id == version_id)
            .one_or_none()
        )
    if version is None:
        return None
    project = version.project
    return {
        "id": int(version.id),
        "project_id": int(version.project_id),
        "display": f"{project.display_name if project else 'Project'} {version.version}".strip(),
        "version": version.version,
        "release_date": (
            version.release_date.isoformat() if version.release_date else None
        ),
        "status": version.status,
        "is_draft": bool(getattr(version, "is_draft", False)),
        "is_latest": bool(getattr(version, "is_latest", False)),
        "link_to_source_code": version.link_to_source_code,
        "notes": version.notes,
        "dependency_count": int(getattr(version, "dependency_count", 0) or 0),
        "vulnerability_count": int(getattr(version, "vulnerability_count", 0) or 0),
        "capability_nodes": _version_framework_nodes(db, version.id),
        "created_at": version.created_at.isoformat() if version.created_at else None,
        "updated_at": version.updated_at.isoformat() if version.updated_at else None,
    }


def _serialise_changelog(row: EntityChangelog) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "entity_ref": row.entity_ref,
        "entity_title": row.entity_title,
        "action": row.action,
        "summary": row.summary,
        "before_state": row.before_state,
        "after_state": row.after_state,
        "changes": row.changes or [],
        "changed_by_user_id": row.changed_by_user_id,
        "changed_by_username": row.changed_by_username,
        "changed_at": row.changed_at.isoformat() if row.changed_at else None,
        "request_method": row.request_method,
        "request_path": row.request_path,
    }


def list_entity_changelogs(
    db: Session,
    *,
    entity_type: str | None = None,
    entity_id: int | None = None,
    username: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))

    qry = db.query(EntityChangelog)
    if entity_type:
        qry = qry.filter(EntityChangelog.entity_type == entity_type.strip().lower())
    if entity_id is not None:
        qry = qry.filter(EntityChangelog.entity_id == int(entity_id))
    if username:
        qry = qry.filter(
            EntityChangelog.changed_by_username.icontains(
                username.strip(), autoescape=True
            )
        )
    if q:
        needle = q.strip()
        qry = qry.filter(
            or_(
                EntityChangelog.entity_ref.icontains(needle, autoescape=True),
                EntityChangelog.entity_title.icontains(needle, autoescape=True),
                EntityChangelog.summary.icontains(needle, autoescape=True),
                EntityChangelog.changed_by_username.icontains(needle, autoescape=True),
            )
        )

    total = qry.order_by(None).count()
    rows = (
        qry.order_by(desc(EntityChangelog.changed_at)).limit(limit).offset(offset).all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_serialise_changelog(row) for row in rows],
    }
