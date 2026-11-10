from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import (
    DependencyPackage,
    DependencyVersion,
    DependencyVulnerability,
    Framework,
    FrameworkNode,
    Project,
    ProjectOwnerGroup,
    ProjectVersion,
    ProjectVersionDependency,
    ProjectVersionFrameworkNode,
    User,
    UserGroup,
)
from app.db.session import get_db
from app.security.auth import get_current_user
from app.security.roles import ROLE_ADMIN, attach_effective_role

router = APIRouter()


def _is_admin(db: Session, user: User) -> bool:
    return (attach_effective_role(db, user) or "").lower() == ROLE_ADMIN


def _require_admin(db: Session, user: User) -> None:
    if not _is_admin(db, user):
        raise HTTPException(status_code=403, detail="Admin role required")


def _can_view_drafts_for_project(db: Session, user: User, project_id: int) -> bool:
    """Drafts are visible to admins and each project's owners (user or group)."""

    attach_effective_role(db, user)
    owner = db.query(Project).filter(Project.id == project_id).one_or_none()
    if owner and owner.created_by_user_id == user.id:
        return True

    user_groups = {
        int(gid)
        for (gid,) in db.query(UserGroup.group_id)
        .filter(UserGroup.user_id == user.id)
        .all()
        if gid is not None
    }
    if not user_groups:
        return False
    owner_groups = {
        int(gid)
        for (gid,) in db.query(ProjectOwnerGroup.group_id)
        .filter(ProjectOwnerGroup.project_id == project_id)
        .all()
        if gid is not None
    }
    return bool(user_groups & owner_groups)


def _require_admin_or_project_owner(db: Session, user: User, project: Project) -> None:
    if _is_admin(db, user):
        return
    if project.created_by_user_id and int(project.created_by_user_id) == int(user.id):
        return

    user_groups = {
        int(gid)
        for (gid,) in db.query(UserGroup.group_id)
        .filter(UserGroup.user_id == user.id)
        .all()
        if gid is not None
    }
    owner_groups = {
        int(gid)
        for (gid,) in db.query(ProjectOwnerGroup.group_id)
        .filter(ProjectOwnerGroup.project_id == project.id)
        .all()
        if gid is not None
    }
    if user_groups and owner_groups and user_groups.intersection(owner_groups):
        return

    raise HTTPException(status_code=403, detail="Project owner or admin role required")


def _version_or_404(
    db: Session, project: Project, user: User, version_id: int | None
) -> ProjectVersion:
    def can_view_drafts() -> bool:
        eff = attach_effective_role(db, user)
        if eff == ROLE_ADMIN:
            return True
        if project.created_by_user_id == user.id:
            return True
        user_groups = {
            int(gid)
            for (gid,) in db.query(UserGroup.group_id)
            .filter(UserGroup.user_id == user.id)
            .all()
            if gid is not None
        }
        owner_groups = {
            int(gid)
            for (gid,) in db.query(ProjectOwnerGroup.group_id)
            .filter(ProjectOwnerGroup.project_id == project.id)
            .all()
            if gid is not None
        }
        return bool(
            user_groups and owner_groups and user_groups.intersection(owner_groups)
        )

    if version_id is not None:
        pv = (
            db.query(ProjectVersion)
            .filter(ProjectVersion.id == version_id)
            .filter(ProjectVersion.project_id == project.id)
            .one_or_none()
        )
        if not pv:
            raise HTTPException(status_code=404, detail="Project version not found")
        if bool(getattr(pv, "is_draft", False)) and not can_view_drafts():
            raise HTTPException(
                status_code=403, detail="Draft version is not accessible"
            )
        return pv
    pv = (
        db.query(ProjectVersion)
        .filter(ProjectVersion.project_id == project.id)
        .filter(ProjectVersion.is_latest.is_(True))
        .order_by(ProjectVersion.created_at.desc())
        .first()
    )
    if not pv:
        raise HTTPException(status_code=404, detail="Project has no versions")
    return pv


def _dependency_namespace(ecosystem: str, package_name: str) -> str:
    """Best-effort namespace/scope extractor to group packages in the dependency tree.

    Notes:
    - We prefer grouping npm deps by scope ("@scope"), and for non-scoped packages we
      keep them under "(unscoped)".
    - Some scanners/tools can slightly vary the stored representation; this helper is
      intentionally defensive.
    """
    eco = (ecosystem or "").lower().strip()
    name = (package_name or "").strip()
    if not name:
        return "(unknown)"

    # npm scoped packages: @scope/name
    if eco in {"npm", "node", "nodejs"}:
        # Common case
        if name.startswith("@") and "/" in name:
            return name.split("/", 1)[0]
        # Occasionally a leading invisible/formatting char can sneak in; try a lighter heuristic.
        if "@" in name and "/" in name:
            first = name.split("/", 1)[0]
            if first.strip().startswith("@"):
                return first.strip()
        return "(unscoped)"

    # Composer: vendor/package
    if eco in {"composer", "php", "packagist"}:
        if "/" in name:
            return name.split("/", 1)[0]
        return "(root)"

    # Maven/Gradle: group:artifact -> group
    if eco in {"maven", "gradle"}:
        if ":" in name:
            return name.split(":", 1)[0]
        return "(root)"

    # Generic heuristic: org/pkg -> org
    if "/" in name:
        return name.split("/", 1)[0]

    return "(root)"


@router.get("/v1/projects/{project_id}/dependency-graph")
def get_project_dependency_graph(
    project_id: int,
    version_id: int | None = Query(default=None),
    include_vulnerabilities: bool = Query(default=True),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Return hierarchical dependency data for D3 (tidy-tree/treemap/sunburst/radial-tree).

    Shape is intentionally simple: a D3-friendly hierarchy (dependency_tree) plus a flat list (dependencies)
    and an optional aggregated vulnerability list for the selected project version.
    """

    project = db.query(Project).filter(Project.id == project_id).one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    pv = _version_or_404(db, project, user, version_id)

    rows = (
        db.query(
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
        .filter(ProjectVersionDependency.project_version_id == pv.id)
        .group_by(
            DependencyPackage.ecosystem,
            DependencyPackage.name,
            DependencyPackage.normalized_name,
            DependencyVersion.version,
            DependencyVersion.id,
            ProjectVersionDependency.is_indirect,
            ProjectVersionDependency.source_files,
        )
        .all()
    )

    # Group deps by ecosystem -> namespace
    by_ecosystem: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    deps_flat: list[dict[str, Any]] = []
    total_vulns = 0

    def _leaf_display_name(
        ecosystem: str, namespace: str, package_name: str, version: str
    ) -> str:
        """Improve readability once we have a namespace node.

        Example: namespace '@inquirer' + package '@inquirer/confirm' becomes leaf 'confirm@5.1.21'.
        """
        eco = (ecosystem or "").lower().strip()
        name = (package_name or "").strip()
        ver = (version or "").strip()
        label = f"{name}@{ver}" if ver else name

        if eco in {"npm", "node", "nodejs"} and namespace and namespace.startswith("@"):
            prefix = f"{namespace}/"
            if name.startswith(prefix):
                rest = name.split("/", 1)[1]
                return f"{rest}@{ver}" if ver else rest

        if eco in {"composer", "php", "packagist"} and "/" in name:
            rest = name.split("/", 1)[1]
            return f"{rest}@{ver}" if ver else rest

        return label

    for r in rows:
        eco = str(r.ecosystem)
        name = str(r.name)
        ver = str(r.version or "")
        label = f"{name}@{ver}" if ver else name
        # Prefer normalized_name for grouping; it's lowercased and more consistent.
        ns_source = str(r.normalized_name or name)
        ns = _dependency_namespace(eco, ns_source)
        display_label = _leaf_display_name(eco, ns, name, ver)

        item = {
            "ecosystem": eco,
            "namespace": ns,
            "name": name,
            "normalized_name": r.normalized_name,
            "version": ver,
            "label": label,
            "display_label": display_label,
            "dependency_version_id": int(r.dependency_version_id),
            "is_indirect": bool(r.is_indirect),
            "source_files": list(r.source_files or []),
            "vulnerability_count": int(r.vuln_count or 0),
        }
        total_vulns += int(r.vuln_count or 0)
        deps_flat.append(item)
        by_ecosystem[eco][ns].append(item)

    # Hierarchy: Project -> Version -> Ecosystem -> Namespace -> Dependency leaf
    project_label = project.display_name or project.machine_name
    tree = {
        "name": project_label,
        "children": [
            {
                "name": pv.version,
                "children": [
                    {
                        "name": eco,
                        "children": [
                            {
                                "name": ns,
                                "children": [
                                    {
                                        "name": d.get("display_label") or d["label"],
                                        "value": 1,
                                        "ecosystem": d["ecosystem"],
                                        "namespace": d["namespace"],
                                        "package": d["name"],
                                        "version": d["version"],
                                        "dependency_version_id": d[
                                            "dependency_version_id"
                                        ],
                                        "is_indirect": d["is_indirect"],
                                        "vulnerability_count": d["vulnerability_count"],
                                    }
                                    for d in sorted(
                                        items, key=lambda x: x["label"].lower()
                                    )
                                ],
                            }
                            for ns, items in sorted(
                                ns_map.items(), key=lambda x: x[0].lower()
                            )
                        ],
                    }
                    for eco, ns_map in sorted(
                        by_ecosystem.items(), key=lambda x: x[0].lower()
                    )
                ],
            }
        ],
    }

    vulnerabilities: list[dict[str, Any]] = []
    if include_vulnerabilities:
        vuln_rows = (
            db.query(
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
            .filter(ProjectVersionDependency.project_version_id == pv.id)
            .order_by(
                DependencyPackage.ecosystem.asc(),
                DependencyPackage.normalized_name.asc(),
                DependencyVulnerability.vulnerability_id.asc(),
            )
            .all()
        )

        for r in vuln_rows:
            eco = str(r.ecosystem)
            name = str(r.name)
            ver = str(r.version or "")
            label = f"{name}@{ver}" if ver else name
            ns_source = str(r.normalized_name or name)
            vulnerabilities.append(
                {
                    "ecosystem": eco,
                    "namespace": _dependency_namespace(eco, ns_source),
                    "package": name,
                    "version": ver,
                    "dependency_label": label,
                    "dependency_version_id": int(r.dependency_version_id),
                    "scanner": str(r.scanner or "legacy"),
                    "vulnerability_id": str(r.vulnerability_id),
                    "severity": (str(r.severity).upper() if r.severity else None),
                    "title": r.title,
                    "fixed_version": r.fixed_version,
                    "references": list(r.references or []),
                    "created_at": r.created_at,
                }
            )

    return {
        "project": {
            "id": project.id,
            "name": project_label,
            "display_name": project.display_name,
            "machine_name": project.machine_name,
        },
        "version": {
            "id": pv.id,
            "version": pv.version,
            "is_latest": pv.is_latest,
            "link_to_source_code": pv.link_to_source_code,
            "dependency_discovery_status": pv.dependency_discovery_status,
            "dependency_discovery_started_at": pv.dependency_discovery_started_at,
            "dependency_discovery_finished_at": pv.dependency_discovery_finished_at,
            "dependency_discovery_error": pv.dependency_discovery_error,
            "dependency_last_commit": pv.dependency_last_commit,
            "dependency_count": pv.dependency_count,
            "vulnerability_count": pv.vulnerability_count,
        },
        "dependency_tree": tree,
        "dependencies": deps_flat,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "dependency_count": len(deps_flat),
            "vulnerability_count": total_vulns,
            "ecosystems": {
                k: sum(len(v) for v in ns_map.values())
                for k, ns_map in by_ecosystem.items()
            },
            "namespaces": {
                k: {ns: len(items) for ns, items in ns_map.items()}
                for k, ns_map in by_ecosystem.items()
            },
        },
    }


@router.post("/v1/project-versions/{project_version_id}/dependency-discovery")
def enqueue_dependency_discovery(
    project_version_id: int,
    run_now: bool = Query(default=True),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Queue (and optionally start) dependency discovery for a project version."""

    if not bool(getattr(settings, "dependency_discovery_enabled", True)):
        raise HTTPException(status_code=400, detail="Dependency discovery is disabled")

    pv = (
        db.query(ProjectVersion)
        .filter(ProjectVersion.id == project_version_id)
        .one_or_none()
    )
    if not pv:
        raise HTTPException(status_code=404, detail="Project version not found")

    project = db.query(Project).filter(Project.id == pv.project_id).one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_admin_or_project_owner(db, user, project)
    if not pv.link_to_source_code:
        raise HTTPException(
            status_code=400, detail="Project version has no link_to_source_code"
        )

    pv.dependency_discovery_status = "queued"
    pv.dependency_discovery_error = None
    pv.dependency_discovery_started_at = None
    pv.dependency_discovery_finished_at = None
    pv.dependency_last_commit = None
    pv.dependency_count = 0
    pv.vulnerability_count = 0
    db.query(ProjectVersionDependency).filter(
        ProjectVersionDependency.project_version_id == pv.id
    ).delete(synchronize_session=False)
    db.commit()

    launched = False
    if run_now:
        try:
            from app.tasks.dependency_discovery import (
                discover_project_version_dependencies,
            )

            discover_project_version_dependencies.delay(project_version_id)
            launched = True
        except Exception:
            launched = False
    return {
        "queued": True,
        "launched": launched,
        "project_version_id": project_version_id,
    }


@router.get("/v1/visualisations/dependencies-bipartite")
def dependencies_bipartite(
    latest_only: bool = Query(default=True),
    limit_projects: int = Query(default=30, ge=1, le=200),
    limit_dependencies: int = Query(default=60, ge=1, le=500),
    min_usage: int = Query(default=1, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Cross-project bipartite graph: project versions <-> dependency versions."""

    _require_admin(db, user)

    base = db.query(
        ProjectVersionDependency.project_version_id,
        ProjectVersionDependency.dependency_version_id,
    )
    if latest_only:
        base = base.join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionDependency.project_version_id,
        ).filter(ProjectVersion.is_latest.is_(True))

    # Top dependencies by usage across (distinct) project versions.
    usage_rows = (
        db.query(
            ProjectVersionDependency.dependency_version_id,
            func.count(
                func.distinct(ProjectVersionDependency.project_version_id)
            ).label("usage_count"),
        )
        .select_from(ProjectVersionDependency)
        .join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionDependency.project_version_id,
        )
        .filter(ProjectVersion.is_latest.is_(True) if latest_only else True)  # type: ignore[arg-type]  # SQLAlchemy accepts bool filters and desc() chains
        .group_by(ProjectVersionDependency.dependency_version_id)
        .having(
            func.count(func.distinct(ProjectVersionDependency.project_version_id))
            >= int(min_usage)
        )
        .order_by(
            func.count(
                func.distinct(ProjectVersionDependency.project_version_id)
            ).desc()
        )
        .limit(int(limit_dependencies))
        .all()
    )
    top_dep_ids = [int(r.dependency_version_id) for r in usage_rows]
    usage_map = {
        int(r.dependency_version_id): int(r.usage_count or 0) for r in usage_rows
    }
    if not top_dep_ids:
        return {"nodes": [], "links": [], "meta": {"latest_only": latest_only}}

    # Edges restricted to top deps
    edges_q = db.query(
        ProjectVersionDependency.project_version_id,
        ProjectVersionDependency.dependency_version_id,
    ).filter(ProjectVersionDependency.dependency_version_id.in_(top_dep_ids))
    if latest_only:
        edges_q = edges_q.join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionDependency.project_version_id,
        ).filter(ProjectVersion.is_latest.is_(True))
    edges = edges_q.all()

    # Pick top projects by number of edges in this subgraph
    project_edge_counts: dict[int, int] = defaultdict(int)
    for e in edges:
        project_edge_counts[int(e.project_version_id)] += 1
    top_project_ids = [
        pid
        for pid, _ in sorted(
            project_edge_counts.items(), key=lambda x: x[1], reverse=True
        )[: int(limit_projects)]
    ]
    if not top_project_ids:
        return {"nodes": [], "links": [], "meta": {"latest_only": latest_only}}

    # Load project/version labels
    pv_rows = (
        db.query(
            ProjectVersion.id,
            ProjectVersion.version,
            Project.id.label("project_id"),
            func.coalesce(Project.display_name, Project.machine_name).label(
                "project_name"
            ),
        )
        .join(Project, Project.id == ProjectVersion.project_id)
        .filter(ProjectVersion.id.in_(top_project_ids))
        .all()
    )

    pv_label = {int(r.id): f"{r.project_name} {r.version}" for r in pv_rows}

    pv_project_id = {int(r.id): int(r.project_id) for r in pv_rows}

    dv_rows = (
        db.query(
            DependencyVersion.id,
            DependencyVersion.version,
            DependencyPackage.ecosystem,
            DependencyPackage.name,
        )
        .join(
            DependencyPackage, DependencyPackage.id == DependencyVersion.dependency_id
        )
        .filter(DependencyVersion.id.in_(top_dep_ids))
        .all()
    )
    dv_label = {
        int(r.id): (str(r.ecosystem), f"{r.name}@{r.version}" if r.version else r.name)
        for r in dv_rows
    }

    nodes: list[dict[str, Any]] = []
    for pid in top_project_ids:
        nodes.append(
            {
                "id": f"p:{pid}",
                "type": "project_version",
                "label": pv_label.get(pid, str(pid)),
                "project_version_id": pid,
                "project_id": pv_project_id.get(pid),
            }
        )
    for dep_id in top_dep_ids:
        eco, label = dv_label.get(dep_id, ("", str(dep_id)))
        nodes.append(
            {
                "id": f"d:{dep_id}",
                "type": "dependency_version",
                "label": label,
                "ecosystem": eco,
                "dependency_version_id": dep_id,
                "usage_count": usage_map.get(dep_id, 0),
            }
        )

    links: list[dict[str, Any]] = []
    edge_set = set()
    for e in edges:
        pid = int(e.project_version_id)
        did = int(e.dependency_version_id)
        if pid not in top_project_ids:
            continue
        if did not in top_dep_ids:
            continue
        key = (pid, did)
        if key in edge_set:
            continue
        edge_set.add(key)
        links.append({"source": f"p:{pid}", "target": f"d:{did}", "weight": 1})

    return {
        "nodes": nodes,
        "links": links,
        "meta": {
            "latest_only": latest_only,
            "limit_projects": limit_projects,
            "limit_dependencies": limit_dependencies,
            "min_usage": min_usage,
        },
    }


def _capabilities_bipartite(
    *,
    latest_only: bool,
    limit_projects: int,
    limit_items: int,
    min_usage: int,
    db: Session,
) -> dict[str, Any]:
    """Cross-project bipartite graph: project versions <-> framework nodes (capabilities)."""

    usage_rows = (
        db.query(
            ProjectVersionFrameworkNode.framework_node_id,
            func.count(
                func.distinct(ProjectVersionFrameworkNode.project_version_id)
            ).label("usage_count"),
        )
        .select_from(ProjectVersionFrameworkNode)
        .join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionFrameworkNode.project_version_id,
        )
        .filter(ProjectVersion.is_latest.is_(True) if latest_only else True)  # type: ignore[arg-type]  # SQLAlchemy accepts bool filters and desc() chains
        .group_by(ProjectVersionFrameworkNode.framework_node_id)
        .having(
            func.count(func.distinct(ProjectVersionFrameworkNode.project_version_id))
            >= int(min_usage)
        )
        .order_by(
            func.count(
                func.distinct(ProjectVersionFrameworkNode.project_version_id)
            ).desc()
        )
        .limit(int(limit_items))
        .all()
    )

    top_node_ids = [int(r.framework_node_id) for r in usage_rows]
    usage_map = {int(r.framework_node_id): int(r.usage_count or 0) for r in usage_rows}
    if not top_node_ids:
        return {
            "nodes": [],
            "links": [],
            "meta": {"latest_only": latest_only, "lens": "capabilities"},
        }

    edges_q = db.query(
        ProjectVersionFrameworkNode.project_version_id,
        ProjectVersionFrameworkNode.framework_node_id,
    ).filter(ProjectVersionFrameworkNode.framework_node_id.in_(top_node_ids))
    if latest_only:
        edges_q = edges_q.join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionFrameworkNode.project_version_id,
        ).filter(ProjectVersion.is_latest.is_(True))
    edges = edges_q.all()

    project_edge_counts: dict[int, int] = defaultdict(int)
    for e in edges:
        project_edge_counts[int(e.project_version_id)] += 1
    top_project_ids = [
        pid
        for pid, _ in sorted(
            project_edge_counts.items(), key=lambda x: x[1], reverse=True
        )[: int(limit_projects)]
    ]
    if not top_project_ids:
        return {
            "nodes": [],
            "links": [],
            "meta": {"latest_only": latest_only, "lens": "capabilities"},
        }

    pv_rows = (
        db.query(
            ProjectVersion.id,
            ProjectVersion.version,
            Project.id.label("project_id"),
            func.coalesce(Project.display_name, Project.machine_name).label(
                "project_name"
            ),
        )
        .join(Project, Project.id == ProjectVersion.project_id)
        .filter(ProjectVersion.id.in_(top_project_ids))
        .all()
    )
    pv_label = {int(r.id): f"{r.project_name} {r.version}" for r in pv_rows}

    pv_project_id = {int(r.id): int(r.project_id) for r in pv_rows}

    fn_rows = (
        db.query(
            FrameworkNode.id,
            FrameworkNode.display_name,
            FrameworkNode.key,
            Framework.machine_name.label("framework_machine_name"),
            Framework.display_name.label("framework_display_name"),
        )
        .join(Framework, Framework.id == FrameworkNode.framework_id)
        .filter(FrameworkNode.id.in_(top_node_ids))
        .all()
    )
    fn_label: dict[int, tuple[str, str]] = {}
    for r in fn_rows:
        # Framework model uses machine_name/display_name (not key/name).
        fkey = str(getattr(r, "framework_machine_name", "") or "").strip()
        fname = str(getattr(r, "framework_display_name", "") or "").strip()
        prefix = fname or fkey
        label = str(r.display_name or r.key or r.id)
        if prefix:
            label = f"{prefix}: {label}"
        fn_label[int(r.id)] = (prefix, label)

    nodes: list[dict[str, Any]] = []
    for pid in top_project_ids:
        nodes.append(
            {
                "id": f"p:{pid}",
                "type": "project_version",
                "label": pv_label.get(pid, str(pid)),
                "project_version_id": pid,
                "project_id": pv_project_id.get(pid),
            }
        )

    for node_id in top_node_ids:
        fkey, label = fn_label.get(node_id, ("", str(node_id)))
        nodes.append(
            {
                "id": f"c:{node_id}",
                "type": "capability",
                "label": label,
                "framework": fkey,
                "framework_node_id": node_id,
                "usage_count": usage_map.get(node_id, 0),
            }
        )

    links: list[dict[str, Any]] = []
    edge_set = set()
    for e in edges:
        pid = int(e.project_version_id)
        nid = int(e.framework_node_id)
        if pid not in top_project_ids:
            continue
        if nid not in top_node_ids:
            continue
        key = (pid, nid)
        if key in edge_set:
            continue
        edge_set.add(key)
        links.append({"source": f"p:{pid}", "target": f"c:{nid}", "weight": 1})

    return {
        "nodes": nodes,
        "links": links,
        "meta": {
            "latest_only": latest_only,
            "lens": "capabilities",
            "limit_projects": limit_projects,
            "limit_items": limit_items,
            "min_usage": min_usage,
        },
    }


def _licenses_bipartite(
    *,
    latest_only: bool,
    limit_projects: int,
    limit_items: int,
    min_usage: int,
    db: Session,
) -> dict[str, Any]:
    """Cross-project bipartite graph: project versions <-> project license strings."""

    license_expr = func.coalesce(Project.license, "(unknown)")

    usage_rows = (
        db.query(
            license_expr.label("license"),
            func.count(func.distinct(Project.id)).label("usage_count"),
        )
        .select_from(Project)
        .join(ProjectVersion, ProjectVersion.project_id == Project.id)
        .filter(ProjectVersion.is_latest.is_(True) if latest_only else True)  # type: ignore[arg-type]  # SQLAlchemy accepts bool filters and desc() chains
        .group_by(license_expr)
        .having(func.count(func.distinct(Project.id)) >= int(min_usage))
        .order_by(func.count(func.distinct(Project.id)).desc())
        .limit(int(limit_items))
        .all()
    )

    top_licenses = [str(r.license) for r in usage_rows]
    usage_map = {str(r.license): int(r.usage_count or 0) for r in usage_rows}
    if not top_licenses:
        return {
            "nodes": [],
            "links": [],
            "meta": {"latest_only": latest_only, "lens": "licenses"},
        }

    pv_rows = (
        db.query(
            ProjectVersion.id,
            ProjectVersion.version,
            Project.id.label("project_id"),
            func.coalesce(Project.display_name, Project.machine_name).label(
                "project_name"
            ),
            license_expr.label("license"),
        )
        .join(Project, Project.id == ProjectVersion.project_id)
        .filter(ProjectVersion.is_latest.is_(True) if latest_only else True)  # type: ignore[arg-type]  # SQLAlchemy accepts bool filters and desc() chains
        .filter(license_expr.in_(top_licenses))
        .order_by(func.coalesce(Project.display_name, Project.machine_name).asc())
        .limit(int(limit_projects))
        .all()
    )

    top_project_ids = [int(r.id) for r in pv_rows]
    if not top_project_ids:
        return {
            "nodes": [],
            "links": [],
            "meta": {"latest_only": latest_only, "lens": "licenses"},
        }

    pv_label = {int(r.id): f"{r.project_name} {r.version}" for r in pv_rows}

    pv_project_id = {int(r.id): int(r.project_id) for r in pv_rows}

    nodes: list[dict[str, Any]] = []
    for pid in top_project_ids:
        nodes.append(
            {
                "id": f"p:{pid}",
                "type": "project_version",
                "label": pv_label.get(pid, str(pid)),
                "project_version_id": pid,
                "project_id": pv_project_id.get(pid),
            }
        )

    for lic in top_licenses:
        nodes.append(
            {
                "id": f"l:{lic}",
                "type": "license",
                "label": lic,
                "usage_count": usage_map.get(lic, 0),
            }
        )

    links: list[dict[str, Any]] = []
    edge_set = set()
    for r in pv_rows:
        pid = int(r.id)
        lic = str(r.license)
        key = (pid, lic)
        if key in edge_set:
            continue
        edge_set.add(key)
        links.append({"source": f"p:{pid}", "target": f"l:{lic}", "weight": 1})

    return {
        "nodes": nodes,
        "links": links,
        "meta": {
            "latest_only": latest_only,
            "lens": "licenses",
            "limit_projects": limit_projects,
            "limit_items": limit_items,
            "min_usage": min_usage,
        },
    }


@router.get("/v1/visualisations/bipartite")
def visualisations_bipartite(
    lens: str = Query(default="dependencies"),
    latest_only: bool = Query(default=True),
    limit_projects: int = Query(default=30, ge=1, le=200),
    limit_items: int = Query(default=80, ge=1, le=500),
    min_usage: int = Query(default=2, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Cross-project bipartite visualisations.

    lens:
      - dependencies: project versions <-> dependency versions
      - capabilities: project versions <-> framework nodes
      - licenses: project versions <-> project license strings
    """

    lens_value = str(lens or "dependencies").lower().strip()

    if lens_value in {"dependency", "dependencies", "deps"}:
        return dependencies_bipartite(
            latest_only=latest_only,
            limit_projects=limit_projects,
            limit_dependencies=limit_items,
            min_usage=min_usage,
            db=db,
            user=user,
        )

    if lens_value in {"capability", "capabilities", "framework", "framework_nodes"}:
        return _capabilities_bipartite(
            latest_only=latest_only,
            limit_projects=limit_projects,
            limit_items=limit_items,
            min_usage=min_usage,
            db=db,
        )

    if lens_value in {"license", "licenses"}:
        return _licenses_bipartite(
            latest_only=latest_only,
            limit_projects=limit_projects,
            limit_items=limit_items,
            min_usage=min_usage,
            db=db,
        )

    raise HTTPException(status_code=400, detail=f"Unknown lens '{lens}'")


# -----------------------------------------------------------------------------
# Dependency detail pages
# -----------------------------------------------------------------------------


def _iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)


def _severity_rank(value: str | None) -> int:
    v = str(value or "").strip().upper()
    # Common scanners: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
        "": 0,
        None: 0,
    }
    return int(order.get(v, 0))


_PUBLIC_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def _resolve_dependency_version_id(db: Session, raw: str) -> int:
    """Resolve a detail reference to a DependencyVersion id.

    The reference is either an existing dependency-version id, a package id
    (the browser's legacy numeric links) or a package UUID public id (the
    browser's deep links). Package references resolve to the newest
    recorded version of that package, so a package-level row always lands
    on something concrete instead of a 404.
    """

    text = (raw or "").strip().lower()
    if _PUBLIC_ID_RE.fullmatch(text):
        package = (
            db.query(DependencyPackage.id)
            .filter(DependencyPackage.public_id == text)
            .scalar()
        )
        if not package:
            raise HTTPException(status_code=404, detail="Dependency not found")
        version = (
            db.query(DependencyVersion.id)
            .filter(DependencyVersion.dependency_id == package)
            .order_by(DependencyVersion.version.desc(), DependencyVersion.id.desc())
            .first()
        )
        if not version:
            raise HTTPException(
                status_code=404, detail="Dependency has no recorded versions yet"
            )
        return int(version)
    try:
        number = int(text)
    except ValueError:
        raise HTTPException(status_code=404, detail="Dependency not found") from None
    exists = (
        db.query(DependencyVersion.id).filter(DependencyVersion.id == number).scalar()
    )
    if exists:
        return int(exists)
    version = (
        db.query(DependencyVersion.id)
        .join(
            DependencyPackage,
            DependencyPackage.id == DependencyVersion.dependency_id,
        )
        .filter(DependencyPackage.id == number)
        .order_by(DependencyVersion.version.desc(), DependencyVersion.id.desc())
        .first()
    )
    if not version:
        raise HTTPException(status_code=404, detail="Dependency version not found")
    return int(version)


@router.get("/v1/dependencies/{dependency_version_id}")
def dependency_version_detail(
    dependency_version_id: str,
    namespace_limit: int = Query(default=120, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Dependency version detail for the UI.

    Includes backlink metadata (projects using this dependency), vulnerability list,
    and (for npm scopes) other packages under the same @namespace.
    """

    _require_admin(db, user)

    # Ensure user is authenticated (and attach role for future policy), but currently
    # dependency metadata is global within the instance.
    attach_effective_role(db, user)

    resolved_version_id = _resolve_dependency_version_id(db, dependency_version_id)

    dv = (
        db.query(
            DependencyVersion.id.label("dependency_version_id"),
            DependencyVersion.version.label("version"),
            DependencyVersion.created_at.label("created_at"),
            DependencyPackage.id.label("dependency_id"),
            DependencyPackage.ecosystem.label("ecosystem"),
            DependencyPackage.name.label("name"),
            DependencyPackage.normalized_name.label("normalized_name"),
        )
        .join(
            DependencyPackage, DependencyPackage.id == DependencyVersion.dependency_id
        )
        .filter(DependencyVersion.id == resolved_version_id)
        .first()
    )
    if not dv:
        raise HTTPException(status_code=404, detail="Dependency version not found")

    # Backlinks: which project versions use this dep version
    used_by = (
        db.query(
            ProjectVersionDependency.project_version_id.label("project_version_id"),
            ProjectVersionDependency.is_indirect.label("is_indirect"),
            ProjectVersionDependency.source_files.label("source_files"),
            ProjectVersion.id.label("pv_id"),
            ProjectVersion.version.label("pv_version"),
            ProjectVersion.is_latest.label("is_latest"),
            ProjectVersion.is_draft.label("is_draft"),
            Project.id.label("project_id"),
            func.coalesce(Project.display_name, Project.machine_name).label(
                "project_name"
            ),
        )
        .join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionDependency.project_version_id,
        )
        .join(Project, Project.id == ProjectVersion.project_id)
        .filter(ProjectVersionDependency.dependency_version_id == resolved_version_id)
        .order_by(
            func.coalesce(Project.display_name, Project.machine_name).asc(),
            ProjectVersion.version.asc(),
        )
        .all()
    )

    projects: list[dict[str, Any]] = []
    for r in used_by:
        projects.append(
            {
                "project_id": int(r.project_id),
                "project_name": str(r.project_name),
                "project_version_id": int(r.project_version_id),
                "project_version": str(r.pv_version or ""),
                "is_latest": bool(r.is_latest),
                "is_draft": bool(r.is_draft),
                "is_indirect": bool(r.is_indirect),
                "source_files": list(r.source_files or []),
            }
        )

    # Vulnerabilities
    vuln_rows = (
        db.query(DependencyVulnerability)
        .filter(DependencyVulnerability.dependency_version_id == resolved_version_id)
        .all()
    )
    vulns: list[dict[str, Any]] = []
    sev_counts: dict[str, int] = defaultdict(int)
    for v in vuln_rows:
        sev = str(v.severity or "UNKNOWN").upper()
        sev_counts[sev] += 1
        vulns.append(
            {
                "scanner": v.scanner,
                "vulnerability_id": v.vulnerability_id,
                "severity": v.severity,
                "title": v.title,
                "fixed_version": v.fixed_version,
                "references": list(v.references or []),
                "raw": v.raw or {},
                "created_at": _iso(v.created_at),
            }
        )

    vulns.sort(
        key=lambda x: (
            -_severity_rank(x.get("severity")),
            str(x.get("vulnerability_id") or ""),
        )
    )

    # Namespace (npm scopes)
    namespace: dict[str, Any] | None = None
    eco = str(dv.ecosystem or "").lower().strip()
    name = str(dv.name or "")
    scope = None
    if eco == "npm" and name.startswith("@") and "/" in name:
        scope = name.split("/", 1)[0]

    if scope:
        like = f"{scope}/%"
        pkg_rows = (
            db.query(
                DependencyPackage.id.label("dependency_id"),
                DependencyPackage.name.label("name"),
                DependencyPackage.normalized_name.label("normalized_name"),
            )
            .filter(DependencyPackage.ecosystem == dv.ecosystem)
            .filter(DependencyPackage.name.ilike(like))
            .order_by(DependencyPackage.name.asc())
            .limit(int(namespace_limit))
            .all()
        )
        namespace = {
            "scope": scope,
            "ecosystem": dv.ecosystem,
            "packages": [
                {
                    "dependency_id": int(p.dependency_id),
                    "name": str(p.name),
                    "normalized_name": str(p.normalized_name),
                }
                for p in pkg_rows
            ],
            "truncated": len(pkg_rows) >= int(namespace_limit),
        }

    return {
        "dependency_version": {
            "dependency_version_id": int(dv.dependency_version_id),
            "dependency_id": int(dv.dependency_id),
            "ecosystem": dv.ecosystem,
            "name": dv.name,
            "normalized_name": dv.normalized_name,
            "version": dv.version,
            "created_at": _iso(dv.created_at),
        },
        "projects": projects,
        "vulnerabilities": vulns,
        "severity_counts": dict(sev_counts),
        "namespace": namespace,
    }


@router.get("/v1/capabilities/{framework_node_id}")
def capability_detail(
    framework_node_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Capability (framework node) detail for the UI.

    Includes backlink metadata (projects/versions that have the capability).
    """

    attach_effective_role(db, user)

    node = (
        db.query(
            FrameworkNode,
            Framework.id.label("framework_id"),
            Framework.machine_name.label("framework_machine_name"),
            Framework.display_name.label("framework_display_name"),
        )
        .join(Framework, Framework.id == FrameworkNode.framework_id)
        .filter(FrameworkNode.id == int(framework_node_id))
        .first()
    )
    if not node:
        raise HTTPException(status_code=404, detail="Capability not found")

    fn: FrameworkNode = node[0]
    framework_id = int(node.framework_id)
    framework_machine = str(node.framework_machine_name or "")
    framework_display = str(node.framework_display_name or "")

    # Compute path by loading all nodes in the framework (fast enough for UI detail).
    all_nodes = (
        db.query(FrameworkNode.id, FrameworkNode.display_name, FrameworkNode.parent_id)
        .filter(FrameworkNode.framework_id == framework_id)
        .all()
    )
    by_id = {
        int(r.id): {"name": r.display_name, "parent_id": r.parent_id} for r in all_nodes
    }

    def path_for(nid: int) -> str:
        cur = by_id.get(nid)
        if not cur:
            return str(nid)
        parts = [str(cur.get("name") or nid)]
        pid = cur.get("parent_id")
        safety = 0
        while pid and safety < 50:
            p = by_id.get(int(pid))
            if not p:
                break
            parts.append(str(p.get("name") or pid))
            pid = p.get("parent_id")
            safety += 1
        return " / ".join(reversed(parts))

    path = path_for(int(framework_node_id))

    # Draft versions are only exposed to accounts that can view them for the
    # owning project; every other caller sees released versions only.
    admin_view = attach_effective_role(db, user) == ROLE_ADMIN

    used_by = (
        db.query(
            ProjectVersionFrameworkNode.project_version_id.label("project_version_id"),
            ProjectVersion.id.label("pv_id"),
            ProjectVersion.version.label("pv_version"),
            ProjectVersion.is_latest.label("is_latest"),
            ProjectVersion.is_draft.label("is_draft"),
            ProjectVersion.project_id.label("version_project_id"),
            Project.id.label("project_id"),
            func.coalesce(Project.display_name, Project.machine_name).label(
                "project_name"
            ),
        )
        .join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionFrameworkNode.project_version_id,
        )
        .join(Project, Project.id == ProjectVersion.project_id)
        .filter(ProjectVersionFrameworkNode.framework_node_id == int(framework_node_id))
        .order_by(
            func.coalesce(Project.display_name, Project.machine_name).asc(),
            ProjectVersion.version.asc(),
        )
        .all()
    )

    draft_owners = {int(r.project_id) for r in used_by if bool(r.is_draft)}
    drafts_visible: set[int] = set()
    for project_id in draft_owners:
        if admin_view or _can_view_drafts_for_project(db, user, project_id):
            drafts_visible.add(project_id)

    projects: list[dict[str, Any]] = []
    for r in used_by:
        if bool(r.is_draft) and int(r.project_id) not in drafts_visible:
            continue
        projects.append(
            {
                "project_id": int(r.project_id),
                "project_name": str(r.project_name),
                "project_version_id": int(r.project_version_id),
                "project_version": str(r.pv_version or ""),
                "is_latest": bool(r.is_latest),
                "is_draft": bool(r.is_draft),
            }
        )

    return {
        "capability": {
            "framework_node_id": int(fn.id),
            "framework_id": framework_id,
            "framework_machine_name": framework_machine,
            "framework_display_name": framework_display,
            "key": fn.key,
            "display_name": fn.display_name,
            "description": fn.description,
            "parent_id": fn.parent_id,
            "level": fn.level,
            "path": path,
        },
        "projects": projects,
    }


@router.get("/v1/dependencies")
def dependency_index(
    q: str | None = None,
    ecosystem: str | None = None,
    vulnerable: bool | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A searchable directory of every dependency the catalogue knows.

    Name query, ecosystem filter and vuln-only flag; each row carries the
    UUID public id the browser deep-links, plus usage counts so a web team
    spots concentration at a glance.
    """
    attach_effective_role(db, user)

    search = (q or "").strip().lower()
    query = (
        db.query(
            DependencyPackage.id.label("package_id"),
            DependencyPackage.public_id.label("public_id"),
            DependencyPackage.ecosystem.label("ecosystem"),
            DependencyPackage.name.label("name"),
            DependencyPackage.normalized_name.label("normalized_name"),
            func.count(DependencyVersion.id).label("version_count"),
        )
        .outerjoin(
            DependencyVersion, DependencyVersion.dependency_id == DependencyPackage.id
        )
        .group_by(
            DependencyPackage.id,
            DependencyPackage.public_id,
            DependencyPackage.ecosystem,
            DependencyPackage.name,
            DependencyPackage.normalized_name,
        )
    )
    if search:
        query = query.filter(
            or_(
                DependencyPackage.normalized_name.ilike(f"%{search}%"),
                DependencyPackage.name.ilike(f"%{search}%"),
            )
        )
    if ecosystem:
        query = query.filter(DependencyPackage.ecosystem == ecosystem.strip())

    # Vulnerability filtering has to happen in SQL across the whole result
    # set, not within the page slice, or pages would only short-change
    # themselves: a package with any vulnerable version still counts once.
    if vulnerable:
        vulnerable_packages = (
            db.query(DependencyVersion.dependency_id)
            .join(
                DependencyVulnerability,
                DependencyVulnerability.dependency_version_id == DependencyVersion.id,
            )
            .distinct()
        )
        # A scalar subquery nests as IN (SELECT ...), so membership is
        # resolved by the planner instead of materialising the catalogue.
        query = query.filter(
            DependencyPackage.id.in_(vulnerable_packages.scalar_subquery())
        )

    # One bounded aggregate for the pager: a count over the same filtered
    # query, before pagination, wherever the web team pages through it.
    total = int(query.order_by(None).count() or 0)

    rows = (
        query.order_by(DependencyPackage.normalized_name.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Per-package usage counts and vulnerability tallies in one bounded pass
    # over the page's packages, however the catalogue grows.
    package_ids = [int(row.package_id) for row in rows]
    usage: dict[int, int] = {}
    vuln_counts: dict[int, int] = {}
    if package_ids:
        links = (
            db.query(
                DependencyVersion.id.label("dv_id"),
                DependencyVersion.dependency_id.label("dep_id"),
                ProjectVersionDependency.project_version_id.label("pv_link_id"),
                DependencyVulnerability.vulnerability_id.label("vuln_id"),
            )
            .join(
                ProjectVersionDependency,
                ProjectVersionDependency.dependency_version_id == DependencyVersion.id,
            )
            .outerjoin(
                DependencyVulnerability,
                DependencyVulnerability.dependency_version_id == DependencyVersion.id,
            )
            .filter(DependencyVersion.dependency_id.in_(package_ids))
            .all()
        )
        vuln_seen: set[tuple[int, int, str]] = set()
        for link in links:
            dep_id = int(link.dep_id)
            usage[dep_id] = usage.get(dep_id, 0) + 1
            if link.vuln_id:
                key = (dep_id, int(link.dv_id), str(link.vuln_id))
                if key not in vuln_seen:
                    vuln_seen.add(key)
                    vuln_counts[dep_id] = vuln_counts.get(dep_id, 0) + 1

    # The ecosystem dropdown is built from what exists; distinct names are
    # few by design (scanner ecosystems), but stay capped for safety.
    ecosystems = [
        str(row[0] or "")
        for row in (
            db.query(DependencyPackage.ecosystem)
            .distinct()
            .order_by(DependencyPackage.ecosystem.asc())
            .limit(64)
            .all()
        )
        if row[0]
    ]

    return {
        "dependencies": [
            {
                "id": int(row.package_id),
                "public_id": row.public_id,
                "ecosystem": row.ecosystem,
                "name": row.name,
                "normalized_name": row.normalized_name,
                "version_count": int(row.version_count or 0),
                "used_by_count": usage.get(int(row.package_id), 0),
                "vulnerability_count": vuln_counts.get(int(row.package_id), 0),
            }
            for row in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
        "ecosystems": ecosystems,
    }


@router.get("/v1/dashboard")
def global_dashboard(
    organisation_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A dependency-first overview for the whole catalogue.

    Per project: the latest known release, its dependency discovery state and
    the unfixed vulnerability summary from the current Grype data, so a web
    team answers which projects need attention without reading a graph.
    """
    from app.core.features import is_enabled

    attach_effective_role(db, user)

    projects_query = db.query(Project).order_by(
        func.coalesce(Project.display_name, Project.machine_name).asc()
    )
    if organisation_id:
        projects_query = projects_query.filter(
            Project.organisation_id == int(organisation_id)
        )
    projects = projects_query.all()

    def _project_row(project: Project) -> dict[str, Any]:
        latest = (
            db.query(ProjectVersion)
            .filter(
                ProjectVersion.project_id == project.id,
                ProjectVersion.is_draft.is_(False),
                ProjectVersion.is_latest.is_(True),
            )
            .one_or_none()
        )
        if latest is None:
            alternatives = (
                db.query(ProjectVersion)
                .filter(
                    ProjectVersion.project_id == project.id,
                    ProjectVersion.is_draft.is_(False),
                )
                .order_by(ProjectVersion.version.desc())
                .limit(1)
                .all()
            )
            latest = alternatives[0] if alternatives else None
        if latest is None:
            return {
                "id": project.id,
                "name": project.display_name or project.machine_name,
                "machine_name": project.machine_name,
                "organisation": project.organisation,
                "organisation_id": project.organisation_id,
                "project_type": project.project_type,
                "latest": None,
                "dependencies": None,
                "vulnerabilities": None,
            }
        severities: dict[str, int] = {}
        rows = (
            db.query(
                DependencyVulnerability.severity,
                func.count(DependencyVulnerability.id),
            )
            .join(
                DependencyVersion,
                DependencyVersion.id == DependencyVulnerability.dependency_version_id,
            )
            .join(
                ProjectVersionDependency,
                ProjectVersionDependency.dependency_version_id == DependencyVersion.id,
            )
            .filter(ProjectVersionDependency.project_version_id == latest.id)
            .group_by(DependencyVulnerability.severity)
            .all()
        )
        for severity, count in rows:
            severities[(severity or "unknown").lower()] = int(count or 0)
        return {
            "id": project.id,
            "name": project.display_name or project.machine_name,
            "machine_name": project.machine_name,
            "organisation": project.organisation,
            "organisation_id": project.organisation_id,
            "project_type": project.project_type,
            "latest": {
                "id": latest.id,
                "version": latest.version,
                "is_draft": bool(latest.is_draft),
                "is_latest": bool(latest.is_latest),
                "release_date": latest.release_date,
            },
            "dependencies": {
                "discovery_status": latest.dependency_discovery_status,
                "count": latest.dependency_count,
                "last_commit": latest.dependency_last_commit,
                "discovered_at": latest.dependency_discovery_finished_at,
            },
            "vulnerabilities": {
                "total": sum(severities.values()),
                "by_severity": severities,
            },
        }

    return {
        "dependency_scans_enabled": is_enabled("dependency_scans"),
        "projects": [_project_row(p) for p in projects],
    }
