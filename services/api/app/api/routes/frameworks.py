from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.payloads import (
    FrameworkCreatePayload,
    FrameworkNodeCreatePayload,
    FrameworkNodeUpdatePayload,
    FrameworkUpdatePayload,
)
from app.db.capability_taxonomy import ensure_default_frameworks
from app.db.models import (
    Framework,
    FrameworkNode,
    Manifest,
    Project,
    ProjectVersion,
    ProjectVersionFrameworkNode,
    User,
)
from app.db.session import get_db
from app.security.auth import get_current_user
from app.security.permissions import PERM_FRAMEWORK_WRITE, has_permission
from app.security.roles import ROLE_ADMIN, attach_effective_role

router = APIRouter()


def _build_tree(nodes: list[FrameworkNode]) -> list[dict]:
    children: dict[int | None, list[FrameworkNode]] = defaultdict(list)
    for n in nodes:
        children[n.parent_id].append(n)

    for pid, arr in children.items():
        arr.sort(
            key=lambda x: (int(x.sort_order or 0), (x.display_name or "").lower(), x.id)
        )

    def build(parent_id: int | None) -> list[dict]:
        out: list[dict] = []
        for n in children.get(parent_id, []):
            out.append(
                {
                    "id": n.id,
                    "key": n.key,
                    "display_name": n.display_name,
                    "description": n.description,
                    "parent_id": n.parent_id,
                    "level": n.level,
                    "sort_order": n.sort_order,
                    "children": build(n.id),
                }
            )
        return out

    return build(None)


def _paths_by_id(nodes: list[FrameworkNode]) -> dict[int, str]:
    by_id = {n.id: n for n in nodes}

    def path_for(n: FrameworkNode) -> str:
        parts = [n.display_name]
        seen = {n.id}
        parent = by_id.get(n.parent_id) if n.parent_id else None
        # A stored cycle (which updates refuse) must not loop forever.
        while parent and parent.id not in seen:
            seen.add(parent.id)
            parts.append(parent.display_name)
            parent = by_id.get(parent.parent_id) if parent.parent_id else None
        return " / ".join(reversed(parts))

    return {n.id: path_for(n) for n in nodes}


def _project_ids_by_node_id(
    db: Session,
    framework_id: int,
    *,
    latest_only: bool,
) -> dict[int, set[int]]:
    """Return distinct project id sets per framework node (direct mappings).

    Sets are based on ProjectVersionFrameworkNode mappings. When latest_only=True,
    only latest versions contribute.
    """

    q = (
        db.query(
            ProjectVersionFrameworkNode.framework_node_id.label("node_id"),
            Project.id.label("project_id"),
        )
        .select_from(ProjectVersionFrameworkNode)
        .join(
            ProjectVersion,
            ProjectVersion.id == ProjectVersionFrameworkNode.project_version_id,
        )
        .join(Project, Project.id == ProjectVersion.project_id)
        .join(
            FrameworkNode,
            FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
        )
        .filter(FrameworkNode.framework_id == framework_id)
    )
    if latest_only:
        q = q.filter(ProjectVersion.is_latest.is_(True))

    rows = q.distinct().all()
    out: dict[int, set[int]] = defaultdict(set)
    for r in rows:
        if r.node_id is None or r.project_id is None:
            continue
        out[int(r.node_id)].add(int(r.project_id))
    return dict(out)


def _project_name_by_id(db: Session, project_ids: set[int]) -> dict[int, str]:
    if not project_ids:
        return {}
    rows = (
        db.query(
            Project.id,
            func.coalesce(Project.display_name, Project.machine_name).label("name"),
        )
        .filter(Project.id.in_(sorted(project_ids)))
        .all()
    )
    return {int(r.id): str(r.name) for r in rows}


def _build_tree_with_counts(
    nodes: list[FrameworkNode],
    *,
    direct_project_ids_by_node_id: dict[int, set[int]],
    project_name_by_id: dict[int, str],
    list_limit: int = 50,
) -> list[dict]:
    """Build taxonomy tree with project counts.

    IMPORTANT: totals are computed as *distinct unions* across descendants (not naive sums),
    so parent counts do not over-count projects that appear in multiple sub-capabilities.

    Also includes project name lists to help the UI explain 'directly mapped' vs inherited.
    """

    children: dict[int | None, list[FrameworkNode]] = defaultdict(list)
    for n in nodes:
        children[n.parent_id].append(n)

    for pid, arr in children.items():
        arr.sort(
            key=lambda x: (int(x.sort_order or 0), (x.display_name or "").lower(), x.id)
        )

    def projects_payload(project_ids: set[int]) -> list[dict]:
        if not project_ids:
            return []
        ids = sorted(project_ids)
        truncated = False
        if list_limit and len(ids) > int(list_limit):
            ids = ids[: int(list_limit)]
            truncated = True
        payload = [
            {"id": int(pid), "name": project_name_by_id.get(int(pid), str(pid))}
            for pid in ids
        ]
        if truncated:
            payload.append(
                {"id": -1, "name": f"… (+{len(project_ids) - int(list_limit)} more)"}
            )
        return payload

    def build_node(n: FrameworkNode):
        child_payloads: list[dict] = []
        descendant_ids: set[int] = set()
        for ch in children.get(n.id, []):
            payload, child_total_ids, _child_desc = build_node(ch)
            child_payloads.append(payload)
            descendant_ids |= set(child_total_ids)

        direct_ids = set(direct_project_ids_by_node_id.get(int(n.id), set()))
        total_ids = direct_ids | descendant_ids

        payload = {
            "id": n.id,
            "key": n.key,
            "display_name": n.display_name,
            "description": n.description,
            "parent_id": n.parent_id,
            "level": n.level,
            "sort_order": n.sort_order,
            "project_count_direct": len(direct_ids),
            "project_count_descendants": len(descendant_ids),
            "project_count_total": len(total_ids),
            "projects_direct": projects_payload(direct_ids),
            "projects_total": projects_payload(total_ids),
            "children": child_payloads,
        }
        return payload, total_ids, descendant_ids

    def build(parent_id: int | None) -> list[dict]:
        out: list[dict] = []
        for n in children.get(parent_id, []):
            payload, _total_ids, _desc_ids = build_node(n)
            out.append(payload)
        return out

    return build(None)


def _require_framework_write(db: Session, user: User) -> None:
    if not has_permission(db, user, PERM_FRAMEWORK_WRITE):
        raise HTTPException(
            status_code=403, detail="Missing permission: framework.write"
        )


@router.get("/v1/frameworks")
def list_frameworks(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    ensure_default_frameworks(db)
    items = (
        db.query(Framework)
        .order_by(Framework.display_name.asc(), Framework.machine_name.asc())
        .all()
    )

    return {
        "items": [
            {
                "id": f.id,
                "machine_name": f.machine_name,
                "display_name": f.display_name,
                "description": f.description,
                "created_by_user_id": f.created_by_user_id,
            }
            for f in items
        ]
    }


@router.post("/v1/frameworks")
def create_framework(
    payload: FrameworkCreatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_framework_write(db, user)

    machine = payload.machine_name.strip().lower()
    if not machine:
        raise HTTPException(status_code=400, detail="machine_name is required")

    existing = (
        db.query(Framework).filter(Framework.machine_name == machine).one_or_none()
    )
    if existing:
        raise HTTPException(
            status_code=409, detail="Framework machine_name already exists"
        )

    fw = Framework(
        machine_name=machine,
        display_name=payload.display_name.strip(),
        description=(payload.description or None),
        created_by_user_id=user.id,
    )
    db.add(fw)
    db.commit()

    return {
        "id": fw.id,
        "machine_name": fw.machine_name,
        "display_name": fw.display_name,
        "description": fw.description,
        "created_by_user_id": fw.created_by_user_id,
    }


@router.get("/v1/frameworks/{framework_id}")
def get_framework(
    framework_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    fw = db.query(Framework).filter(Framework.id == framework_id).one_or_none()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    return {
        "id": fw.id,
        "machine_name": fw.machine_name,
        "display_name": fw.display_name,
        "description": fw.description,
        "created_by_user_id": fw.created_by_user_id,
    }


@router.put("/v1/frameworks/{framework_id}")
def update_framework(
    framework_id: int,
    payload: FrameworkUpdatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_framework_write(db, user)

    fw = db.query(Framework).filter(Framework.id == framework_id).one_or_none()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    if payload.machine_name is not None:
        machine = payload.machine_name.strip().lower()
        if not machine:
            raise HTTPException(status_code=400, detail="machine_name cannot be blank")
        if machine != fw.machine_name:
            conflict = (
                db.query(Framework)
                .filter(Framework.machine_name == machine)
                .one_or_none()
            )
            if conflict:
                raise HTTPException(
                    status_code=409, detail="Framework machine_name already exists"
                )
            fw.machine_name = machine

    if payload.display_name is not None:
        fw.display_name = payload.display_name.strip()

    if payload.description is not None:
        fw.description = payload.description or None

    db.add(fw)
    db.commit()

    return get_framework(framework_id=framework_id, db=db)


@router.delete("/v1/frameworks/{framework_id}")
def delete_framework(
    framework_id: int,
    force: bool = Query(False, description="Force delete even if referenced"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Delete a framework (and its taxonomy) if the caller is the owner or an admin.

    This cascades to framework nodes and any project-version mappings that reference those nodes.
    """

    _require_framework_write(db, user)

    fw = db.query(Framework).filter(Framework.id == framework_id).one_or_none()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    effective_role = attach_effective_role(db, user)
    is_admin = effective_role == ROLE_ADMIN

    is_owner = fw.created_by_user_id is not None and int(fw.created_by_user_id) == int(
        user.id
    )
    if not (is_admin or is_owner):
        raise HTTPException(
            status_code=403,
            detail="Only the framework owner or an admin can delete this framework",
        )

    # Safety: if referenced, require force=true.
    mapped_count = (
        db.query(ProjectVersionFrameworkNode)
        .join(
            FrameworkNode,
            FrameworkNode.id == ProjectVersionFrameworkNode.framework_node_id,
        )
        .filter(FrameworkNode.framework_id == framework_id)
        .count()
    )
    manifests_count = (
        db.query(Manifest).filter(Manifest.framework_id == framework_id).count()
    )
    if (mapped_count or manifests_count) and not force:
        raise HTTPException(
            status_code=409,
            detail=f"Framework is referenced by {mapped_count} project mappings and {manifests_count} manifests. Retry with ?force=true to delete anyway.",
        )

    db.delete(fw)
    db.commit()

    return {"ok": True}


@router.get("/v1/frameworks/{framework_id}/nodes")
def get_framework_nodes(
    framework_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    fw = db.query(Framework).filter(Framework.id == framework_id).one_or_none()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    nodes = (
        db.query(FrameworkNode)
        .filter(FrameworkNode.framework_id == framework_id)
        .order_by(
            FrameworkNode.level.asc(),
            FrameworkNode.sort_order.asc(),
            FrameworkNode.display_name.asc(),
        )
        .all()
    )

    tree = _build_tree(nodes)
    paths = _paths_by_id(nodes)

    items = [
        {
            "id": n.id,
            "key": n.key,
            "display_name": n.display_name,
            "description": n.description,
            "parent_id": n.parent_id,
            "level": n.level,
            "sort_order": n.sort_order,
            "path": paths.get(n.id, n.display_name),
        }
        for n in nodes
    ]

    return {
        "framework": {
            "id": fw.id,
            "machine_name": fw.machine_name,
            "display_name": fw.display_name,
        },
        "tree": tree,
        "items": items,
    }


@router.get("/v1/frameworks/{framework_id}/catalogue")
def get_framework_catalogue(
    framework_id: int,
    latest_only: bool = Query(
        True, description="Count projects mapped via latest versions only"
    ),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Framework taxonomy plus project counts per node.

    Used by the "Find projects" treemap catalogue.
    """

    fw = db.query(Framework).filter(Framework.id == framework_id).one_or_none()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    nodes = (
        db.query(FrameworkNode)
        .filter(FrameworkNode.framework_id == framework_id)
        .order_by(
            FrameworkNode.level.asc(),
            FrameworkNode.sort_order.asc(),
            FrameworkNode.display_name.asc(),
        )
        .all()
    )

    paths = _paths_by_id(nodes)
    direct_ids_by_id = _project_ids_by_node_id(
        db, framework_id, latest_only=bool(latest_only)
    )
    all_project_ids: set[int] = set()
    for s in direct_ids_by_id.values():
        all_project_ids |= set(s)
    project_name_by_id = _project_name_by_id(db, all_project_ids)
    tree = _build_tree_with_counts(
        nodes,
        direct_project_ids_by_node_id=direct_ids_by_id,
        project_name_by_id=project_name_by_id,
        list_limit=50,
    )

    # Flatten for lookup by node id.
    by_id: dict[int, dict] = {}
    stack = list(tree)
    while stack:
        node = stack.pop()
        nid = node.get("id")
        if nid is not None:
            by_id[int(nid)] = node
        for ch in node.get("children") or []:
            stack.append(ch)

    items = [
        {
            "id": n.id,
            "key": n.key,
            "display_name": n.display_name,
            "description": n.description,
            "parent_id": n.parent_id,
            "level": n.level,
            "sort_order": n.sort_order,
            "path": paths.get(n.id, n.display_name),
            "project_count_direct": int(
                (by_id.get(int(n.id)) or {}).get("project_count_direct") or 0
            ),
            "project_count_descendants": int(
                (by_id.get(int(n.id)) or {}).get("project_count_descendants") or 0
            ),
            "project_count_total": int(
                (by_id.get(int(n.id)) or {}).get("project_count_total") or 0
            ),
            "projects_direct": (by_id.get(int(n.id)) or {}).get("projects_direct")
            or [],
            "projects_total": (by_id.get(int(n.id)) or {}).get("projects_total") or [],
        }
        for n in nodes
    ]

    return {
        "framework": {
            "id": fw.id,
            "machine_name": fw.machine_name,
            "display_name": fw.display_name,
        },
        "tree": tree,
        "items": items,
        "meta": {
            "latest_only": bool(latest_only),
        },
    }


@router.post("/v1/frameworks/{framework_id}/nodes")
def create_framework_node(
    framework_id: int,
    payload: FrameworkNodeCreatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_framework_write(db, user)

    fw = db.query(Framework).filter(Framework.id == framework_id).one_or_none()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    key = payload.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="key is required")

    existing = (
        db.query(FrameworkNode)
        .filter(FrameworkNode.framework_id == framework_id, FrameworkNode.key == key)
        .one_or_none()
    )
    if existing:
        raise HTTPException(
            status_code=409, detail="Node key already exists in this framework"
        )

    parent_id = payload.parent_id
    level = 0
    if parent_id:
        parent = (
            db.query(FrameworkNode)
            .filter(
                FrameworkNode.id == parent_id,
                FrameworkNode.framework_id == framework_id,
            )
            .one_or_none()
        )
        if not parent:
            raise HTTPException(
                status_code=400, detail="parent_id is invalid for this framework"
            )
        level = int(parent.level or 0) + 1

    node = FrameworkNode(
        framework_id=framework_id,
        key=key,
        display_name=payload.display_name.strip(),
        description=(payload.description or None),
        parent_id=parent_id or None,
        sort_order=int(payload.sort_order or 0),
        level=level,
    )
    db.add(node)
    db.commit()

    return {
        "id": node.id,
        "framework_id": node.framework_id,
        "key": node.key,
        "display_name": node.display_name,
        "description": node.description,
        "parent_id": node.parent_id,
        "level": node.level,
        "sort_order": node.sort_order,
    }


@router.put("/v1/framework-nodes/{node_id}")
def update_framework_node(
    node_id: int,
    payload: FrameworkNodeUpdatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_framework_write(db, user)

    node = db.query(FrameworkNode).filter(FrameworkNode.id == node_id).one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    if payload.key is not None:
        key = payload.key.strip()
        if not key:
            raise HTTPException(status_code=400, detail="key cannot be blank")
        if key != node.key:
            conflict = (
                db.query(FrameworkNode)
                .filter(
                    FrameworkNode.framework_id == node.framework_id,
                    FrameworkNode.key == key,
                )
                .one_or_none()
            )
            if conflict:
                raise HTTPException(
                    status_code=409, detail="Node key already exists in this framework"
                )
            node.key = key

    if payload.display_name is not None:
        node.display_name = payload.display_name.strip()

    if payload.description is not None:
        node.description = payload.description or None

    if payload.sort_order is not None:
        node.sort_order = int(payload.sort_order)

    # parent changes are allowed but level must be recomputed.
    if payload.parent_id is not None:
        parent_id = payload.parent_id
        level = 0
        if parent_id:
            parent = (
                db.query(FrameworkNode)
                .filter(
                    FrameworkNode.id == parent_id,
                    FrameworkNode.framework_id == node.framework_id,
                )
                .one_or_none()
            )
            if not parent:
                raise HTTPException(
                    status_code=400, detail="parent_id is invalid for this framework"
                )
            if parent.id == node.id:
                raise HTTPException(
                    status_code=400, detail="Node cannot be its own parent"
                )
            # Walking up from the new parent must never reach this node: a
            # node under its own descendant would form a cycle.
            ancestor: FrameworkNode | None = parent
            seen: set[int] = set()
            while ancestor is not None and ancestor.id not in seen:
                if ancestor.id == node.id:
                    raise HTTPException(
                        status_code=400,
                        detail="Node cannot move under one of its own descendants",
                    )
                seen.add(ancestor.id)
                ancestor = (
                    db.get(FrameworkNode, ancestor.parent_id)
                    if ancestor.parent_id
                    else None
                )
            level = int(parent.level or 0) + 1
        node.parent_id = parent_id or None
        node.level = level
        # The moved node's descendants move with it.
        pending = [node]
        while pending:
            current = pending.pop()
            for child in db.query(FrameworkNode).filter(
                FrameworkNode.parent_id == current.id
            ):
                child.level = int(current.level or 0) + 1
                pending.append(child)

    db.add(node)
    db.commit()

    return {
        "id": node.id,
        "framework_id": node.framework_id,
        "key": node.key,
        "display_name": node.display_name,
        "description": node.description,
        "parent_id": node.parent_id,
        "level": node.level,
        "sort_order": node.sort_order,
    }


@router.delete("/v1/framework-nodes/{node_id}")
def delete_framework_node(
    node_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_framework_write(db, user)

    node = db.query(FrameworkNode).filter(FrameworkNode.id == node_id).one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    # prevent deletion if children exist
    child = (
        db.query(FrameworkNode.id).filter(FrameworkNode.parent_id == node_id).first()
    )
    if child:
        raise HTTPException(
            status_code=409, detail="Node has children; delete/move children first"
        )

    db.delete(node)
    db.commit()
    return {"ok": True}
