from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.capability_taxonomy import ensure_capability_taxonomy
from app.db.models import CapabilityNode, User
from app.db.session import get_db
from app.security.auth import get_current_user

router = APIRouter()


def _build_tree(nodes: list[CapabilityNode]) -> list[dict]:
    by_id: dict[int, dict] = {}
    roots: list[dict] = []

    sorted_nodes = sorted(
        nodes, key=lambda n: (n.level, n.sort_order, n.display_name.lower(), n.id)
    )

    for n in sorted_nodes:
        by_id[n.id] = {
            "id": n.id,
            "key": n.key,
            "display_name": n.display_name,
            "parent_id": n.parent_id,
            "level": n.level,
            "sort_order": n.sort_order,
            "children": [],
        }

    for node in sorted_nodes:
        payload = by_id[node.id]
        if node.parent_id and node.parent_id in by_id:
            by_id[node.parent_id]["children"].append(payload)
        else:
            roots.append(payload)

    return roots


def _paths_by_id(nodes: list[CapabilityNode]) -> dict[int, str]:
    by_id = {n.id: n for n in nodes}

    def path_for(node: CapabilityNode) -> str:
        parts = [node.display_name]
        parent_id = node.parent_id
        safety = 0
        while parent_id and parent_id in by_id and safety < 20:
            p = by_id[parent_id]
            parts.append(p.display_name)
            parent_id = p.parent_id
            safety += 1
        parts.reverse()
        return " > ".join(parts)

    return {n.id: path_for(n) for n in nodes}


@router.get("/v1/lookups")
def get_lookups(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_capability_taxonomy(db)

    nodes = (
        db.query(CapabilityNode)
        .order_by(
            CapabilityNode.level.asc(),
            CapabilityNode.sort_order.asc(),
            CapabilityNode.display_name.asc(),
        )
        .all()
    )
    paths = _paths_by_id(nodes)

    tree = _build_tree(nodes)
    flat = [
        {
            "id": n.id,
            "key": n.key,
            "display_name": n.display_name,
            "parent_id": n.parent_id,
            "level": n.level,
            "sort_order": n.sort_order,
            "path": paths.get(n.id, n.display_name),
        }
        for n in nodes
    ]

    return {
        "capability_tree": tree,
        "capabilities": flat,
    }
