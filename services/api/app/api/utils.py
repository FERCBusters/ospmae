from __future__ import annotations

from fastapi import HTTPException


def require_non_empty(value: str, field: str) -> str:
    v = (value or "").strip()
    if not v:
        raise HTTPException(status_code=400, detail=f"{field} is required")
    return v


def normalize_tags(items: list[str] | None) -> list[str]:
    if not items:
        return []
    out: list[str] = []
    seen = set()
    for raw in items:
        s = (raw or "").strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out
