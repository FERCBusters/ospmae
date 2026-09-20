from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/v1/system/health")
def health():
    return {"ok": True}
