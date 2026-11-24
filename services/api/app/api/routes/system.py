from __future__ import annotations

from fastapi import Depends
from mosp.api.routing import Router
from mosp.security.auth import require_authenticated
from sqlalchemy.orm import Session

from app.core.features import public_dict
from app.db.models import User
from app.db.session import get_db

router = Router()


@router.get("/v1/system/health")
def health():
    return {"ok": True}


@router.get("/v1/system/features")
def features(
    user: User = Depends(require_authenticated), db: Session = Depends(get_db)
):
    """Installation feature switches for the UI; authentication required."""
    return public_dict(db)
