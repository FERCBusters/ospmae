from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.features import public_dict
from app.db.models import User
from app.db.session import get_db
from app.security.auth import get_current_user

router = APIRouter()


@router.get("/v1/system/health")
def health():
    return {"ok": True}


@router.get("/v1/system/features")
def features(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Installation feature switches for the UI; authentication required."""
    return public_dict(db)
