from __future__ import annotations

from fastapi import HTTPException

from app.core.config import settings

FEATURE_KEYS = (
    "frameworks",
    "manifests",
    "questions",
    "dependency_scans",
    "comparisons",
    "release_feed",
)


def is_enabled(key: str) -> bool:
    """Whether the named product feature is switched on for this installation.

    Disabled features reject their operational API routes and background
    tasks with 404, so the deployment answers as though the feature does not
    exist, and the UI hides its pages.
    """

    return bool(getattr(settings, f"feature_{key}", True))


def public_dict() -> dict[str, bool]:
    return {key: is_enabled(key) for key in FEATURE_KEYS}


def require_feature(key: str):
    """FastAPI dependency factory: 404 when the feature is off."""

    def _dependency() -> None:
        if not is_enabled(key):
            raise HTTPException(status_code=404, detail="Feature not available")

    return _dependency
