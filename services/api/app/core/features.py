"""Installation features: which optional product areas this OSPMAE offers.

Ported from KEEN's ``app/services/features.py``; keep the two aligned.
Administrators switch features on and off on the Administration page, where
each save is checked against the configuration version it started from. The
deployment's ``OSPMAE_FEATURE_*`` settings are a ceiling: a feature the
deployment turns off stays off whatever the stored setting says, and its
switch cannot be turned on from the page.

A disabled feature answers 404 on its operational API routes and skips its
background tasks, so the installation behaves as though it does not exist,
and the UI hides its pages. Permissions remain independently authoritative,
and existing records are kept while a feature is off.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from weakref import WeakKeyDictionary

from fastapi import Depends, HTTPException
from sqlalchemy import Connection, Engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import ManagedConfiguration, ManagedConfigurationRevision
from app.db.session import SessionLocal, get_db

CONFIG_NAME = "features"

# Ordered parents precede children. Keys are stable API identifiers.
DEFINITIONS: tuple[tuple[str, str, str | None], ...] = (
    ("frameworks", "Frameworks and capability mapping", None),
    ("manifests", "Manifests", None),
    ("comparisons", "Project comparisons", None),
    ("questions", "Questions and replies", None),
    ("dependency_scans", "Dependency scans and vulnerabilities", None),
    ("release_feed", "Release feeds", None),
)
FEATURE_KEYS = tuple(key for key, _, _ in DEFINITIONS)
KEYS = frozenset(FEATURE_KEYS)


def deployment_allows(key: str) -> bool:
    """Whether the deployment's OSPMAE_FEATURE_* setting leaves the feature on."""
    return bool(getattr(settings, f"feature_{key}", True))


@dataclass(frozen=True)
class FeatureState:
    version: int
    configured: tuple[tuple[str, bool], ...]
    effective: tuple[tuple[str, bool], ...]
    deployment: tuple[tuple[str, bool], ...]

    def enabled(self, key: str) -> bool:
        if key not in KEYS:
            raise ValueError("Unknown feature")
        return dict(self.effective)[key]

    def public(self) -> dict[str, bool]:
        return dict(self.effective)

    def admin(self) -> dict:
        return {
            "version": self.version,
            "enabled": dict(self.effective),
            "configured": dict(self.configured),
            "deployment": dict(self.deployment),
            "items": [
                {"key": key, "label": label, "parent": parent}
                for key, label, parent in DEFINITIONS
            ],
        }


def compile_state(version: int, document) -> FeatureState:
    if (
        not isinstance(document, dict)
        or set(document) - KEYS
        or any(type(v) is not bool for v in document.values())
    ):
        raise HTTPException(503, "Feature configuration is unavailable.")
    configured = {key: document.get(key, True) for key in FEATURE_KEYS}
    deployment = {key: deployment_allows(key) for key in FEATURE_KEYS}
    effective: dict[str, bool] = {}
    for key, _, parent in DEFINITIONS:
        effective[key] = (
            configured[key] and deployment[key] and (not parent or effective[parent])
        )
    return FeatureState(
        version,
        tuple(configured.items()),
        tuple(effective.items()),
        tuple(deployment.items()),
    )


# One immutable state per live database engine and deployment ceiling. No user
# identities, secrets or authorisation decisions are cached; each session
# checks the stored version once, so every process sees a change at once.
_cache: WeakKeyDictionary[Engine | Connection, FeatureState] = WeakKeyDictionary()
_cache_lock = RLock()


def state(db: Session, *, refresh: bool = False) -> FeatureState:
    if not refresh and "ospmae_features" in db.info:
        return db.info["ospmae_features"]
    version = db.scalar(
        select(ManagedConfiguration.version).where(
            ManagedConfiguration.name == CONFIG_NAME
        )
    )
    engine = db.get_bind()
    deployment = tuple((key, deployment_allows(key)) for key in FEATURE_KEYS)
    with _cache_lock:
        cached = _cache.get(engine)
    if (
        cached is None
        or cached.version != (version or 0)
        or cached.deployment != deployment
    ):
        row = (
            db.execute(
                select(
                    ManagedConfiguration.version, ManagedConfiguration.document
                ).where(ManagedConfiguration.name == CONFIG_NAME)
            ).first()
            if version is not None
            else None
        )
        cached = (
            compile_state(row.version, row.document) if row else compile_state(0, {})
        )
        with _cache_lock:
            _cache[engine] = cached
    db.info["ospmae_features"] = cached
    return cached


def is_enabled(key: str, db: Session | None = None) -> bool:
    """Whether the named feature is on for this installation right now."""
    if key not in KEYS:
        raise ValueError("Unknown feature")
    if not deployment_allows(key):
        return False
    if db is not None:
        return state(db).enabled(key)
    with SessionLocal() as session:
        return state(session).enabled(key)


def public_dict(db: Session | None = None) -> dict[str, bool]:
    if db is not None:
        return state(db).public()
    with SessionLocal() as session:
        return state(session).public()


def require_feature(key: str):
    """FastAPI dependency factory: 404 when the feature is off."""

    if key not in KEYS:
        raise ValueError("Unknown feature")

    def _dependency(db: Session = Depends(get_db)) -> None:
        if not is_enabled(key, db):
            raise HTTPException(status_code=404, detail="Feature not available")

    return _dependency


def update(db: Session, user, version, changes) -> dict:
    """Save an administrator's changes against the version they started from."""
    if (
        type(version) is not int
        or version < 0
        or not isinstance(changes, dict)
        or not changes
        or set(changes) - KEYS
        or any(type(v) is not bool for v in changes.values())
    ):
        raise HTTPException(
            422, "Supply a configuration version and known boolean feature settings."
        )
    for key, on in changes.items():
        if on and not deployment_allows(key):
            raise HTTPException(
                409,
                f"This deployment turns {key} off "
                f"(OSPMAE_FEATURE_{key.upper()}=false); it cannot be turned on here.",
            )
    row = (
        db.query(ManagedConfiguration)
        .filter_by(name=CONFIG_NAME)
        .with_for_update()
        .one_or_none()
    )
    if (row.version if row else 0) != version:
        raise HTTPException(
            409, "Features changed in another session. Reload before saving."
        )
    document = dict(compile_state(version, row.document if row else {}).configured)
    document.update(changes)
    updated = compile_state(version + 1, document)
    if row is None:
        row = ManagedConfiguration(
            name=CONFIG_NAME,
            document=document,
            version=updated.version,
            updated_by=user.id,
        )
        db.add(row)
    else:
        row.document, row.version, row.updated_by = document, updated.version, user.id
    db.add(
        ManagedConfigurationRevision(
            name=CONFIG_NAME,
            document=document,
            version=updated.version,
            updated_by=user.id,
        )
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            409, "Features changed in another session. Reload before saving."
        ) from None
    db.info.pop("ospmae_features", None)
    with _cache_lock:
        _cache.pop(db.get_bind(), None)
    return updated.admin()
