"""Queueing dependency scans and release-feed imports for the workers.

A scan is queued in the database first, then handed to the broker. The beat
dispatcher (tasks.dependency_queue) hands over any scan the broker refused,
and a scan task runs only from the queued state, so a scan handed over twice
(by its caller and the dispatcher) runs once.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.features import is_enabled
from app.db.models import ProjectVersion

logger = logging.getLogger(__name__)


def mark_scan_queued(version: ProjectVersion) -> None:
    """Queue a fresh scan of a version's source.

    The previous results stay visible until the new scan replaces them, so a
    dashboard never shows a version as empty between scans.
    """

    version.dependency_discovery_status = "queued"
    version.dependency_discovery_error = None
    version.dependency_discovery_started_at = None
    version.dependency_discovery_finished_at = None


def automatic_scans_enabled(db: Session) -> bool:
    """Whether the installation scans versions without being asked."""

    return (
        is_enabled("dependency_scans", db)
        and settings.dependency_discovery_enabled
        and settings.dependency_discovery_auto_enqueue
    )


def queue_latest_version_scan(db: Session, project_id: int) -> int | None:
    """Queue the first scan of the project's Latest version when it lacks one.

    A version reaches Latest by several routes: published from a draft,
    marked Latest by hand, promoted when another version is deleted, or
    published by the release feed. Each route calls this after settling the
    marker, so the version the dashboard reports on is always scanned. A
    version that has been scanned, or whose scan is in flight, is left alone.
    Returns the version's id for launch_dependency_scan once the caller has
    committed, else None.
    """

    if not automatic_scans_enabled(db):
        return None
    latest = (
        db.query(ProjectVersion)
        .filter(ProjectVersion.project_id == project_id)
        .filter(ProjectVersion.is_draft.is_(False))
        .filter(ProjectVersion.is_latest.is_(True))
        .order_by(ProjectVersion.id.desc())
        .first()
    )
    if latest is None or latest.dependency_discovery_status != "not_run":
        return None
    if not (latest.link_to_source_code or "").strip():
        return None
    mark_scan_queued(latest)
    return latest.id


def launch_dependency_scan(version_id: int) -> bool:
    """Hand a queued scan to the workers now; False when the broker refused it.

    A refused scan stays queued, and the beat dispatcher hands it over later.
    """

    from app.tasks.dependency_discovery import discover_project_version_dependencies

    try:
        # One attempt: a request never waits on the broker's reconnection
        # retries, and the dispatcher hands over a scan that stayed queued.
        discover_project_version_dependencies.apply_async((version_id,), retry=False)
    except Exception:
        logger.exception(
            "Broker refused the dependency scan of project_version_id=%s; "
            "the queued-scan dispatcher retries it",
            version_id,
        )
        return False
    return True


def launch_release_discovery(project_id: int) -> bool:
    """Import a project's whole release feed; False when the broker refused it.

    The regular feed poll still reaches the project on its next beat.
    """

    from app.tasks.release_feed import discover_project_release_feed

    try:
        discover_project_release_feed.apply_async((project_id,), retry=False)
    except Exception:
        logger.exception(
            "Broker refused the release discovery of project_id=%s", project_id
        )
        return False
    return True
