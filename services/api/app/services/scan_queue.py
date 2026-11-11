"""Queueing dependency scans and release-feed imports for the workers.

A scan is queued in the database first, then handed to the broker. The beat
dispatcher (tasks.dependency_queue) hands over any scan the broker refused,
and a scan task runs only from the queued state, so a scan handed over twice
(by its caller and the dispatcher) runs once.
"""

from __future__ import annotations

import logging

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


def launch_dependency_scan(version_id: int) -> bool:
    """Hand a queued scan to the workers now; False when the broker refused it.

    A refused scan stays queued, and the beat dispatcher hands it over later.
    """

    from app.tasks.dependency_discovery import discover_project_version_dependencies

    try:
        discover_project_version_dependencies.delay(version_id)
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
        discover_project_release_feed.delay(project_id)
    except Exception:
        logger.exception(
            "Broker refused the release discovery of project_id=%s", project_id
        )
        return False
    return True
