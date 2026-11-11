from __future__ import annotations

from datetime import datetime
from typing import Any

from celery.utils.log import get_task_logger
from sqlalchemy import update
from sqlalchemy.engine import CursorResult

from app.celery_app import celery_app
from app.core.config import settings
from app.db.models import Project
from app.db.session import SessionLocal
from app.services.branch_tracking import (
    ensure_branch_version,
    is_tracking,
    scan_due,
    scan_in_flight,
)
from app.services.entity_changelog import (
    project_version_changelog_state,
    record_entity_changelog,
)
from app.services.scan_queue import mark_scan_queued

log = get_task_logger(__name__)


@celery_app.task(name="app.tasks.branch_tracking.poll_tracked_branches")
def poll_tracked_branches(limit_projects: int = 200) -> dict[str, Any]:
    """Queue a fresh scan for every tracked branch whose interval has passed.

    The scan itself is launched by the queued-discovery dispatcher, which
    clones the branch head; this task only decides what is due. Each project
    is claimed with a compare-and-set on its last poll time, so overlapping
    beat runs never queue the same branch twice.
    """

    from app.core.features import is_enabled

    if not is_enabled("dependency_scans"):
        return {"ok": False, "reason": "dependency_scans feature disabled"}
    if not settings.dependency_discovery_enabled:
        return {"ok": False, "reason": "dependency discovery disabled"}

    db = SessionLocal()
    checked = 0
    queued = 0
    try:
        now = datetime.utcnow()
        projects = (
            db.query(Project)
            .filter(Project.track_branch.is_(True))
            .filter(Project.tracked_branch.isnot(None))
            .filter(Project.tracked_repo_url.isnot(None))
            .order_by(Project.branch_last_polled_at.asc().nullsfirst(), Project.id)
            .limit(limit_projects)
            .all()
        )
        for project in projects:
            if not is_tracking(project) or not scan_due(project, now):
                continue
            checked += 1
            previous = project.branch_last_polled_at
            claim = db.execute(
                update(Project)
                .where(Project.id == project.id)
                .where(
                    Project.branch_last_polled_at.is_(None)
                    if previous is None
                    else Project.branch_last_polled_at == previous
                )
                .values(branch_last_polled_at=now)
                .execution_options(synchronize_session=False)
            )
            if not isinstance(claim, CursorResult) or claim.rowcount != 1:
                db.rollback()
                continue
            try:
                version, created = ensure_branch_version(db, project)
                if created:
                    record_entity_changelog(
                        db,
                        entity_type="project_version",
                        entity_id=version.id,
                        action="created",
                        before=None,
                        after=project_version_changelog_state(db, version),
                        user=None,
                        request_method="TASK",
                        request_path="branch_tracking.poll_tracked_branches",
                    )
                if not scan_in_flight(version, now):
                    mark_scan_queued(version)
                    queued += 1
                db.commit()
            except Exception:
                log.exception(
                    "Tracked branch poll failed for project_id=%s", project.id
                )
                db.rollback()
        return {"ok": True, "checked": checked, "queued": queued}
    finally:
        db.close()
