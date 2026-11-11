from __future__ import annotations

from celery.utils.log import get_task_logger

from app.celery_app import celery_app
from app.db.models import ProjectVersion
from app.db.session import SessionLocal

log = get_task_logger(__name__)


@celery_app.task(
    name="app.tasks.dependency_queue.dispatch_queued_dependency_discoveries"
)
def dispatch_queued_dependency_discoveries(limit: int = 10) -> dict:
    """Kick off discovery tasks for any ProjectVersions marked as queued."""

    from app.core.features import is_enabled

    if not is_enabled("dependency_scans"):
        return {"ok": False, "reason": "dependency_scans feature disabled"}

    db = SessionLocal()
    try:
        queued = (
            db.query(ProjectVersion)
            .filter(ProjectVersion.dependency_discovery_status == "queued")
            .filter(ProjectVersion.link_to_source_code.isnot(None))
            .order_by(ProjectVersion.updated_at.desc())
            .limit(int(limit or 10))
            .all()
        )
        from app.services.scan_queue import launch_dependency_scan

        launched = sum(launch_dependency_scan(pv.id) for pv in queued)
        return {"queued": len(queued), "launched": launched}
    finally:
        db.close()
