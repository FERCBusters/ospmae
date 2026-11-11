"""Branch tracking: a project that follows one branch head instead of releases.

A tracked project keeps a single version row whose label is the branch name.
That row is the project's Latest version, points at the tracked repository,
and is re-cloned and scanned every ``branch_poll_interval_hours``: the poller
in app/tasks/branch_tracking.py marks it queued and the existing discovery
dispatcher runs the scan, which clones exactly that branch head.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import Project, ProjectVersion, ProjectVersionFrameworkNode
from app.services.versioning import set_latest_version

# The re-scan interval is bounded below so a project re-clones at most hourly.
MIN_POLL_INTERVAL_HOURS = 1
MAX_POLL_INTERVAL_HOURS = 720
DEFAULT_POLL_INTERVAL_HOURS = 24

# A scan still "running" after this long lost its worker; the next poll
# queues it again instead of leaving the branch unscanned for good.
STALE_RUNNING_AFTER = timedelta(hours=6)

_IN_FLIGHT = {"queued", "running"}


def is_tracking(project: Project) -> bool:
    return bool(
        project.track_branch and project.tracked_branch and project.tracked_repo_url
    )


def is_branch_version(project: Project, version: ProjectVersion) -> bool:
    """Whether this version row stands for the project's tracked branch."""

    return is_tracking(project) and version.version == project.tracked_branch


def branch_version(db: Session, project: Project) -> ProjectVersion | None:
    if not is_tracking(project):
        return None
    return (
        db.query(ProjectVersion)
        .filter(ProjectVersion.project_id == project.id)
        .filter(ProjectVersion.version == project.tracked_branch)
        .one_or_none()
    )


def ensure_branch_version(db: Session, project: Project) -> tuple[ProjectVersion, bool]:
    """Create or refresh the version row for the tracked branch.

    A new row inherits the framework mappings of the version it replaces as
    Latest, the way release-feed drafts inherit theirs. The row is always
    published, points at the tracked repository and becomes Latest. Returns
    the row and whether it was created.
    """

    if not is_tracking(project):
        raise ValueError("Project does not track a branch")

    version = branch_version(db, project)
    created = version is None
    if version is None:
        previous_latest = (
            db.query(ProjectVersion)
            .filter(ProjectVersion.project_id == project.id)
            .filter(ProjectVersion.is_draft.is_(False))
            .filter(ProjectVersion.is_latest.is_(True))
            .first()
        )
        version = ProjectVersion(
            project_id=project.id,
            version=project.tracked_branch,
            link_to_source_code=project.tracked_repo_url,
            notes=f"Tracks the head of branch {project.tracked_branch}.",
            is_draft=False,
            is_latest=False,
        )
        db.add(version)
        db.flush()
        if previous_latest is not None:
            inherited = (
                db.query(ProjectVersionFrameworkNode.framework_node_id)
                .filter(
                    ProjectVersionFrameworkNode.project_version_id == previous_latest.id
                )
                .all()
            )
            for (framework_node_id,) in inherited:
                db.add(
                    ProjectVersionFrameworkNode(
                        project_version_id=version.id,
                        framework_node_id=framework_node_id,
                    )
                )
    else:
        version.link_to_source_code = project.tracked_repo_url
        version.is_draft = False
    db.flush()
    set_latest_version(db, project.id, version.id)
    db.flush()
    db.refresh(version)
    return version, created


def scan_in_flight(version: ProjectVersion, now: datetime) -> bool:
    status = version.dependency_discovery_status
    if status not in _IN_FLIGHT:
        return False
    if status == "running":
        started = version.dependency_discovery_started_at
        if started is not None and now - started > STALE_RUNNING_AFTER:
            return False
    return True


def scan_due(project: Project, now: datetime) -> bool:
    if not is_tracking(project):
        return False
    last = project.branch_last_polled_at
    if last is None:
        return True
    hours = max(project.branch_poll_interval_hours, MIN_POLL_INTERVAL_HOURS)
    return now - last >= timedelta(hours=hours)
