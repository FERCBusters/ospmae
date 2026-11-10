from __future__ import annotations

from datetime import timedelta

from celery import Celery

from app.core.config import settings


def _broker_url() -> str:
    explicit = str(getattr(settings, "celery_broker_url", "") or "").strip()
    if explicit:
        return explicit
    # Default for local docker-compose
    return "redis://redis:6379/0"


def _result_backend() -> str:
    explicit = str(getattr(settings, "celery_result_backend", "") or "").strip()
    if explicit:
        return explicit
    return "redis://redis:6379/1"


celery_app = Celery(
    "ospmae",
    broker=_broker_url(),
    backend=_result_backend(),
    include=[
        "app.tasks.dependency_discovery",
        "app.tasks.dependency_queue",
        "app.tasks.release_feed",
    ],
)

celery_app.conf.update(
    timezone=str(getattr(settings, "celery_timezone", "UTC") or "UTC"),
    enable_utc=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    worker_prefetch_multiplier=1,
    task_acks_late=False,
)


# Periodically dispatch queued dependency discovery jobs. The schedule and
# the tasks themselves are disabled when the dependency-scan feature is off.
from app.core.features import is_enabled as _feature_on

if bool(getattr(settings, "dependency_discovery_enabled", True)) and _feature_on(
    "dependency_scans"
):
    celery_app.conf.beat_schedule = {
        **(celery_app.conf.beat_schedule or {}),
        "dispatch-queued-dependency-discoveries": {
            "task": "app.tasks.dependency_queue.dispatch_queued_dependency_discoveries",
            "schedule": timedelta(minutes=1),
        },
    }


# Periodically poll project release feeds and create draft versions.
if bool(getattr(settings, "release_feed_poll_enabled", True)) and _feature_on(
    "release_feed"
):
    minutes = int(getattr(settings, "release_feed_poll_minutes", 15) or 15)
    if minutes < 1:
        minutes = 15
    celery_app.conf.beat_schedule = {
        **(celery_app.conf.beat_schedule or {}),
        "poll-project-release-feeds": {
            "task": "app.tasks.release_feed.poll_release_feeds",
            "schedule": timedelta(minutes=minutes),
        },
    }


# Housekeeping: expired login states, used/expired reset and verification
# tokens and stale rate-limit ledger rows never accumulate without bound.
celery_app.conf.beat_schedule = {
    **(celery_app.conf.beat_schedule or {}),
    "sweep-expired-rows": {
        "task": "app.tasks.maintenance.sweep_expired_rows",
        "schedule": timedelta(minutes=15),
    },
}
