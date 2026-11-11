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
        "app.tasks.branch_tracking",
        "app.tasks.dependency_discovery",
        "app.tasks.dependency_queue",
        "app.tasks.maintenance",
        "app.tasks.notifications",
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
    # Requests hand work to the broker and return; nothing reads a task's
    # result. Keeping results would make every hand-off reach the result store
    # too, and an unreachable store held a request for about twenty seconds.
    task_ignore_result=True,
    # A hand-off from a request waits at most this long for the broker; the
    # work stays queued in the database for the beat dispatchers.
    broker_connection_timeout=3,
)


# Periodically dispatch queued dependency discovery jobs. The schedule and
# the tasks themselves are disabled when the dependency-scan feature is off.
# The schedule follows the deployment ceiling (OSPMAE_FEATURE_*); each task
# checks the administrator setting when it runs, so switching a feature off on
# the Administration page stops its work without restarting beat.
from app.core.features import deployment_allows as _feature_on

if bool(getattr(settings, "dependency_discovery_enabled", True)) and _feature_on(
    "dependency_scans"
):
    celery_app.conf.beat_schedule = {
        **(celery_app.conf.beat_schedule or {}),
        "dispatch-queued-dependency-discoveries": {
            "task": "app.tasks.dependency_queue.dispatch_queued_dependency_discoveries",
            "schedule": timedelta(minutes=1),
        },
        # Tracked branches re-scan on their own hourly-or-longer interval; a
        # five-minute check keeps each one close to its due time.
        "poll-tracked-branches": {
            "task": "app.tasks.branch_tracking.poll_tracked_branches",
            "schedule": timedelta(minutes=5),
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

# The e-mail outbox drains on a short beat so queued mail never waits longer
# than minutes even when an interactive kick was missed.
_celery_beat = dict(celery_app.conf.beat_schedule or {})
_celery_beat["deliver-notifications"] = {
    "task": "app.tasks.notifications.deliver_notifications",
    "schedule": timedelta(minutes=2),
}
celery_app.conf.beat_schedule = _celery_beat
