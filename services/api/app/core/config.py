from __future__ import annotations

from mosp.config import MospSettings
from pydantic import Field
from pydantic_settings import SettingsConfigDict


class Settings(MospSettings):
    """OSPMAE's settings: mosp's (mosp.config.MospSettings) and OSPMAE's own."""

    model_config = SettingsConfigDict(
        env_prefix="OSPMAE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # OSPMAE's names and defaults for settings mosp defines.
    session_cookie_name: str = Field(default="ospmae_session")
    session_ttl_seconds: int = Field(default=60 * 60 * 12)
    csrf_cookie_name: str = Field(default="ospmae_csrf")
    smtp_from_name: str = Field(default="OSPMAE")
    audit_log_retention_days: int = Field(default=90, ge=0, le=36500)

    app_title: str = Field(default="UWRA Project Catalog")

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8080)

    # ---------------------------------------------------------------------
    # Background jobs (Celery)
    # ---------------------------------------------------------------------
    celery_broker_url: str = Field(default="")
    celery_timezone: str = Field(default="UTC")
    # How long a worker task may run before it is stopped: every task, then
    # the two kinds that clone, scan or fetch for longer.
    task_time_limit_seconds: int = Field(default=900, ge=120)
    scan_task_time_limit_seconds: int = Field(default=1800, ge=120)
    feed_task_time_limit_seconds: int = Field(default=1800, ge=120)

    # ---------------------------------------------------------------------
    # Release feed polling (RSS/Atom)
    # ---------------------------------------------------------------------
    release_feed_poll_enabled: bool = Field(default=True)
    release_feed_poll_minutes: int = Field(default=15)

    # Safety limits for fetching/parsing feeds
    release_feed_max_bytes: int = Field(default=2_000_000)
    release_feed_max_redirects: int = Field(default=3)

    # ---------------------------------------------------------------------
    # Installation feature switches
    # ---------------------------------------------------------------------
    # Each switch turns an optional product area off entirely: its routes
    # answer 404, its background tasks become no-ops and the UI hides its
    # pages. Authentication, account security and administration stay on.
    feature_frameworks: bool = Field(default=True)
    feature_manifests: bool = Field(default=True)
    feature_questions: bool = Field(default=True)
    feature_dependency_scans: bool = Field(default=True)
    feature_comparisons: bool = Field(default=True)
    feature_release_feed: bool = Field(default=True)

    # ---------------------------------------------------------------------
    # Dependency discovery
    # ---------------------------------------------------------------------
    dependency_discovery_enabled: bool = Field(default=True)
    dependency_discovery_auto_enqueue: bool = Field(default=True)

    # Optional hostname allowlist (comma-separated). Empty means allow all.
    dependency_discovery_allowed_hosts: str = Field(
        default="github.com,gitlab.com,codeberg.org"
    )

    # Safety limits
    dependency_discovery_max_file_bytes: int = Field(default=5_000_000)
    dependency_discovery_max_files: int = Field(default=2500)
    dependency_discovery_clone_timeout_seconds: int = Field(default=180)

    # Optional Syft dependency cataloging (requires the syft binary in the worker image).
    # When enabled, Syft supplies the full package inventory and the existing
    # lockfile parsers act as supplemental/fallback sources.
    syft_enabled: bool = Field(default=True)
    syft_cmd: str = Field(default="syft")
    syft_timeout_seconds: int = Field(default=300)

    # Optional Grype vulnerability scan (requires the grype binary in the worker image).
    # Dependency discovery still works when this is disabled; only vulnerability
    # refreshes are skipped.
    grype_enabled: bool = Field(default=False)
    grype_cmd: str = Field(default="grype")
    grype_timeout_seconds: int = Field(default=300)


settings = Settings()
