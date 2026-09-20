from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OSPMAE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_title: str = Field(default="UWRA Project Catalog")

    database_url: str = Field(default="")

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8080)

    # session/cookie
    session_cookie_name: str = Field(default="ospmae_session")
    session_ttl_seconds: int = Field(default=60 * 60 * 12)
    cookie_secure: bool = Field(default=True)
    cookie_samesite: str = Field(default="lax")
    cookie_domain: str = Field(default="")

    # CSRF
    csrf_cookie_name: str = Field(default="ospmae_csrf")
    csrf_header_name: str = Field(default="X-CSRF-Token")
    csrf_cookie_samesite: str = Field(default="strict")

    # Reverse-proxy headers (X-Forwarded-Proto, X-Forwarded-For).
    # Enable only when the app is behind a trusted proxy/ingress that strips
    # client-supplied forwarded headers.
    trust_proxy_headers: bool = Field(default=False)

    # Native (local) username/password login
    local_auth_enabled: bool = Field(default=True)

    # ---------------------------------------------------------------------
    # Post-login redirect allowlist
    # ---------------------------------------------------------------------
    # Comma-separated list of hostnames that the UI is allowed to redirect to
    # after successful login when a `?next=` parameter is present.
    #
    # Security note:
    #   - Same-origin relative paths are always permitted.
    #   - Absolute URLs are only permitted when their hostname is in this list.
    #   - Leave empty to disallow all cross-origin redirects.
    login_redirect_allowed_hosts: str = Field(default="")

    # Public base URL for links in emails etc. Optional; if empty we derive
    # from the incoming request.
    public_base_url: str = Field(default="")

    # Optional admin email address (or comma-separated addresses) for operational
    # notifications such as newly auto-provisioned SSO users awaiting review.
    admin_notification_email: str = Field(default="")

    # ---------------------------------------------------------------------
    # Generic OpenID Connect provider
    # ---------------------------------------------------------------------
    oidc_sso_enabled: bool = Field(default=False)
    oidc_provider_label: str = Field(default="OpenID Connect")

    # Explicit endpoints are recommended and avoid discovery at runtime.
    oidc_discovery_url: str = Field(default="")
    oidc_authorization_endpoint: str = Field(default="")
    oidc_token_endpoint: str = Field(default="")
    oidc_jwks_uri: str = Field(default="")
    oidc_issuer: str = Field(default="")
    oidc_userinfo_endpoint: str = Field(default="")
    oidc_client_id: str = Field(default="")
    oidc_client_secret: str = Field(default="")
    oidc_scopes: str = Field(default="openid email profile")
    oidc_redirect_uri: str = Field(default="")
    oidc_end_session_endpoint: str = Field(default="")
    oidc_post_logout_redirect_uri: str = Field(default="")
    oidc_id_token_leeway_seconds: int = Field(default=60)
    oidc_auto_provision: bool = Field(default=False)
    oidc_auto_provision_role: str = Field(default="pending")
    oidc_auto_link_existing: bool = Field(default=True)
    oidc_allowed_email_domains: str = Field(default="")
    oidc_username_claims: str = Field(default="preferred_username,email")

    # Google OIDC. Defaults are suitable for consumer Google and any Google
    # Workspace domain; do not set a hosted-domain restriction unless you want
    # to intentionally limit access to specific domains.
    google_sso_enabled: bool = Field(default=False)
    google_provider_label: str = Field(default="Google")
    google_authorization_endpoint: str = Field(
        default="https://accounts.google.com/o/oauth2/v2/auth"
    )
    google_token_endpoint: str = Field(default="https://oauth2.googleapis.com/token")
    google_jwks_uri: str = Field(default="https://www.googleapis.com/oauth2/v3/certs")
    google_issuer: str = Field(
        default="https://accounts.google.com,accounts.google.com"
    )
    google_userinfo_endpoint: str = Field(
        default="https://openidconnect.googleapis.com/v1/userinfo"
    )
    google_client_id: str = Field(default="")
    google_client_secret: str = Field(default="")
    google_scopes: str = Field(default="openid email profile")
    google_redirect_uri: str = Field(default="")
    google_end_session_endpoint: str = Field(default="")
    google_post_logout_redirect_uri: str = Field(default="")
    google_auto_provision: bool = Field(default=False)
    google_auto_provision_role: str = Field(default="pending")
    google_auto_link_existing: bool = Field(default=True)
    google_allowed_email_domains: str = Field(default="")
    google_username_claims: str = Field(default="email")

    # GitHub OAuth. OSPMAE uses /user for the stable numeric account id and
    # /user/emails to resolve a verified primary email when possible.
    github_sso_enabled: bool = Field(default=False)
    github_provider_label: str = Field(default="GitHub")
    github_authorization_endpoint: str = Field(
        default="https://github.com/login/oauth/authorize"
    )
    github_token_endpoint: str = Field(
        default="https://github.com/login/oauth/access_token"
    )
    github_user_endpoint: str = Field(default="https://api.github.com/user")
    github_emails_endpoint: str = Field(default="https://api.github.com/user/emails")
    github_issuer: str = Field(default="https://github.com/login/oauth")
    github_client_id: str = Field(default="")
    github_client_secret: str = Field(default="")
    github_scopes: str = Field(default="read:user user:email")
    github_redirect_uri: str = Field(default="")
    github_auto_provision: bool = Field(default=False)
    github_auto_provision_role: str = Field(default="pending")
    github_auto_link_existing: bool = Field(default=True)
    github_allowed_email_domains: str = Field(default="")

    # Optional trusted remote user (for Vouch / SSO proxy mode)
    trust_remote_user: bool = Field(default=False)
    remote_user_header_name: str = Field(default="REMOTE_USER")

    # Optional: auto-create local users on first trusted remote-user login.
    # Useful in SSO-first deployments.
    remote_user_auto_provision: bool = Field(default=False)
    remote_user_auto_provision_role: str = Field(default="pending")

    # ---------------------------------------------------------------------
    # SMTP (password reset emails)
    # ---------------------------------------------------------------------
    smtp_host: str = Field(default="")
    smtp_port: int = Field(default=587)
    smtp_username: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_use_tls: bool = Field(default=True)  # STARTTLS
    smtp_use_ssl: bool = Field(default=False)  # SMTPS (465)
    smtp_timeout_seconds: int = Field(default=20)
    smtp_from_email: str = Field(default="")
    smtp_from_name: str = Field(default="OSPMAE")

    password_reset_token_ttl_minutes: int = Field(default=60)

    # ---------------------------------------------------------------------
    # Background jobs (Celery)
    # ---------------------------------------------------------------------
    celery_broker_url: str = Field(default="")
    celery_result_backend: str = Field(default="")
    celery_timezone: str = Field(default="UTC")

    # ---------------------------------------------------------------------
    # Release feed polling (RSS/Atom)
    # ---------------------------------------------------------------------
    release_feed_poll_enabled: bool = Field(default=True)
    release_feed_poll_minutes: int = Field(default=15)

    # Safety limits for fetching/parsing feeds
    release_feed_max_bytes: int = Field(default=2_000_000)
    release_feed_max_redirects: int = Field(default=3)

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
