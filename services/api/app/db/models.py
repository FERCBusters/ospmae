from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

# -----------------------------------------------------------------------------
# Auth / RBAC
# -----------------------------------------------------------------------------


class UserPreference(Base):
    __tablename__ = "user_preferences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )

    # Theme palette id from the shared design system; empty means the
    # application default until the account sets one.
    theme: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Generic framework palette overrides.
    # Keys are formatted as '<framework_machine_name>:<node_key>', for example:
    #   {
    #     "uwra:channel_tier": "#5b8def",
    #     "uwra:secure_storage": "#8b5cf6"
    #   }
    node_colors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    default_start_page: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # UI behaviour preferences (kept in DB so they roam across devices).
    sticky_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auto_apply_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(
        String(160), unique=True, index=True, nullable=False
    )
    email: Mapped[str | None] = mapped_column(
        String(255), unique=True, index=True, nullable=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # One of roles.py roles.
    role: Mapped[str] = mapped_column(String(50), default="viewer", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Local second factor: enabled means local sign-in needs the ceremony.
    # Every change to the enrolment bumps mfa_version, and a session whose
    # recorded version no longer matches is refused at resolution, so the
    # browser's other sessions end with the change. Wrong TOTP and recovery
    # codes are counted across sign-ins from mfa_code_failures_since; see
    # app/security/mfa.py.
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    mfa_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    mfa_totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_totp_last_step: Mapped[int] = mapped_column(
        Integer, nullable=False, default=-1, server_default="-1"
    )
    mfa_code_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    mfa_code_failures_since: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    preferences: Mapped[UserPreference | None] = relationship(
        "UserPreference", uselist=False, backref="user", cascade="all, delete-orphan"
    )

    shortcuts: Mapped[list["UserShortcut"]] = relationship(
        "UserShortcut", back_populates="user", cascade="all, delete-orphan"
    )

    emails: Mapped[list["UserEmail"]] = relationship(
        "UserEmail", back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # How the session was created. Used to decide whether logout should trigger
    # RP-initiated logout (OIDC) or just clear the local session.
    auth_method: Mapped[str] = mapped_column(
        String(20), nullable=False, default="local"
    )

    # The second-factor state this session was issued with: a session proves
    # the factor only when its recorded enrolment version matches the
    # account's and the ceremony completed. See local_session_allowed in
    # app/security/mfa.py.
    mfa_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    mfa_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    # Optional: store the last OIDC id_token for this session so we can pass
    # id_token_hint to the provider's end_session endpoint (if configured).
    oidc_id_token: Mapped[str | None] = mapped_column(Text, nullable=True)


class MfaCredential(Base):
    """A registered WebAuthn security key or passkey."""

    __tablename__ = "mfa_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MfaRecoveryCode(Base):
    """One-time recovery codes, stored hashed."""

    __tablename__ = "mfa_recovery_codes"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)


class MfaChallenge(Base):
    """A pending second-factor ceremony, never part of the session namespace.

    The browser holds only the unhashed token; the row is looked up by the
    token's SHA-256 digest and carries the account state it was issued for.
    """

    __tablename__ = "mfa_challenges"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    password_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


# -----------------------------------------------------------------------------
# Password resets (local auth)
# -----------------------------------------------------------------------------


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # SHA256 hex digest of the token sent to the user (store hash only).
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# -----------------------------------------------------------------------------
# Mailbox verification (self-asserted account emails)
# -----------------------------------------------------------------------------


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email_lower: Mapped[str] = mapped_column(String(255), nullable=False)

    # SHA256 hex digest of the token sent to the user (store hash only).
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# -----------------------------------------------------------------------------
# External identities (OIDC)
# -----------------------------------------------------------------------------


class UserIdentity(Base):
    __tablename__ = "user_identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Provider type, e.g. "oidc"
    provider: Mapped[str] = mapped_column(String(40), nullable=False, default="oidc")
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)

    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    preferred_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    claims: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_user_identity_issuer_subject"),
    )


class UserEmail(Base):
    __tablename__ = "user_emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    email_lower: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    # source: user, admin, sso, legacy_user, legacy_identity
    source: Mapped[str] = mapped_column(String(40), nullable=False, default="user")
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    user: Mapped[User] = relationship("User", back_populates="emails")


class OidcLoginState(Base):
    __tablename__ = "oidc_login_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    state: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    nonce: Mapped[str] = mapped_column(String(255), nullable=False)
    code_verifier: Mapped[str] = mapped_column(String(255), nullable=False)

    next_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class UserShortcut(Base):
    __tablename__ = "user_shortcuts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    user: Mapped["User"] = relationship("User", back_populates="shortcuts")

    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_user_shortcuts_user_name"),
    )


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(
        String(200), unique=True, index=True, nullable=False
    )

    # Optional group role (used in role inheritance).
    role: Mapped[str | None] = mapped_column(String(50), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Optional human-friendly description shown in the admin UI.
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserGroup(Base):
    __tablename__ = "user_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )

    __table_args__ = (UniqueConstraint("user_id", "group_id", name="uq_user_group"),)


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(
        String(120), unique=True, index=True, nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserPermission(Base):
    __tablename__ = "user_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("user_id", "permission_id", name="uq_user_permission"),
    )


class GroupPermission(Base):
    __tablename__ = "group_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )
    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("group_id", "permission_id", name="uq_group_permission"),
    )


# -----------------------------------------------------------------------------
# Frameworks & node taxonomies
# -----------------------------------------------------------------------------


class Framework(Base):
    __tablename__ = "frameworks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_name: Mapped[str] = mapped_column(
        String(160), unique=True, index=True, nullable=False
    )
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    created_by_user: Mapped[User | None] = relationship("User")

    nodes: Mapped[list["FrameworkNode"]] = relationship(
        "FrameworkNode", cascade="all, delete-orphan", back_populates="framework"
    )


class FrameworkNode(Base):
    __tablename__ = "framework_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework_id: Mapped[int] = mapped_column(
        ForeignKey("frameworks.id", ondelete="CASCADE"), nullable=False, index=True
    )

    key: Mapped[str] = mapped_column(String(160), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("framework_nodes.id", ondelete="CASCADE"), nullable=True
    )

    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    framework: Mapped[Framework] = relationship("Framework", back_populates="nodes")

    parent: Mapped["FrameworkNode | None"] = relationship(
        "FrameworkNode", remote_side="FrameworkNode.id", back_populates="children"
    )
    children: Mapped[list["FrameworkNode"]] = relationship(
        "FrameworkNode", back_populates="parent"
    )

    __table_args__ = (
        UniqueConstraint("framework_id", "key", name="uq_framework_node_key"),
    )


# -----------------------------------------------------------------------------
# Project catalog
# -----------------------------------------------------------------------------


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_name: Mapped[str] = mapped_column(
        String(160), unique=True, index=True, nullable=False
    )
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)

    organisation: Mapped[str | None] = mapped_column(String(200), nullable=True)
    project_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    license: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Multi-select field (stored as JSONB array of strings)
    programming_languages: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    capability: Mapped[str | None] = mapped_column(String(200), nullable=True)
    link_to_app: Mapped[str | None] = mapped_column(String(600), nullable=True)

    # Optional: release RSS/Atom feed to auto-discover new versions.
    # Example: GitHub releases Atom feed.
    release_rss_feed_url: Mapped[str | None] = mapped_column(String(800), nullable=True)
    release_rss_ignore_patterns: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    # State for release feed polling (to avoid re-processing old entries).
    release_rss_last_entry_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    release_rss_last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    release_rss_last_etag: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    release_rss_last_modified: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    supported_profiles: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    supported_formats: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    supported_issuance_protocols: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    supported_key_managements: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    supported_presentation_protocols: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    supported_signing_algorithms: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    versions: Mapped[list["ProjectVersion"]] = relationship(
        "ProjectVersion", cascade="all, delete-orphan", back_populates="project"
    )

    created_by_user: Mapped[User | None] = relationship("User")

    owner_group_links: Mapped[list["ProjectOwnerGroup"]] = relationship(
        "ProjectOwnerGroup", cascade="all, delete-orphan", back_populates="project"
    )


class ProjectOwnerGroup(Base):
    __tablename__ = "project_owner_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("project_id", "group_id", name="uq_project_owner_group"),
    )

    project: Mapped[Project] = relationship(
        "Project", back_populates="owner_group_links"
    )
    group: Mapped[Group] = relationship("Group")


class ProjectVersion(Base):
    __tablename__ = "project_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )

    version: Mapped[str] = mapped_column(String(64), nullable=False)
    release_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str | None] = mapped_column(String(120), nullable=True)
    link_to_source_code: Mapped[str | None] = mapped_column(String(600), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Draft versions are created automatically from release feeds.
    # Drafts are hidden from general browsing and do not notify subscribers.
    is_draft: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    is_latest: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Dependency discovery (async)
    dependency_discovery_status: Mapped[str] = mapped_column(
        String(32), default="not_run", nullable=False
    )
    dependency_discovery_started_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    dependency_discovery_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    dependency_discovery_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    dependency_last_commit: Mapped[str | None] = mapped_column(
        String(80), nullable=True
    )
    dependency_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    project: Mapped[Project] = relationship("Project", back_populates="versions")

    framework_node_mappings: Mapped[list["ProjectVersionFrameworkNode"]] = relationship(
        "ProjectVersionFrameworkNode",
        cascade="all, delete-orphan",
        back_populates="project_version",
    )

    dependency_mappings: Mapped[list["ProjectVersionDependency"]] = relationship(
        "ProjectVersionDependency",
        cascade="all, delete-orphan",
        back_populates="project_version",
    )

    __table_args__ = (
        UniqueConstraint("project_id", "version", name="uq_project_version"),
    )


class ProjectSubscription(Base):
    __tablename__ = "project_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    notify_new_versions: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    notify_questions: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("project_id", "user_id", name="uq_project_subscription"),
    )


class ProjectVersionFrameworkNode(Base):
    __tablename__ = "project_version_framework_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_version_id: Mapped[int] = mapped_column(
        ForeignKey("project_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    framework_node_id: Mapped[int] = mapped_column(
        ForeignKey("framework_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )

    project_version: Mapped[ProjectVersion] = relationship(
        "ProjectVersion", back_populates="framework_node_mappings"
    )
    framework_node: Mapped[FrameworkNode] = relationship("FrameworkNode")

    __table_args__ = (
        UniqueConstraint(
            "project_version_id",
            "framework_node_id",
            name="uq_project_version_framework_node",
        ),
    )


# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------


class DependencyPackage(Base):
    __tablename__ = "dependency_packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    versions: Mapped[list["DependencyVersion"]] = relationship(
        "DependencyVersion", cascade="all, delete-orphan", back_populates="dependency"
    )

    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "normalized_name", name="uq_dependency_packages_ecosystem_name"
        ),
    )


class DependencyVersion(Base):
    __tablename__ = "dependency_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dependency_id: Mapped[int] = mapped_column(
        ForeignKey("dependency_packages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    dependency: Mapped[DependencyPackage] = relationship(
        "DependencyPackage", back_populates="versions"
    )
    project_version_links: Mapped[list["ProjectVersionDependency"]] = relationship(
        "ProjectVersionDependency",
        cascade="all, delete-orphan",
        back_populates="dependency_version",
    )
    vulnerabilities: Mapped[list["DependencyVulnerability"]] = relationship(
        "DependencyVulnerability",
        cascade="all, delete-orphan",
        back_populates="dependency_version",
    )

    __table_args__ = (
        UniqueConstraint(
            "dependency_id", "version", name="uq_dependency_versions_dependency_version"
        ),
    )


class ProjectVersionDependency(Base):
    __tablename__ = "project_version_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_version_id: Mapped[int] = mapped_column(
        ForeignKey("project_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dependency_version_id: Mapped[int] = mapped_column(
        ForeignKey("dependency_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    source_files: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    is_indirect: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    project_version: Mapped[ProjectVersion] = relationship(
        "ProjectVersion", back_populates="dependency_mappings"
    )
    dependency_version: Mapped[DependencyVersion] = relationship(
        "DependencyVersion", back_populates="project_version_links"
    )

    __table_args__ = (
        UniqueConstraint(
            "project_version_id",
            "dependency_version_id",
            name="uq_project_version_dependency",
        ),
    )


class DependencyVulnerability(Base):
    __tablename__ = "dependency_vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dependency_version_id: Mapped[int] = mapped_column(
        ForeignKey("dependency_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanner: Mapped[str] = mapped_column(String(32), nullable=False, default="legacy")
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    references: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    dependency_version: Mapped[DependencyVersion] = relationship(
        "DependencyVersion", back_populates="vulnerabilities"
    )

    __table_args__ = (
        UniqueConstraint(
            "dependency_version_id",
            "scanner",
            "vulnerability_id",
            name="uq_dependency_vuln",
        ),
    )


# -----------------------------------------------------------------------------
# Manifests
# -----------------------------------------------------------------------------


class Manifest(Base):
    __tablename__ = "manifests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Query/filter snapshot. Includes framework_id/node_ids/project_ids etc.
    filters_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Strongly-typed FK for the primary framework used to generate this manifest.
    framework_id: Mapped[int | None] = mapped_column(
        ForeignKey("frameworks.id", ondelete="SET NULL"), nullable=True
    )

    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    owner_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("groups.id", ondelete="SET NULL"), nullable=True
    )

    # Sharing settings
    is_public: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    items: Mapped[list["ManifestProject"]] = relationship(
        "ManifestProject", cascade="all, delete-orphan", back_populates="manifest"
    )

    owner_group: Mapped[Group | None] = relationship("Group")
    created_by_user: Mapped[User | None] = relationship("User")

    framework: Mapped[Framework | None] = relationship("Framework")


class ManifestProject(Base):
    __tablename__ = "manifest_projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    manifest_id: Mapped[int] = mapped_column(
        ForeignKey("manifests.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )
    project_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("project_versions.id", ondelete="SET NULL"), nullable=True
    )

    machine_name: Mapped[str] = mapped_column(String(160), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)

    organisation: Mapped[str | None] = mapped_column(String(200), nullable=True)
    project_type: Mapped[str | None] = mapped_column(String(160), nullable=True)
    license: Mapped[str | None] = mapped_column(String(120), nullable=True)

    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latest_release_date: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    supported_profiles: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    supported_formats: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    link_to_app: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    manifest: Mapped[Manifest] = relationship("Manifest", back_populates="items")

    node_mappings: Mapped[list["ManifestProjectFrameworkNode"]] = relationship(
        "ManifestProjectFrameworkNode",
        cascade="all, delete-orphan",
        back_populates="manifest_project",
    )


class ManifestProjectFrameworkNode(Base):
    __tablename__ = "manifest_project_framework_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    manifest_project_id: Mapped[int] = mapped_column(
        ForeignKey("manifest_projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    framework_node_id: Mapped[int | None] = mapped_column(
        ForeignKey("framework_nodes.id", ondelete="SET NULL"), nullable=True
    )
    node_path: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    manifest_project: Mapped[ManifestProject] = relationship(
        "ManifestProject", back_populates="node_mappings"
    )
    framework_node: Mapped[FrameworkNode | None] = relationship("FrameworkNode")


# -----------------------------------------------------------------------------
# Questions (thread + post model)
# -----------------------------------------------------------------------------


class ProjectQuestionThread(Base):
    __tablename__ = "project_question_threads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    last_answer_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    project: Mapped[Project] = relationship("Project")
    created_by_user: Mapped[User] = relationship("User")

    posts: Mapped[list["ProjectQuestionPost"]] = relationship(
        "ProjectQuestionPost",
        cascade="all, delete-orphan",
        back_populates="thread",
        order_by="ProjectQuestionPost.id.asc()",
    )


class ProjectQuestionPost(Base):
    __tablename__ = "project_question_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    thread_id: Mapped[int] = mapped_column(
        ForeignKey("project_question_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    thread: Mapped[ProjectQuestionThread] = relationship(
        "ProjectQuestionThread", back_populates="posts"
    )
    created_by_user: Mapped[User] = relationship("User")


class RateLimitEntry(Base):
    __tablename__ = "rate_limit_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )


class AuditLog(Base):
    """Record UI/API requests as an internal audit trail.

    This intentionally mirrors KEEN's request-level audit log shape. Semantic
    before/after business changes are stored separately in EntityChangelog.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )

    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    query_string: Mapped[str | None] = mapped_column(Text, nullable=True)

    status_code: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    referer: Mapped[str | None] = mapped_column(String(512), nullable=True)


class EntityChangelog(Base):
    """Immutable semantic changelog for user-facing project catalog changes."""

    __tablename__ = "entity_changelogs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    entity_ref: Mapped[str | None] = mapped_column(
        String(160), nullable=True, index=True
    )
    entity_title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    before_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    changes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    changed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    changed_by_username: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    changed_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )
    request_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    request_path: Mapped[str | None] = mapped_column(
        String(256), nullable=True, index=True
    )

    changed_by: Mapped[User | None] = relationship(
        "User", foreign_keys=[changed_by_user_id]
    )
