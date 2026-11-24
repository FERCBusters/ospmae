from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from mosp.core.datetime_utils import utc_now_naive
from mosp.db.accounts import (
    AuditLogMixin,
    GroupMixin,
    MfaChallengeMixin,
    MfaCredentialMixin,
    MfaRecoveryCodeMixin,
    OidcLoginStateMixin,
    PermissionMixin,
    SecurityNotificationMixin,
    SsoEmailChallengeMixin,
    UserIdentityMixin,
    UserLoginIPMixin,
    UserMixin,
    UserSsoEmailMixin,
    association_tables,
)
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

# A column named uuid would hide the module from class-level annotations.
Uuid = uuid.UUID

# -----------------------------------------------------------------------------
# Accounts: mosp's tables (mosp.db.accounts) with OSPMAE's additions
# -----------------------------------------------------------------------------

user_groups, user_permissions, group_permissions = association_tables(Base.metadata)


class User(Base, UserMixin):
    preferences: Mapped[UserPreference | None] = relationship(
        "UserPreference", uselist=False, backref="user", cascade="all, delete-orphan"
    )
    shortcuts: Mapped[list["UserShortcut"]] = relationship(
        "UserShortcut", back_populates="user", cascade="all, delete-orphan"
    )


class Group(Base, GroupMixin):
    pass


class Permission(Base, PermissionMixin):
    pass


class UserIdentity(Base, UserIdentityMixin):
    pass


class OidcLoginState(Base, OidcLoginStateMixin):
    pass


class MfaCredential(Base, MfaCredentialMixin):
    pass


class MfaRecoveryCode(Base, MfaRecoveryCodeMixin):
    pass


class MfaChallenge(Base, MfaChallengeMixin):
    pass


class UserLoginIP(Base, UserLoginIPMixin):
    pass


class SecurityNotification(Base, SecurityNotificationMixin):
    pass


class UserSsoEmail(Base, UserSsoEmailMixin):
    pass


class SsoEmailChallenge(Base, SsoEmailChallengeMixin):
    pass


class AuditLog(Base, AuditLogMixin):
    """Requests recorded as the audit trail (mosp.middleware). Semantic
    before/after changes are stored separately in EntityChangelog."""


class UserPreference(Base):
    __tablename__ = "user_preferences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Uuid] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
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
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
    )


class UserShortcut(Base):
    __tablename__ = "user_shortcuts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Uuid] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
    )

    user: Mapped["User"] = relationship("User", back_populates="shortcuts")

    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_user_shortcuts_user_name"),
    )


class Organisation(Base):
    """A developing or sponsoring organisation for projects.

    Created and administered by administrators; membership may name users or
    groups, at most one of the two per row. Projects carry an organisation FK
    so the catalogue can be filtered, grouped and reported per organisation.
    """

    __tablename__ = "organisations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(
        String(200), unique=True, index=True, nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    website: Mapped[str | None] = mapped_column(String(600), nullable=True)

    created_by_user_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
    )

    projects: Mapped[list["Project"]] = relationship(
        "Project", back_populates="organisation_ref"
    )


class OrganisationMember(Base):
    """A user or group on an organisation's view, exactly one of the two."""

    __tablename__ = "organisation_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organisation_id: Mapped[int] = mapped_column(
        ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    group_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("groups.id", ondelete="CASCADE"), nullable=True
    )
    role: Mapped[str | None] = mapped_column(String(50), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "organisation_id",
            "user_id",
            "group_id",
            name="uq_organisation_member",
        ),
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

    created_by_user_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
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

    # The developing organisation: a first-class record so projects can be
    # filtered, grouped and reported per organisation. Kept alongside the
    # historic free-text column filled by the 0031 backfill.
    organisation_id: Mapped[int | None] = mapped_column(
        ForeignKey("organisations.id", ondelete="SET NULL"), nullable=True
    )
    # The historic free-text name retained for reference after the backfill.
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

    # New releases the feed poll finds are staged as drafts for a maintainer to
    # publish; with this on they are published as they arrive and the newest
    # becomes Latest (app/tasks/release_feed.py).
    release_auto_publish: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
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

    # Branch tracking: instead of following releases, the project follows the
    # head of one branch, re-cloned and scanned every branch_poll_interval_hours
    # (app/services/branch_tracking.py keeps the version row named after the
    # branch). The branch name is that version's label, so it shares its width.
    track_branch: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tracked_repo_url: Mapped[str | None] = mapped_column(String(600), nullable=True)
    tracked_branch: Mapped[str | None] = mapped_column(String(64), nullable=True)
    branch_poll_interval_hours: Mapped[int] = mapped_column(
        Integer, default=24, nullable=False
    )
    branch_last_polled_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    # A private repository's clones authenticate with one access token, bound
    # to the host it was saved for (app/security/repo_credentials.py). The
    # token is write-only: stored Fernet-encrypted and never returned.
    repo_private: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    repo_token_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The one repository the token is for: every clone that carries it goes
    # there, and the project's versions, tracked branch and feed releases
    # live there.
    repo_token_repository: Mapped[str | None] = mapped_column(
        String(600), nullable=True
    )
    repo_token_username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    repo_token_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    repo_token_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
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

    created_by_user_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
    )

    versions: Mapped[list["ProjectVersion"]] = relationship(
        "ProjectVersion", cascade="all, delete-orphan", back_populates="project"
    )

    created_by_user: Mapped[User | None] = relationship("User")

    organisation_ref: Mapped["Organisation | None"] = relationship(
        "Organisation", back_populates="projects"
    )

    owner_group_links: Mapped[list["ProjectOwnerGroup"]] = relationship(
        "ProjectOwnerGroup", cascade="all, delete-orphan", back_populates="project"
    )


class ProjectOwnerGroup(Base):
    __tablename__ = "project_owner_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    group_id: Mapped[Uuid] = mapped_column(
        UUID(as_uuid=True), ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
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
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
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
    user_id: Mapped[Uuid] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    notify_new_versions: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    notify_questions: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
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
    # The externally used identifier (UUIDv4); sequence numbers never leave
    # the database, so an enumeration walk cannot probe dependency rows.
    public_id: Mapped[str | None] = mapped_column(
        String(36), unique=True, nullable=True, default=lambda: str(uuid.uuid4())
    )
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
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
    public_id: Mapped[str | None] = mapped_column(
        String(36), unique=True, nullable=True, default=lambda: str(uuid.uuid4())
    )
    dependency_id: Mapped[int] = mapped_column(
        ForeignKey("dependency_packages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
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
        DateTime, default=utc_now_naive, nullable=False
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
        DateTime, default=utc_now_naive, nullable=False
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

    created_by_user_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    owner_group_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("groups.id", ondelete="SET NULL"), nullable=True
    )

    # Sharing settings
    is_public: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
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
        DateTime, default=utc_now_naive, nullable=False
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
        DateTime, default=utc_now_naive, nullable=False
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
    created_by_user_id: Mapped[Uuid] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    last_answer_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
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
    created_by_user_id: Mapped[Uuid] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )

    thread: Mapped[ProjectQuestionThread] = relationship(
        "ProjectQuestionThread", back_populates="posts"
    )
    created_by_user: Mapped[User] = relationship("User")


class ManagedConfiguration(Base):
    """Versioned administrator setting, such as the installation features.

    Ported from KEEN: each change bumps the version, which saves check against
    so two administrators cannot silently overwrite one another.
    """

    __tablename__ = "managed_configurations"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    document: Mapped[dict] = mapped_column(JSONB, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_by: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, onupdate=utc_now_naive, nullable=False
    )


class ManagedConfigurationRevision(Base):
    """Every saved version of a managed configuration, kept as history."""

    __tablename__ = "managed_configuration_revisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    document: Mapped[dict] = mapped_column(JSONB, nullable=False)
    updated_by: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )

    __table_args__ = (UniqueConstraint("name", "version"),)


class Notification(Base):
    """Transactional e-mail outbox.

    Senders queue a row inside their own transaction; the worker delivers it
    with exponential backoff and records the outcome, so a broken SMTP
    configuration is visible instead of silently swallowed. A sent message's
    body is cleared (verification links are one-time secrets); bodies fail
    after eight attempts like the KEEN outbox this model ships for parity.
    """

    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), default="pending", nullable=False, server_default="pending"
    )
    attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, server_default="0"
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False
    )

    __table_args__ = (Index("ix_notifications_pending", "status", "next_attempt_at"),)


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

    changed_by_user_id: Mapped[Uuid | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    changed_by_username: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    changed_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now_naive, nullable=False, index=True
    )
    request_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    request_path: Mapped[str | None] = mapped_column(
        String(256), nullable=True, index=True
    )

    changed_by: Mapped[User | None] = relationship(
        "User", foreign_keys=[changed_by_user_id]
    )
