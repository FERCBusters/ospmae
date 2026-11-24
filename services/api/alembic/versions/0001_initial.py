"""Initial OSPMAE schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-24

Written out table by table: a revision never builds tables from the live
models, so every installation gets the same schema from the same revision.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("path", sa.String(length=256), nullable=False),
        sa.Column("query_string", sa.Text(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("referer", sa.String(length=512), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_audit_logs_method"), "audit_logs", ["method"], unique=False
    )
    op.create_index(op.f("ix_audit_logs_path"), "audit_logs", ["path"], unique=False)
    op.create_index(
        op.f("ix_audit_logs_status_code"), "audit_logs", ["status_code"], unique=False
    )
    op.create_index(op.f("ix_audit_logs_ts"), "audit_logs", ["ts"], unique=False)
    op.create_index(
        op.f("ix_audit_logs_username"), "audit_logs", ["username"], unique=False
    )
    op.create_table(
        "dependency_packages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=36), nullable=True),
        sa.Column("ecosystem", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ecosystem", "normalized_name", name="uq_dependency_packages_ecosystem_name"
        ),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(
        op.f("ix_dependency_packages_ecosystem"),
        "dependency_packages",
        ["ecosystem"],
        unique=False,
    )
    op.create_index(
        op.f("ix_dependency_packages_normalized_name"),
        "dependency_packages",
        ["normalized_name"],
        unique=False,
    )
    op.create_table(
        "groups",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_groups_name"), "groups", ["name"], unique=True)
    op.create_table(
        "oidc_login_states",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("state", sa.String(length=255), nullable=False),
        sa.Column("nonce", sa.String(length=255), nullable=False),
        sa.Column("code_verifier", sa.Text(), nullable=False),
        sa.Column("next_url", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("state"),
    )
    op.create_table(
        "permissions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("code", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_permissions_code"), "permissions", ["code"], unique=True)
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("login_key", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "auth_backend", sa.String(length=16), server_default="local", nullable=False
        ),
        sa.Column("mfa_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("session_version", sa.Integer(), server_default="0", nullable=False),
        sa.Column("mfa_version", sa.Integer(), server_default="0", nullable=False),
        sa.Column("mfa_totp_secret", sa.Text(), nullable=True),
        sa.Column(
            "mfa_totp_last_step", sa.Integer(), server_default="-1", nullable=False
        ),
        sa.Column(
            "mfa_code_failures", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("mfa_code_failures_since", sa.DateTime(), nullable=True),
        sa.Column("email", sa.String(length=256), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("authz_version", sa.Integer(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_login_key"), "users", ["login_key"], unique=False)
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)
    op.create_table(
        "dependency_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=36), nullable=True),
        sa.Column("dependency_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["dependency_id"], ["dependency_packages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "dependency_id", "version", name="uq_dependency_versions_dependency_version"
        ),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(
        op.f("ix_dependency_versions_dependency_id"),
        "dependency_versions",
        ["dependency_id"],
        unique=False,
    )
    op.create_table(
        "entity_changelogs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("entity_ref", sa.String(length=160), nullable=True),
        sa.Column("entity_title", sa.String(length=512), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column(
            "before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("changes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("changed_by_user_id", sa.UUID(), nullable=True),
        sa.Column("changed_by_username", sa.String(length=128), nullable=True),
        sa.Column("changed_at", sa.DateTime(), nullable=False),
        sa.Column("request_method", sa.String(length=16), nullable=True),
        sa.Column("request_path", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(
            ["changed_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_entity_changelogs_action"),
        "entity_changelogs",
        ["action"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_changelogs_changed_at"),
        "entity_changelogs",
        ["changed_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_changelogs_changed_by_user_id"),
        "entity_changelogs",
        ["changed_by_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_changelogs_changed_by_username"),
        "entity_changelogs",
        ["changed_by_username"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_changelogs_entity_id"),
        "entity_changelogs",
        ["entity_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_changelogs_entity_ref"),
        "entity_changelogs",
        ["entity_ref"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_changelogs_entity_type"),
        "entity_changelogs",
        ["entity_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_changelogs_request_path"),
        "entity_changelogs",
        ["request_path"],
        unique=False,
    )
    op.create_table(
        "frameworks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("machine_name", sa.String(length=160), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_frameworks_machine_name"), "frameworks", ["machine_name"], unique=True
    )
    op.create_table(
        "group_permissions",
        sa.Column("group_id", sa.UUID(), nullable=False),
        sa.Column("permission_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["permission_id"], ["permissions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("group_id", "permission_id"),
    )
    op.create_table(
        "managed_configuration_revisions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "version"),
    )
    op.create_index(
        op.f("ix_managed_configuration_revisions_name"),
        "managed_configuration_revisions",
        ["name"],
        unique=False,
    )
    op.create_table(
        "managed_configurations",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_table(
        "mfa_challenges",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("password_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index(
        op.f("ix_mfa_challenges_expires_at"),
        "mfa_challenges",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_mfa_challenges_user_id"), "mfa_challenges", ["user_id"], unique=False
    )
    op.create_table(
        "mfa_credentials",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("credential_id", sa.Text(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index(
        op.f("ix_mfa_credentials_user_id"), "mfa_credentials", ["user_id"], unique=False
    )
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "code_hash"),
    )
    op.create_table(
        "notifications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("recipient", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="pending", nullable=False
        ),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_notifications_pending",
        "notifications",
        ["status", "next_attempt_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notifications_user_id"), "notifications", ["user_id"], unique=False
    )
    op.create_table(
        "organisations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("website", sa.String(length=600), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_organisations_name"), "organisations", ["name"], unique=True
    )
    op.create_table(
        "security_notifications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("recipient", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_notifications_pending",
        "security_notifications",
        ["status", "next_attempt_at"],
        unique=False,
    )
    op.create_table(
        "sso_email_challenges",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("mfa_version", sa.Integer(), nullable=False),
        sa.Column("password_digest", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index(
        op.f("ix_sso_email_challenges_user_id"),
        "sso_email_challenges",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "user_groups",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("group_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "group_id"),
    )
    op.create_table(
        "user_identities",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("preferred_username", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("claims", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "issuer", "subject", name="uq_user_identities_issuer_subject"
        ),
    )
    op.create_index(
        op.f("ix_user_identities_user_id"), "user_identities", ["user_id"], unique=False
    )
    op.create_table(
        "user_login_ips",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("address", sa.String(length=45), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "address"),
    )
    op.create_table(
        "user_permissions",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("permission_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"], ["permissions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "permission_id"),
    )
    op.create_table(
        "user_preferences",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("theme", sa.String(length=16), nullable=True),
        sa.Column(
            "node_colors", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("default_start_page", sa.String(length=255), nullable=True),
        sa.Column("sticky_enabled", sa.Boolean(), nullable=False),
        sa.Column("auto_apply_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )
    op.create_table(
        "user_shortcuts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "name", name="uq_user_shortcuts_user_name"),
    )
    op.create_index(
        op.f("ix_user_shortcuts_user_id"), "user_shortcuts", ["user_id"], unique=False
    )
    op.create_table(
        "user_sso_emails",
        sa.Column("email", sa.String(length=256), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("email"),
    )
    op.create_index(
        op.f("ix_user_sso_emails_user_id"), "user_sso_emails", ["user_id"], unique=False
    )
    op.create_table(
        "dependency_vulnerabilities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dependency_version_id", sa.Integer(), nullable=False),
        sa.Column("scanner", sa.String(length=32), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("fixed_version", sa.String(length=255), nullable=True),
        sa.Column(
            "references", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["dependency_version_id"], ["dependency_versions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "dependency_version_id",
            "scanner",
            "vulnerability_id",
            name="uq_dependency_vuln",
        ),
    )
    op.create_index(
        op.f("ix_dependency_vulnerabilities_dependency_version_id"),
        "dependency_vulnerabilities",
        ["dependency_version_id"],
        unique=False,
    )
    op.create_table(
        "framework_nodes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("framework_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=160), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["framework_id"], ["frameworks.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"], ["framework_nodes.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("framework_id", "key", name="uq_framework_node_key"),
    )
    op.create_index(
        op.f("ix_framework_nodes_framework_id"),
        "framework_nodes",
        ["framework_id"],
        unique=False,
    )
    op.create_table(
        "manifests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "filters_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("framework_id", sa.Integer(), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("owner_group_id", sa.UUID(), nullable=True),
        sa.Column("is_public", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["framework_id"], ["frameworks.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["owner_group_id"], ["groups.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_manifests_is_public"), "manifests", ["is_public"], unique=False
    )
    op.create_table(
        "organisation_members",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organisation_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("group_id", sa.UUID(), nullable=True),
        sa.Column("role", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organisation_id"], ["organisations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organisation_id", "user_id", "group_id", name="uq_organisation_member"
        ),
    )
    op.create_index(
        op.f("ix_organisation_members_organisation_id"),
        "organisation_members",
        ["organisation_id"],
        unique=False,
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("machine_name", sa.String(length=160), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("organisation_id", sa.Integer(), nullable=True),
        sa.Column("organisation", sa.String(length=200), nullable=True),
        sa.Column("project_type", sa.String(length=120), nullable=True),
        sa.Column("license", sa.String(length=200), nullable=True),
        sa.Column(
            "programming_languages",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("capability", sa.String(length=200), nullable=True),
        sa.Column("link_to_app", sa.String(length=600), nullable=True),
        sa.Column("release_rss_feed_url", sa.String(length=800), nullable=True),
        sa.Column(
            "release_rss_ignore_patterns",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("release_auto_publish", sa.Boolean(), nullable=False),
        sa.Column("release_rss_last_entry_id", sa.Text(), nullable=True),
        sa.Column("release_rss_last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("release_rss_last_etag", sa.String(length=255), nullable=True),
        sa.Column("release_rss_last_modified", sa.String(length=255), nullable=True),
        sa.Column("track_branch", sa.Boolean(), nullable=False),
        sa.Column("tracked_repo_url", sa.String(length=600), nullable=True),
        sa.Column("tracked_branch", sa.String(length=64), nullable=True),
        sa.Column("branch_poll_interval_hours", sa.Integer(), nullable=False),
        sa.Column("branch_last_polled_at", sa.DateTime(), nullable=True),
        sa.Column(
            "repo_private",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("repo_token_host", sa.String(length=255), nullable=True),
        sa.Column("repo_token_repository", sa.String(length=600), nullable=True),
        sa.Column("repo_token_username", sa.String(length=100), nullable=True),
        sa.Column("repo_token_encrypted", sa.Text(), nullable=True),
        sa.Column("repo_token_updated_at", sa.DateTime(), nullable=True),
        sa.Column(
            "supported_profiles",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "supported_formats", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column(
            "supported_issuance_protocols",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "supported_key_managements",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "supported_presentation_protocols",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "supported_signing_algorithms",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["organisation_id"], ["organisations.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_projects_machine_name"), "projects", ["machine_name"], unique=True
    )
    op.create_table(
        "project_owner_groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "group_id", name="uq_project_owner_group"),
    )
    op.create_table(
        "project_question_threads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_answer_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_project_question_threads_created_by_user_id"),
        "project_question_threads",
        ["created_by_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_question_threads_project_id"),
        "project_question_threads",
        ["project_id"],
        unique=False,
    )
    op.create_table(
        "project_subscriptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("notify_new_versions", sa.Boolean(), nullable=False),
        sa.Column("notify_questions", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "user_id", name="uq_project_subscription"),
    )
    op.create_index(
        op.f("ix_project_subscriptions_project_id"),
        "project_subscriptions",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_subscriptions_user_id"),
        "project_subscriptions",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "project_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("release_date", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=120), nullable=True),
        sa.Column("link_to_source_code", sa.String(length=600), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("is_draft", sa.Boolean(), nullable=False),
        sa.Column("is_latest", sa.Boolean(), nullable=False),
        sa.Column("dependency_discovery_status", sa.String(length=32), nullable=False),
        sa.Column("dependency_discovery_started_at", sa.DateTime(), nullable=True),
        sa.Column("dependency_discovery_finished_at", sa.DateTime(), nullable=True),
        sa.Column("dependency_discovery_error", sa.Text(), nullable=True),
        sa.Column("dependency_last_commit", sa.String(length=80), nullable=True),
        sa.Column("dependency_count", sa.Integer(), nullable=False),
        sa.Column("vulnerability_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "version", name="uq_project_version"),
    )
    op.create_index(
        op.f("ix_project_versions_project_id"),
        "project_versions",
        ["project_id"],
        unique=False,
    )
    op.create_table(
        "manifest_projects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("manifest_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("project_version_id", sa.Integer(), nullable=True),
        sa.Column("machine_name", sa.String(length=160), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("organisation", sa.String(length=200), nullable=True),
        sa.Column("project_type", sa.String(length=160), nullable=True),
        sa.Column("license", sa.String(length=120), nullable=True),
        sa.Column("latest_version", sa.String(length=64), nullable=True),
        sa.Column("latest_release_date", sa.DateTime(), nullable=True),
        sa.Column(
            "supported_profiles",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "supported_formats", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("link_to_app", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["manifest_id"], ["manifests.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["project_version_id"], ["project_versions.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "project_question_posts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("thread_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.UUID(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["thread_id"], ["project_question_threads.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_project_question_posts_created_by_user_id"),
        "project_question_posts",
        ["created_by_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_question_posts_thread_id"),
        "project_question_posts",
        ["thread_id"],
        unique=False,
    )
    op.create_table(
        "project_version_dependencies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_version_id", sa.Integer(), nullable=False),
        sa.Column("dependency_version_id", sa.Integer(), nullable=False),
        sa.Column(
            "source_files", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("is_indirect", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["dependency_version_id"], ["dependency_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_version_id"], ["project_versions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_version_id",
            "dependency_version_id",
            name="uq_project_version_dependency",
        ),
    )
    op.create_index(
        op.f("ix_project_version_dependencies_dependency_version_id"),
        "project_version_dependencies",
        ["dependency_version_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_version_dependencies_project_version_id"),
        "project_version_dependencies",
        ["project_version_id"],
        unique=False,
    )
    op.create_table(
        "project_version_framework_nodes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_version_id", sa.Integer(), nullable=False),
        sa.Column("framework_node_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["framework_node_id"], ["framework_nodes.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_version_id"], ["project_versions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_version_id",
            "framework_node_id",
            name="uq_project_version_framework_node",
        ),
    )
    op.create_index(
        op.f("ix_project_version_framework_nodes_framework_node_id"),
        "project_version_framework_nodes",
        ["framework_node_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_project_version_framework_nodes_project_version_id"),
        "project_version_framework_nodes",
        ["project_version_id"],
        unique=False,
    )
    op.create_table(
        "manifest_project_framework_nodes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("manifest_project_id", sa.Integer(), nullable=False),
        sa.Column("framework_node_id", sa.Integer(), nullable=True),
        sa.Column("node_path", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["framework_node_id"], ["framework_nodes.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["manifest_project_id"], ["manifest_projects.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_manifest_project_framework_nodes_manifest_project_id"),
        "manifest_project_framework_nodes",
        ["manifest_project_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_manifest_project_framework_nodes_manifest_project_id"),
        table_name="manifest_project_framework_nodes",
    )
    op.drop_table("manifest_project_framework_nodes")
    op.drop_index(
        op.f("ix_project_version_framework_nodes_project_version_id"),
        table_name="project_version_framework_nodes",
    )
    op.drop_index(
        op.f("ix_project_version_framework_nodes_framework_node_id"),
        table_name="project_version_framework_nodes",
    )
    op.drop_table("project_version_framework_nodes")
    op.drop_index(
        op.f("ix_project_version_dependencies_project_version_id"),
        table_name="project_version_dependencies",
    )
    op.drop_index(
        op.f("ix_project_version_dependencies_dependency_version_id"),
        table_name="project_version_dependencies",
    )
    op.drop_table("project_version_dependencies")
    op.drop_index(
        op.f("ix_project_question_posts_thread_id"), table_name="project_question_posts"
    )
    op.drop_index(
        op.f("ix_project_question_posts_created_by_user_id"),
        table_name="project_question_posts",
    )
    op.drop_table("project_question_posts")
    op.drop_table("manifest_projects")
    op.drop_index(op.f("ix_project_versions_project_id"), table_name="project_versions")
    op.drop_table("project_versions")
    op.drop_index(
        op.f("ix_project_subscriptions_user_id"), table_name="project_subscriptions"
    )
    op.drop_index(
        op.f("ix_project_subscriptions_project_id"), table_name="project_subscriptions"
    )
    op.drop_table("project_subscriptions")
    op.drop_index(
        op.f("ix_project_question_threads_project_id"),
        table_name="project_question_threads",
    )
    op.drop_index(
        op.f("ix_project_question_threads_created_by_user_id"),
        table_name="project_question_threads",
    )
    op.drop_table("project_question_threads")
    op.drop_table("project_owner_groups")
    op.drop_index(op.f("ix_projects_machine_name"), table_name="projects")
    op.drop_table("projects")
    op.drop_index(
        op.f("ix_organisation_members_organisation_id"),
        table_name="organisation_members",
    )
    op.drop_table("organisation_members")
    op.drop_index(op.f("ix_manifests_is_public"), table_name="manifests")
    op.drop_table("manifests")
    op.drop_index(op.f("ix_framework_nodes_framework_id"), table_name="framework_nodes")
    op.drop_table("framework_nodes")
    op.drop_index(
        op.f("ix_dependency_vulnerabilities_dependency_version_id"),
        table_name="dependency_vulnerabilities",
    )
    op.drop_table("dependency_vulnerabilities")
    op.drop_index(op.f("ix_user_sso_emails_user_id"), table_name="user_sso_emails")
    op.drop_table("user_sso_emails")
    op.drop_index(op.f("ix_user_shortcuts_user_id"), table_name="user_shortcuts")
    op.drop_table("user_shortcuts")
    op.drop_table("user_preferences")
    op.drop_table("user_permissions")
    op.drop_table("user_login_ips")
    op.drop_index(op.f("ix_user_identities_user_id"), table_name="user_identities")
    op.drop_table("user_identities")
    op.drop_table("user_groups")
    op.drop_index(
        op.f("ix_sso_email_challenges_user_id"), table_name="sso_email_challenges"
    )
    op.drop_table("sso_email_challenges")
    op.drop_index(
        "ix_security_notifications_pending", table_name="security_notifications"
    )
    op.drop_table("security_notifications")
    op.drop_index(op.f("ix_organisations_name"), table_name="organisations")
    op.drop_table("organisations")
    op.drop_index(op.f("ix_notifications_user_id"), table_name="notifications")
    op.drop_index("ix_notifications_pending", table_name="notifications")
    op.drop_table("notifications")
    op.drop_table("mfa_recovery_codes")
    op.drop_index(op.f("ix_mfa_credentials_user_id"), table_name="mfa_credentials")
    op.drop_table("mfa_credentials")
    op.drop_index(op.f("ix_mfa_challenges_user_id"), table_name="mfa_challenges")
    op.drop_index(op.f("ix_mfa_challenges_expires_at"), table_name="mfa_challenges")
    op.drop_table("mfa_challenges")
    op.drop_table("managed_configurations")
    op.drop_index(
        op.f("ix_managed_configuration_revisions_name"),
        table_name="managed_configuration_revisions",
    )
    op.drop_table("managed_configuration_revisions")
    op.drop_table("group_permissions")
    op.drop_index(op.f("ix_frameworks_machine_name"), table_name="frameworks")
    op.drop_table("frameworks")
    op.drop_index(
        op.f("ix_entity_changelogs_request_path"), table_name="entity_changelogs"
    )
    op.drop_index(
        op.f("ix_entity_changelogs_entity_type"), table_name="entity_changelogs"
    )
    op.drop_index(
        op.f("ix_entity_changelogs_entity_ref"), table_name="entity_changelogs"
    )
    op.drop_index(
        op.f("ix_entity_changelogs_entity_id"), table_name="entity_changelogs"
    )
    op.drop_index(
        op.f("ix_entity_changelogs_changed_by_username"), table_name="entity_changelogs"
    )
    op.drop_index(
        op.f("ix_entity_changelogs_changed_by_user_id"), table_name="entity_changelogs"
    )
    op.drop_index(
        op.f("ix_entity_changelogs_changed_at"), table_name="entity_changelogs"
    )
    op.drop_index(op.f("ix_entity_changelogs_action"), table_name="entity_changelogs")
    op.drop_table("entity_changelogs")
    op.drop_index(
        op.f("ix_dependency_versions_dependency_id"), table_name="dependency_versions"
    )
    op.drop_table("dependency_versions")
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_index(op.f("ix_users_login_key"), table_name="users")
    op.drop_table("users")
    op.drop_index(op.f("ix_permissions_code"), table_name="permissions")
    op.drop_table("permissions")
    op.drop_table("oidc_login_states")
    op.drop_index(op.f("ix_groups_name"), table_name="groups")
    op.drop_table("groups")
    op.drop_index(
        op.f("ix_dependency_packages_normalized_name"), table_name="dependency_packages"
    )
    op.drop_index(
        op.f("ix_dependency_packages_ecosystem"), table_name="dependency_packages"
    )
    op.drop_table("dependency_packages")
    op.drop_index(op.f("ix_audit_logs_username"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_ts"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_status_code"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_path"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_method"), table_name="audit_logs")
    op.drop_table("audit_logs")
