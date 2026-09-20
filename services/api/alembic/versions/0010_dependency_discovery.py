"""dependency discovery tables

Revision ID: 0010_dependency_discovery
Revises: 0009_project_type
Create Date: 2026-02-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010_dependency_discovery"
down_revision = "0009_project_type"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- project_versions fields ---
    op.add_column(
        "project_versions",
        sa.Column(
            "dependency_discovery_status",
            sa.String(length=32),
            nullable=False,
            server_default="not_run",
        ),
    )
    op.add_column(
        "project_versions",
        sa.Column("dependency_discovery_started_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "project_versions",
        sa.Column("dependency_discovery_finished_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "project_versions",
        sa.Column("dependency_discovery_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "project_versions",
        sa.Column("dependency_last_commit", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "project_versions",
        sa.Column("dependency_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "project_versions",
        sa.Column(
            "vulnerability_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )

    # --- dependency catalog ---
    op.create_table(
        "dependency_packages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ecosystem", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.UniqueConstraint(
            "ecosystem", "normalized_name", name="uq_dependency_packages_ecosystem_name"
        ),
    )
    op.create_index(
        "ix_dependency_packages_ecosystem", "dependency_packages", ["ecosystem"]
    )
    op.create_index(
        "ix_dependency_packages_normalized_name",
        "dependency_packages",
        ["normalized_name"],
    )

    op.create_table(
        "dependency_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "dependency_id",
            sa.Integer(),
            sa.ForeignKey("dependency_packages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.String(length=255), nullable=False, server_default=""),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.UniqueConstraint(
            "dependency_id", "version", name="uq_dependency_versions_dependency_version"
        ),
    )
    op.create_index(
        "ix_dependency_versions_dependency_id", "dependency_versions", ["dependency_id"]
    )

    op.create_table(
        "project_version_dependencies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "project_version_id",
            sa.Integer(),
            sa.ForeignKey("project_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "dependency_version_id",
            sa.Integer(),
            sa.ForeignKey("dependency_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_files",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "is_indirect", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.UniqueConstraint(
            "project_version_id",
            "dependency_version_id",
            name="uq_project_version_dependency",
        ),
    )
    op.create_index(
        "ix_project_version_dependencies_project_version_id",
        "project_version_dependencies",
        ["project_version_id"],
    )
    op.create_index(
        "ix_project_version_dependencies_dependency_version_id",
        "project_version_dependencies",
        ["dependency_version_id"],
    )

    op.create_table(
        "dependency_vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "dependency_version_id",
            sa.Integer(),
            sa.ForeignKey("dependency_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scanner", sa.String(length=32), nullable=False, server_default="legacy"
        ),
        sa.Column("vulnerability_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("fixed_version", sa.String(length=255), nullable=True),
        sa.Column(
            "references",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "raw",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.UniqueConstraint(
            "dependency_version_id",
            "scanner",
            "vulnerability_id",
            name="uq_dependency_vuln",
        ),
    )
    op.create_index(
        "ix_dependency_vulnerabilities_dependency_version_id",
        "dependency_vulnerabilities",
        ["dependency_version_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_dependency_vulnerabilities_dependency_version_id",
        table_name="dependency_vulnerabilities",
    )
    op.drop_table("dependency_vulnerabilities")

    op.drop_index(
        "ix_project_version_dependencies_dependency_version_id",
        table_name="project_version_dependencies",
    )
    op.drop_index(
        "ix_project_version_dependencies_project_version_id",
        table_name="project_version_dependencies",
    )
    op.drop_table("project_version_dependencies")

    op.drop_index(
        "ix_dependency_versions_dependency_id", table_name="dependency_versions"
    )
    op.drop_table("dependency_versions")

    op.drop_index(
        "ix_dependency_packages_normalized_name", table_name="dependency_packages"
    )
    op.drop_index("ix_dependency_packages_ecosystem", table_name="dependency_packages")
    op.drop_table("dependency_packages")

    op.drop_column("project_versions", "vulnerability_count")
    op.drop_column("project_versions", "dependency_count")
    op.drop_column("project_versions", "dependency_last_commit")
    op.drop_column("project_versions", "dependency_discovery_error")
    op.drop_column("project_versions", "dependency_discovery_finished_at")
    op.drop_column("project_versions", "dependency_discovery_started_at")
    op.drop_column("project_versions", "dependency_discovery_status")
