"""Organisations, e-mail outbox and dependency UUIDs.

Revision ID: 0031_organisations_notifications
Revises: 0030_local_mfa
Create Date: 2026-09-24

- `organisations` + `organisation_members` become first-class records; the
  historic free-text `projects.organisation` values backfill rows and an FK.
- `notifications` provides the e-mail outbox the worker drains.
- Dependency packages and versions gain UUID public identifiers; the browser
  and exported artefacts use them instead of exposing sequence numbers.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0031_organisations_notifications"
down_revision = "0030_local_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organisations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=200), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("website", sa.String(length=600), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_organisations_name", "organisations", ["name"], unique=False)

    op.create_table(
        "organisation_members",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organisation_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organisation_id"], ["organisations.id"], ondelete="CASCADE"
        ),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.Column("role", sa.String(length=50), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "organisation_id", "user_id", "group_id", name="uq_organisation_member"
        ),
    )
    op.create_index(
        "ix_organisation_members_organisation_id",
        "organisation_members",
        ["organisation_id"],
        unique=False,
    )

    op.add_column("projects", sa.Column("organisation_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_projects_organisation_id_organisations",
        "projects",
        "organisations",
        ["organisation_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # Backfill: every distinct free-text organisation becomes a record, and
    # each project points at it. The free-text column stays as reference.
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            INSERT INTO organisations (name, created_at, updated_at)
            SELECT DISTINCT organisation, NOW(), NOW()
            FROM projects
            WHERE organisation IS NOT NULL AND organisation <> ''
            """
        )
    )
    conn.execute(
        sa.text(
            """
            UPDATE projects p
            SET organisation_id = o.id
            FROM organisations o
            WHERE p.organisation IS NOT NULL AND p.organisation <> ''
              AND o.name = p.organisation
            """
        )
    )

    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.Column("recipient", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "status", sa.String(length=16), nullable=False, server_default="pending"
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_notifications_pending", "notifications", ["status", "next_attempt_at"]
    )

    op.add_column(
        "dependency_packages",
        sa.Column("public_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "dependency_versions",
        sa.Column("public_id", sa.String(length=36), nullable=True),
    )
    conn.execute(
        sa.text(
            """
            UPDATE dependency_packages SET public_id = gen_random_uuid()::text
            WHERE public_id IS NULL
            """
        )
    )
    conn.execute(
        sa.text(
            """
            UPDATE dependency_versions SET public_id = gen_random_uuid()::text
            WHERE public_id IS NULL
            """
        )
    )
    op.create_unique_constraint(
        "uq_dependency_packages_public_id", "dependency_packages", ["public_id"]
    )
    op.create_unique_constraint(
        "uq_dependency_versions_public_id", "dependency_versions", ["public_id"]
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_dependency_versions_public_id", "dependency_versions", type_="unique"
    )
    op.drop_constraint(
        "uq_dependency_packages_public_id", "dependency_packages", type_="unique"
    )
    op.drop_column("dependency_versions", "public_id")
    op.drop_column("dependency_packages", "public_id")
    op.drop_index("ix_notifications_pending", table_name="notifications")
    op.drop_table("notifications")
    op.drop_constraint(
        "fk_projects_organisation_id_organisations", "projects", type_="foreignkey"
    )
    op.drop_column("projects", "organisation_id")
    op.drop_index(
        "ix_organisation_members_organisation_id", table_name="organisation_members"
    )
    op.drop_table("organisation_members")
    op.drop_index("ix_organisations_name", table_name="organisations")
    op.drop_table("organisations")
