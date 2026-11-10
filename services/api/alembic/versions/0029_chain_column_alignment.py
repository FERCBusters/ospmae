"""Drop retired chain-only columns.

Revision ID: 0029_chain_column_alignment
Revises: 0028_rate_limit_entries
Create Date: 2026-09-22

The declared model schema has outgrown columns that early revisions kept:
manifests.query_text, manifest_projects.dependencies, the audit-style
timestamps on framework_nodes and permissions and created_by_user_id on
framework_nodes. Application code reads none of them, so a fresh
installation lands exactly on the declared schema once they go.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0029_chain_column_alignment"
down_revision = "0028_rate_limit_entries"
branch_labels = None
depends_on = None

_NOW_DEFAULT = sa.text("now()")
_CURRENT_TIMESTAMP_DEFAULT = sa.text("CURRENT_TIMESTAMP")


def upgrade() -> None:
    op.drop_column("permissions", "updated_at")
    op.drop_column("permissions", "created_at")
    op.drop_column("framework_nodes", "updated_at")
    op.drop_column("framework_nodes", "created_at")
    op.drop_column("framework_nodes", "created_by_user_id")
    op.drop_column("project_version_framework_nodes", "created_at")
    op.drop_column("manifests", "query_text")
    op.drop_column("manifest_projects", "dependencies")


def downgrade() -> None:
    op.add_column(
        "manifest_projects",
        sa.Column("dependencies", sa.JSON(), nullable=False, server_default="'[]'"),
    )
    op.add_column(
        "manifests", sa.Column("query_text", sa.String(length=500), nullable=True)
    )
    op.add_column(
        "project_version_framework_nodes",
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=_NOW_DEFAULT
        ),
    )
    op.add_column(
        "framework_nodes",
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "framework_nodes",
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=_NOW_DEFAULT
        ),
    )
    op.add_column(
        "framework_nodes",
        sa.Column(
            "updated_at", sa.DateTime(), nullable=False, server_default=_NOW_DEFAULT
        ),
    )
    op.add_column(
        "permissions",
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=_CURRENT_TIMESTAMP_DEFAULT,
        ),
    )
    op.add_column(
        "permissions",
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=_CURRENT_TIMESTAMP_DEFAULT,
        ),
    )
    op.create_foreign_key(
        "fk_created_by_user_id_users",
        "framework_nodes",
        "users",
        ["created_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
