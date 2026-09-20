"""Audit logs and entity changelogs

Revision ID: 0022_audit_logs_entity_changelogs
Revises: 0021_release_feed_ignore_patterns
Create Date: 2026-06-18
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0022_audit_logs"
down_revision = "0021_release_feed_ignore"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False, server_default=sa.func.now()),
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
    op.create_index("ix_audit_logs_ts", "audit_logs", ["ts"])
    op.create_index("ix_audit_logs_username", "audit_logs", ["username"])
    op.create_index("ix_audit_logs_method", "audit_logs", ["method"])
    op.create_index("ix_audit_logs_path", "audit_logs", ["path"])
    op.create_index("ix_audit_logs_status_code", "audit_logs", ["status_code"])
    op.alter_column("audit_logs", "ts", server_default=None)

    op.create_table(
        "entity_changelogs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("entity_ref", sa.String(length=160), nullable=True),
        sa.Column("entity_title", sa.String(length=512), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "changes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("changed_by_user_id", sa.Integer(), nullable=True),
        sa.Column("changed_by_username", sa.String(length=128), nullable=True),
        sa.Column(
            "changed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("request_method", sa.String(length=16), nullable=True),
        sa.Column("request_path", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(
            ["changed_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_entity_changelogs_entity_type", "entity_changelogs", ["entity_type"]
    )
    op.create_index(
        "ix_entity_changelogs_entity_id", "entity_changelogs", ["entity_id"]
    )
    op.create_index(
        "ix_entity_changelogs_entity_ref", "entity_changelogs", ["entity_ref"]
    )
    op.create_index("ix_entity_changelogs_action", "entity_changelogs", ["action"])
    op.create_index(
        "ix_entity_changelogs_changed_by_user_id",
        "entity_changelogs",
        ["changed_by_user_id"],
    )
    op.create_index(
        "ix_entity_changelogs_changed_by_username",
        "entity_changelogs",
        ["changed_by_username"],
    )
    op.create_index(
        "ix_entity_changelogs_changed_at", "entity_changelogs", ["changed_at"]
    )
    op.create_index(
        "ix_entity_changelogs_request_path", "entity_changelogs", ["request_path"]
    )
    op.create_index(
        "ix_entity_changelogs_entity_changed_at",
        "entity_changelogs",
        ["entity_type", "entity_id", "changed_at"],
    )
    op.alter_column("entity_changelogs", "summary", server_default=None)
    op.alter_column("entity_changelogs", "changes", server_default=None)
    op.alter_column("entity_changelogs", "changed_at", server_default=None)


def downgrade() -> None:
    op.drop_index(
        "ix_entity_changelogs_entity_changed_at", table_name="entity_changelogs"
    )
    op.drop_index("ix_entity_changelogs_request_path", table_name="entity_changelogs")
    op.drop_index("ix_entity_changelogs_changed_at", table_name="entity_changelogs")
    op.drop_index(
        "ix_entity_changelogs_changed_by_username", table_name="entity_changelogs"
    )
    op.drop_index(
        "ix_entity_changelogs_changed_by_user_id", table_name="entity_changelogs"
    )
    op.drop_index("ix_entity_changelogs_action", table_name="entity_changelogs")
    op.drop_index("ix_entity_changelogs_entity_ref", table_name="entity_changelogs")
    op.drop_index("ix_entity_changelogs_entity_id", table_name="entity_changelogs")
    op.drop_index("ix_entity_changelogs_entity_type", table_name="entity_changelogs")
    op.drop_table("entity_changelogs")

    op.drop_index("ix_audit_logs_status_code", table_name="audit_logs")
    op.drop_index("ix_audit_logs_path", table_name="audit_logs")
    op.drop_index("ix_audit_logs_method", table_name="audit_logs")
    op.drop_index("ix_audit_logs_username", table_name="audit_logs")
    op.drop_index("ix_audit_logs_ts", table_name="audit_logs")
    op.drop_table("audit_logs")
