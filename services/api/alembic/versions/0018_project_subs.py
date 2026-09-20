"""Project subscriptions + release feed polling + draft versions

Revision ID: 0018_project_subs
Revises: 0017_password_resets
Create Date: 2026-02-26
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0018_project_subs"
down_revision = "0017_password_resets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # Project subscriptions (email notifications)
    # ------------------------------------------------------------------
    op.create_table(
        "project_subscriptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "project_id",
            sa.Integer(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.UniqueConstraint("project_id", "user_id", name="uq_project_subscription"),
    )
    op.create_index(
        "ix_project_subscriptions_project_id",
        "project_subscriptions",
        ["project_id"],
    )
    op.create_index(
        "ix_project_subscriptions_user_id",
        "project_subscriptions",
        ["user_id"],
    )

    # ------------------------------------------------------------------
    # Projects: release RSS feed URL + polling state
    # ------------------------------------------------------------------
    op.add_column(
        "projects",
        sa.Column("release_rss_feed_url", sa.String(length=800), nullable=True),
    )
    op.add_column(
        "projects",
        sa.Column("release_rss_last_entry_id", sa.Text(), nullable=True),
    )
    op.add_column(
        "projects",
        sa.Column("release_rss_last_checked_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "projects",
        sa.Column("release_rss_last_etag", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "projects",
        sa.Column("release_rss_last_modified", sa.String(length=255), nullable=True),
    )

    # ------------------------------------------------------------------
    # Project versions: draft flag
    # ------------------------------------------------------------------
    op.add_column(
        "project_versions",
        sa.Column(
            "is_draft",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    # Drop default to keep schema clean.
    op.alter_column("project_versions", "is_draft", server_default=None)


def downgrade() -> None:
    op.drop_column("project_versions", "is_draft")

    op.drop_column("projects", "release_rss_last_modified")
    op.drop_column("projects", "release_rss_last_etag")
    op.drop_column("projects", "release_rss_last_checked_at")
    op.drop_column("projects", "release_rss_last_entry_id")
    op.drop_column("projects", "release_rss_feed_url")

    op.drop_index(
        "ix_project_subscriptions_user_id", table_name="project_subscriptions"
    )
    op.drop_index(
        "ix_project_subscriptions_project_id", table_name="project_subscriptions"
    )
    op.drop_table("project_subscriptions")
