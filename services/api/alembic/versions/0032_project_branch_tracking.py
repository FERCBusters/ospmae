"""Projects that track a branch instead of releases

Revision ID: 0032_project_branch_tracking
Revises: 0031_organisations_notifications
Create Date: 2026-11-11

A project may follow the head of one branch of a repository: the branch is
re-cloned and scanned every `branch_poll_interval_hours` (one hour at least),
and `branch_last_polled_at` records when the last scan was queued.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_project_branch_tracking"
down_revision = "0031_organisations_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column(
            "track_branch",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "projects",
        sa.Column("tracked_repo_url", sa.String(length=600), nullable=True),
    )
    op.add_column(
        "projects",
        sa.Column("tracked_branch", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "projects",
        sa.Column(
            "branch_poll_interval_hours",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("24"),
        ),
    )
    op.add_column(
        "projects",
        sa.Column("branch_last_polled_at", sa.DateTime(), nullable=True),
    )
    op.alter_column("projects", "track_branch", server_default=None)
    op.alter_column("projects", "branch_poll_interval_hours", server_default=None)


def downgrade() -> None:
    op.drop_column("projects", "branch_last_polled_at")
    op.drop_column("projects", "branch_poll_interval_hours")
    op.drop_column("projects", "tracked_branch")
    op.drop_column("projects", "tracked_repo_url")
    op.drop_column("projects", "track_branch")
