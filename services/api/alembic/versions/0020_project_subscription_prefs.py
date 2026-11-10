"""Project subscription preferences (versions vs questions)

Revision ID: 0020_project_subscription_prefs
Revises: 0019_manifest_sharing
Create Date: 2026-02-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_project_subscription_prefs"
down_revision = "0019_manifest_sharing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "project_subscriptions",
        sa.Column(
            "notify_new_versions",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    op.add_column(
        "project_subscriptions",
        sa.Column(
            "notify_questions",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    # Keep schema clean.
    op.alter_column("project_subscriptions", "notify_new_versions", server_default=None)
    op.alter_column("project_subscriptions", "notify_questions", server_default=None)


def downgrade() -> None:
    op.drop_column("project_subscriptions", "notify_questions")
    op.drop_column("project_subscriptions", "notify_new_versions")
