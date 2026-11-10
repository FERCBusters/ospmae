"""Project release feed ignore patterns

Revision ID: 0021_release_feed_ignore
Revises: 0020_project_subscription_prefs
Create Date: 2026-06-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0021_release_feed_ignore"
down_revision = "0020_project_subscription_prefs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column(
            "release_rss_ignore_patterns",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.alter_column("projects", "release_rss_ignore_patterns", server_default=None)


def downgrade() -> None:
    op.drop_column("projects", "release_rss_ignore_patterns")
