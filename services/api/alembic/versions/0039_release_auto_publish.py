"""Projects that publish new releases automatically

Revision ID: 0039_release_auto_publish
Revises: 0038_keen_account_model
Create Date: 2026-11-12

A project following a release feed may publish the releases the poll finds
as they arrive, with the newest becoming Latest, instead of staging each as
a draft for a maintainer to publish.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0039_release_auto_publish"
down_revision = "0038_keen_account_model"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column(
            "release_auto_publish",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.alter_column("projects", "release_auto_publish", server_default=None)


def downgrade() -> None:
    op.drop_column("projects", "release_auto_publish")
