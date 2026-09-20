"""Manifest sharing flags (public + group sharing)

Revision ID: 0019_manifest_sharing
Revises: 0018_project_subs
Create Date: 2026-02-27
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0019_manifest_sharing"
down_revision = "0018_project_subs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "manifests",
        sa.Column(
            "is_public",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.create_index("ix_manifests_is_public", "manifests", ["is_public"])
    # Drop default to keep schema clean.
    op.alter_column("manifests", "is_public", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_manifests_is_public", table_name="manifests")
    op.drop_column("manifests", "is_public")
