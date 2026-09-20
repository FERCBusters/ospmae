"""UI behaviour preferences

Revision ID: 0011_ui_behaviour_prefs
Revises: 0010_dependency_discovery
Create Date: 2026-02-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0011_ui_behaviour_prefs"
down_revision = "0010_dependency_discovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_preferences",
        sa.Column(
            "sticky_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    op.add_column(
        "user_preferences",
        sa.Column(
            "auto_apply_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )


def downgrade() -> None:
    op.drop_column("user_preferences", "auto_apply_enabled")
    op.drop_column("user_preferences", "sticky_enabled")
