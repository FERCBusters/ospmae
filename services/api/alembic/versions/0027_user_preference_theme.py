"""Theme preference on user_preferences and Framework-ish? No - theme only.

Revision ID: 0027_user_preference_theme
Revises: 0026_email_verification_tokens
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0027_user_preference_theme"
down_revision = "0026_email_verification_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_preferences", sa.Column("theme", sa.String(length=16), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("user_preferences", "theme")
