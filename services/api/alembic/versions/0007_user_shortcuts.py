"""add user shortcuts

Revision ID: 0007_user_shortcuts
Revises: 0006_frameworks_refactor
Create Date: 2026-02-23 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0007_user_shortcuts"
down_revision = "0006_frameworks_refactor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_shortcuts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "name", name="uq_user_shortcuts_user_name"),
    )
    op.create_index(
        "ix_user_shortcuts_user_id", "user_shortcuts", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_user_shortcuts_user_id", table_name="user_shortcuts")
    op.drop_table("user_shortcuts")
