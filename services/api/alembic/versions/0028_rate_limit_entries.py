"""Rate-limit ledger table.

Revision ID: 0028_rate_limit_entries
Revises: 0027_user_preference_theme
Create Date: 2026-09-22

The allowance ledger counts per-address attempts (login budgeting and other
in-memory and database-backed allowances); without it the chain ends with the
application writing to a table it expects to exist.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028_rate_limit_entries"
down_revision = "0027_user_preference_theme"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("identifier", sa.String(length=255), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_rate_limit_entries_identifier", "rate_limit_entries", ["identifier"]
    )
    op.create_index(
        "ix_rate_limit_entries_timestamp", "rate_limit_entries", ["timestamp"]
    )


def downgrade() -> None:
    op.drop_index("ix_rate_limit_entries_timestamp", table_name="rate_limit_entries")
    op.drop_index("ix_rate_limit_entries_identifier", table_name="rate_limit_entries")
    op.drop_table("rate_limit_entries")
