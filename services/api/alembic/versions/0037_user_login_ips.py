"""Known sign-in addresses per account

Revision ID: 0037_user_login_ips
Revises: 0036_managed_configurations
Create Date: 2026-11-11

Ported from KEEN. A completed sign-in from an address the account has not
signed in from before mails the account a security notice. The table starts
empty, so each account's first sign-in from an address after this upgrade
sends one notice.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0037_user_login_ips"
down_revision = "0036_managed_configurations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_login_ips",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("address", sa.String(45), primary_key=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("user_login_ips")
