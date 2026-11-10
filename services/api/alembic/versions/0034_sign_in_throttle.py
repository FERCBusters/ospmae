"""Sign-in throttle and recognised browsers

Revision ID: 0034_sign_in_throttle
Revises: 0033_page_moves
Create Date: 2026-11-11

`login_throttles` counts consecutive password failures from unrecognised
browsers per compared-username digest; `login_devices` holds the hashed
device cookies of browsers that have proved an account's password. The
per-name failure and verification allowances they replace leave the rate-limit
ledger here.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0034_sign_in_throttle"
down_revision = "0033_page_moves"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "login_throttles",
        sa.Column("name_key", sa.String(length=64), primary_key=True),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("gate_until", sa.DateTime(), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_login_throttles_last_failure_at", "login_throttles", ["last_failure_at"]
    )
    op.create_table(
        "login_devices",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.Column("name_key", sa.String(length=64), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_login_devices_user_id", "login_devices", ["user_id"])
    op.create_index("ix_login_devices_expires_at", "login_devices", ["expires_at"])
    op.execute(
        sa.text(
            "DELETE FROM rate_limit_entries WHERE identifier LIKE 'login_fail_user:%' "
            "OR identifier LIKE 'login_verify_user:%'"
        )
    )


def downgrade() -> None:
    op.drop_table("login_devices")
    op.drop_table("login_throttles")
