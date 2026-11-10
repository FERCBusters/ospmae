"""Local second factor: TOTP, WebAuthn credentials, recovery codes.

Revision ID: 0030_local_mfa
Revises: 0029_chain_column_alignment
Create Date: 2026-09-23

Adds the account MFA state to users and sessions and the ceremony/credential
storage tables. The migration contract test replays the chain on PostgreSQL,
so the fresh-install result must match the models exactly.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0030_local_mfa"
down_revision = "0029_chain_column_alignment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "users",
        sa.Column("mfa_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("users", sa.Column("mfa_totp_secret", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "mfa_totp_last_step", sa.Integer(), nullable=False, server_default="-1"
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "mfa_code_failures", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "users", sa.Column("mfa_code_failures_since", sa.DateTime(), nullable=True)
    )

    op.add_column(
        "sessions",
        sa.Column(
            "mfa_verified", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "sessions",
        sa.Column("mfa_version", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "mfa_credentials",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("credential_id", sa.Text(), nullable=False, unique=True),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_mfa_credentials_user_id", "mfa_credentials", ["user_id"], unique=False
    )

    op.create_table(
        "mfa_recovery_codes",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("code_hash", sa.String(length=64), primary_key=True),
    )

    op.create_table(
        "mfa_challenges",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("password_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("data", JSONB(astext_type=sa.Text()), nullable=False),
    )
    op.create_index(
        "ix_mfa_challenges_user_id", "mfa_challenges", ["user_id"], unique=False
    )
    op.create_index(
        "ix_mfa_challenges_expires_at", "mfa_challenges", ["expires_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_mfa_challenges_expires_at", table_name="mfa_challenges")
    op.drop_index("ix_mfa_challenges_user_id", table_name="mfa_challenges")
    op.drop_table("mfa_challenges")
    op.drop_table("mfa_recovery_codes")
    op.drop_index("ix_mfa_credentials_user_id", table_name="mfa_credentials")
    op.drop_table("mfa_credentials")
    op.drop_column("sessions", "mfa_version")
    op.drop_column("sessions", "mfa_verified")
    op.drop_column("users", "mfa_code_failures_since")
    op.drop_column("users", "mfa_code_failures")
    op.drop_column("users", "mfa_totp_last_step")
    op.drop_column("users", "mfa_totp_secret")
    op.drop_column("users", "mfa_version")
    op.drop_column("users", "mfa_enabled")
