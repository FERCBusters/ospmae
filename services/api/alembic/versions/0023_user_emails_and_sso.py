"""Add account email aliases for multi-provider SSO linking.

Revision ID: 0023_user_emails_and_sso
Revises: 0022_audit_logs
Create Date: 2026-06-18
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0023_user_emails_and_sso"
down_revision = "0022_audit_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_emails",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("email_lower", sa.String(length=255), nullable=False),
        sa.Column(
            "source", sa.String(length=40), nullable=False, server_default="user"
        ),
        sa.Column(
            "is_primary", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "is_verified", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("email_lower", name="uq_user_emails_email_lower"),
    )
    op.create_index("ix_user_emails_user_id", "user_emails", ["user_id"])

    # Backfill trusted legacy local profile emails.
    op.execute("""
        INSERT INTO user_emails (
            user_id, email, email_lower, source, is_primary, is_verified, created_at, updated_at
        )
        SELECT id, lower(email), lower(email), 'legacy_user', true, true, now(), now()
        FROM users
        WHERE email IS NOT NULL AND trim(email) <> ''
        ON CONFLICT (email_lower) DO NOTHING
        """)

    # Backfill existing identity emails. These are useful for cross-provider SSO
    # linking even when users.email is empty.
    op.execute("""
        INSERT INTO user_emails (
            user_id, email, email_lower, source, is_primary, is_verified, created_at, updated_at
        )
        SELECT DISTINCT ON (lower(email))
            user_id, lower(email), lower(email), 'legacy_identity', false, true, now(), now()
        FROM user_identities
        WHERE email IS NOT NULL AND trim(email) <> ''
        ORDER BY lower(email), updated_at DESC NULLS LAST, id DESC
        ON CONFLICT (email_lower) DO NOTHING
        """)


def downgrade() -> None:
    op.drop_index("ix_user_emails_user_id", table_name="user_emails")
    op.drop_table("user_emails")
