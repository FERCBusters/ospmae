"""Purge sensitive auth callback audit log rows.

Revision ID: 0024_purge_auth_callback_audit_logs
Revises: 0023_user_emails_and_sso
Create Date: 2026-06-18
"""

from __future__ import annotations

from alembic import op

revision = "0024_purge_auth_callback"
down_revision = "0023_user_emails_and_sso"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DELETE FROM audit_logs
        WHERE lower(path) LIKE '%/v1/auth%'
          AND lower(path) LIKE '%callback%'
        """)


def downgrade() -> None:
    # Data deletion cannot be reversed.
    pass
