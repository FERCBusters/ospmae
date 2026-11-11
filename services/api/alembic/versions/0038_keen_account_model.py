"""KEEN's account model: no self-service reset, no pending sign-up

Revision ID: 0038_keen_account_model
Revises: 0037_user_login_ips
Create Date: 2026-11-11

OSPMAE manages accounts as KEEN does. An administrator resets passwords, so
the e-mailed reset tokens go. Accounts are created by administrators, so the
pending role goes: an account still pending was never approved, so it becomes
an inactive viewer for an administrator to review, and a group whose role was
pending grants no role. Account addresses follow KEEN too: the account's
e-mail is set by an administrator, and an account proves the addresses that
link single sign-on (user_sso_emails) by mailbox; addresses already verified
carry over, the rest and their verification tokens go.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038_keen_account_model"
down_revision = "0037_user_login_ips"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("password_reset_tokens")

    # An account whose role came only from a pending group was never approved
    # either; it is deactivated before those groups lose the role.
    op.execute(
        "UPDATE users SET is_active = false "
        "WHERE lower(trim(role)) = 'inherit' "
        "AND EXISTS (SELECT 1 FROM user_groups ug JOIN groups g ON g.id = ug.group_id "
        "WHERE ug.user_id = users.id AND lower(trim(g.role)) = 'pending') "
        "AND NOT EXISTS (SELECT 1 FROM user_groups ug JOIN groups g ON g.id = ug.group_id "
        "WHERE ug.user_id = users.id AND lower(trim(g.role)) IN ("
        "'admin', 'framework_admin', 'maintainer', 'contributor', 'engineer', "
        "'product_owner', 'architect', 'viewer'))"
    )
    op.execute(
        "UPDATE users SET role = 'viewer', is_active = false "
        "WHERE lower(trim(role)) = 'pending'"
    )
    op.execute("UPDATE groups SET role = NULL WHERE lower(trim(role)) = 'pending'")

    op.create_table(
        "user_sso_emails",
        sa.Column("email", sa.String(256), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("verified_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_user_sso_emails_user_id", "user_sso_emails", ["user_id"])
    op.create_table(
        "sso_email_challenges",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(256), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("mfa_version", sa.Integer(), nullable=False),
        sa.Column("password_digest", sa.String(64), nullable=False),
    )
    op.create_index(
        "ix_sso_email_challenges_user_id", "sso_email_challenges", ["user_id"]
    )
    # Verified addresses carry over; email_lower was unique, so no address
    # belongs to two accounts.
    op.execute(
        "INSERT INTO user_sso_emails (email, user_id, verified_at) "
        "SELECT email_lower, user_id, COALESCE(updated_at, created_at, now()) "
        "FROM user_emails WHERE is_verified"
    )
    op.drop_table("email_verification_tokens")
    op.drop_table("user_emails")


def downgrade() -> None:
    raise NotImplementedError("0038 removes self-service reset and sign-up data")
