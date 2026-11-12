"""Sessions stored as digests; unconfirmed authenticator secrets removed

Revision ID: 0040_session_digests
Revises: 0039_release_auto_publish
Create Date: 2026-11-12

The sessions table holds the SHA-256 digest of each session identifier, so a
copy of the table holds nothing a browser could present. Rows written before
hold the identifiers themselves and can no longer be matched, so they are
removed and every browser signs in again.

An authenticator's secret joins an account when its first code is confirmed,
which also turns the enrolment on. A secret on an account that is not
enrolled was never confirmed, so it is removed.
"""

from __future__ import annotations

from alembic import op

revision = "0040_session_digests"
down_revision = "0039_release_auto_publish"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM sessions")
    op.execute(
        "UPDATE users SET mfa_totp_secret = NULL, mfa_totp_last_step = -1 "
        "WHERE mfa_enabled = false AND mfa_totp_secret IS NOT NULL"
    )


def downgrade() -> None:
    # A digest cannot be turned back into the identifier it was made from.
    op.execute("DELETE FROM sessions")
