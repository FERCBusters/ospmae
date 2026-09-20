"""Session auth metadata (OIDC logout support)

Revision ID: 0016_session_auth_metadata
Revises: 0015_proj_langs
Create Date: 2026-02-26
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0016_session_auth_metadata"
down_revision = "0015_proj_langs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Track how a session was created so logout can decide whether to trigger
    # RP-initiated logout against an OIDC provider.
    op.add_column(
        "sessions",
        sa.Column(
            "auth_method", sa.String(length=20), nullable=False, server_default="local"
        ),
    )

    # Optional: store the last OIDC id_token for this session to pass as
    # id_token_hint to the provider's end_session endpoint.
    op.add_column(
        "sessions",
        sa.Column("oidc_id_token", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sessions", "oidc_id_token")
    op.drop_column("sessions", "auth_method")
