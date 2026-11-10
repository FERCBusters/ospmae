"""Private repositories: one write-only access token per project

Revision ID: 0035_private_repositories
Revises: 0034_sign_in_throttle
Create Date: 2026-11-11

The token is stored Fernet-encrypted (app/security/repo_credentials.py) and
bound to the host it was saved for; existing projects stay public.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0035_private_repositories"
down_revision = "0034_sign_in_throttle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column(
            "repo_private", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "projects", sa.Column("repo_token_host", sa.String(255), nullable=True)
    )
    op.add_column(
        "projects", sa.Column("repo_token_username", sa.String(100), nullable=True)
    )
    op.add_column(
        "projects", sa.Column("repo_token_encrypted", sa.Text(), nullable=True)
    )
    op.add_column(
        "projects", sa.Column("repo_token_updated_at", sa.DateTime(), nullable=True)
    )


def downgrade() -> None:
    for column in (
        "repo_token_updated_at",
        "repo_token_encrypted",
        "repo_token_username",
        "repo_token_host",
        "repo_private",
    ):
        op.drop_column("projects", column)
