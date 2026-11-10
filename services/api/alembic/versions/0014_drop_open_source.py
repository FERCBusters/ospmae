"""Drop open_source fields from projects and manifest_projects

Revision ID: 0014_drop_open_source
Revises: 0013_oidc_auth
Create Date: 2026-02-25

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_drop_open_source"
down_revision = "0013_oidc_auth"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    try:
        cols = insp.get_columns(table)
    except Exception:
        return False
    return any(c.get("name") == column for c in cols)


def upgrade() -> None:
    # Field is no longer used by the application; remove it from both catalog and manifest snapshots.
    if _has_column("projects", "open_source"):
        with op.batch_alter_table("projects") as batch:
            batch.drop_column("open_source")

    if _has_column("manifest_projects", "open_source"):
        with op.batch_alter_table("manifest_projects") as batch:
            batch.drop_column("open_source")


def downgrade() -> None:
    # Re-introduce with the historic default.
    if not _has_column("projects", "open_source"):
        with op.batch_alter_table("projects") as batch:
            batch.add_column(
                sa.Column(
                    "open_source",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("true"),
                )
            )

    if not _has_column("manifest_projects", "open_source"):
        with op.batch_alter_table("manifest_projects") as batch:
            batch.add_column(
                sa.Column(
                    "open_source",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("true"),
                )
            )
