"""Administrator-managed configuration: installation feature switches

Revision ID: 0036_managed_configurations
Revises: 0035_private_repositories
Create Date: 2026-11-11

Ported from KEEN. Each named configuration holds one JSON document and a
version that saves check against; every saved version is kept as a revision.
No row means every feature the deployment allows is on.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0036_managed_configurations"
down_revision = "0035_private_repositories"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "managed_configurations",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "updated_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "managed_configuration_revisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column(
            "updated_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("name", "version"),
    )
    op.create_index(
        "ix_managed_configuration_revisions_name",
        "managed_configuration_revisions",
        ["name"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_managed_configuration_revisions_name",
        table_name="managed_configuration_revisions",
    )
    op.drop_table("managed_configuration_revisions")
    op.drop_table("managed_configurations")
