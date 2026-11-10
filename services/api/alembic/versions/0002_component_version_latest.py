"""Add explicit is_latest flag for component versions

Revision ID: 0002_component_version_latest
Revises: 0001_initial_component_catalog
Create Date: 2026-02-17
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_component_version_latest"
down_revision = "0001_initial_component_catalog"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("component_versions")}
    if "is_latest" not in columns:
        op.add_column(
            "component_versions",
            sa.Column(
                "is_latest", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
        )

    op.execute("""
        WITH ranked AS (
            SELECT
                id,
                component_id,
                ROW_NUMBER() OVER (
                    PARTITION BY component_id
                    ORDER BY COALESCE(release_date, created_at) DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
                ) AS rn
            FROM component_versions
        )
        UPDATE component_versions cv
        SET is_latest = CASE WHEN ranked.rn = 1 THEN TRUE ELSE FALSE END
        FROM ranked
        WHERE cv.id = ranked.id
        """)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("component_versions")}
    if "is_latest" in columns:
        op.drop_column("component_versions", "is_latest")
