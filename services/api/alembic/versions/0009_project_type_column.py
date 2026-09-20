"""rename component_type column on projects

Revision ID: 0009_project_type
Revises: 0008_projects_rename
Create Date: 2026-02-24 00:10:00

Follow-up fix for the Component -> Project rename.

The 0008 migration renames the *tables* from components -> projects, but the
projects table retained the original column name 'component_type'. The
application code expects 'project_type'.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0009_project_type"
down_revision = "0008_projects_rename"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    cols = {c["name"]: c for c in inspector.get_columns("projects")}
    if "component_type" in cols and "project_type" not in cols:
        op.alter_column(
            "projects",
            "component_type",
            new_column_name="project_type",
            existing_type=cols["component_type"].get("type") or sa.String(length=160),
            existing_nullable=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    cols = {c["name"]: c for c in inspector.get_columns("projects")}
    if "project_type" in cols and "component_type" not in cols:
        op.alter_column(
            "projects",
            "project_type",
            new_column_name="component_type",
            existing_type=cols["project_type"].get("type") or sa.String(length=160),
            existing_nullable=True,
        )
