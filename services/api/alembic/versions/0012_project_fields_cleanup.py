"""Project fields cleanup

Revision ID: 0012_project_fields_cleanup
Revises: 0011_ui_behaviour_prefs
Create Date: 2026-02-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0012_project_fields_cleanup"
down_revision = "0011_ui_behaviour_prefs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- projects cleanup ---
    op.drop_column("projects", "portability")
    op.drop_column("projects", "dependencies")
    op.drop_column("projects", "case_studies")
    op.drop_column("projects", "supported_status_managements")
    op.drop_column("projects", "supported_trust_managements")

    # --- project_versions cleanup ---
    op.drop_column("project_versions", "project_base_name")
    op.drop_column("project_versions", "metadata_json")


def downgrade() -> None:
    # --- project_versions cleanup ---
    op.add_column(
        "project_versions",
        sa.Column(
            "metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
    )
    op.add_column(
        "project_versions",
        sa.Column("project_base_name", sa.String(length=200), nullable=True),
    )

    # --- projects cleanup ---
    op.add_column(
        "projects",
        sa.Column(
            "supported_trust_managements",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "projects",
        sa.Column(
            "supported_status_managements",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "projects",
        sa.Column(
            "case_studies",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "projects",
        sa.Column(
            "dependencies",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "projects", sa.Column("portability", sa.String(length=200), nullable=True)
    )
