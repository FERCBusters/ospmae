"""rename component terminology to projects

Revision ID: 0008_projects_rename
Revises: 0007_user_shortcuts
Create Date: 2026-02-24 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

# NOTE: Alembic's default alembic_version.version_num column is VARCHAR(32).
# Keep revision identifiers <= 32 chars to avoid truncation errors on upgrade.
revision = "0008_projects_rename"
down_revision = "0007_user_shortcuts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- table renames ---
    op.rename_table("components", "projects")
    op.rename_table("component_versions", "project_versions")
    op.rename_table("component_owner_groups", "project_owner_groups")
    op.rename_table(
        "component_version_framework_nodes", "project_version_framework_nodes"
    )
    op.rename_table("manifest_components", "manifest_projects")
    op.rename_table(
        "manifest_component_framework_nodes", "manifest_project_framework_nodes"
    )
    op.rename_table("component_question_threads", "project_question_threads")
    op.rename_table("component_question_posts", "project_question_posts")

    # --- column renames ---
    op.alter_column(
        "project_owner_groups",
        "component_id",
        new_column_name="project_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "project_versions",
        "component_id",
        new_column_name="project_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "project_versions",
        "component_base_name",
        new_column_name="project_base_name",
        existing_type=sa.String(length=200),
    )
    op.alter_column(
        "project_version_framework_nodes",
        "component_version_id",
        new_column_name="project_version_id",
        existing_type=sa.Integer(),
    )

    op.alter_column(
        "manifest_projects",
        "component_id",
        new_column_name="project_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "manifest_projects",
        "component_version_id",
        new_column_name="project_version_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "manifest_projects",
        "component_type",
        new_column_name="project_type",
        existing_type=sa.String(length=160),
    )
    op.alter_column(
        "manifest_project_framework_nodes",
        "manifest_component_id",
        new_column_name="manifest_project_id",
        existing_type=sa.Integer(),
    )

    op.alter_column(
        "project_question_threads",
        "component_id",
        new_column_name="project_id",
        existing_type=sa.Integer(),
    )

    # --- data: permission codes ---
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'project.write' WHERE code = 'component.write'"""
        )
    )
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'project.question' WHERE code = 'component.question'"""
        )
    )
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'project.answer' WHERE code = 'component.answer'"""
        )
    )
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'project.diff' WHERE code = 'component.diff'"""
        )
    )

    # --- data: manifests filter json key ---
    # NOTE: manifests.filters_json was historically created as JSON in an earlier migration.
    # The key-existence (?) operator and (-) delete operator are JSONB-only, so we first
    # upgrade the column to JSONB (lossless) and set an explicit JSONB default.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    manifest_cols = {c["name"]: c for c in inspector.get_columns("manifests")}
    if "filters_json" in manifest_cols:
        existing_type = manifest_cols["filters_json"]["type"]
        if not isinstance(existing_type, pg.JSONB):
            op.alter_column(
                "manifests",
                "filters_json",
                type_=pg.JSONB(),
                postgresql_using="filters_json::jsonb",
                existing_type=existing_type,
                existing_nullable=False,
            )
            op.alter_column(
                "manifests",
                "filters_json",
                server_default=sa.text("'{}'::jsonb"),
                existing_nullable=False,
            )

    # Convert {"component_ids":[...]} to {"project_ids":[...]} for existing manifests.
    op.execute(sa.text("""UPDATE manifests
        SET filters_json =
            CASE
                WHEN filters_json ? 'component_ids' THEN
                    (filters_json - 'component_ids') || jsonb_build_object('project_ids', filters_json->'component_ids')
                ELSE filters_json
            END
    """))
    op.execute(sa.text("""UPDATE manifests
        SET filters_json =
            CASE
                WHEN filters_json ? 'component_id' THEN
                    (filters_json - 'component_id') || jsonb_build_object('project_id', filters_json->'component_id')
                ELSE filters_json
            END
    """))


def downgrade() -> None:
    # --- reverse data: manifests filter json key ---
    op.execute(sa.text("""UPDATE manifests
        SET filters_json =
            CASE
                WHEN filters_json ? 'project_ids' THEN
                    (filters_json - 'project_ids') || jsonb_build_object('component_ids', filters_json->'project_ids')
                ELSE filters_json
            END
    """))
    op.execute(sa.text("""UPDATE manifests
        SET filters_json =
            CASE
                WHEN filters_json ? 'project_id' THEN
                    (filters_json - 'project_id') || jsonb_build_object('component_id', filters_json->'project_id')
                ELSE filters_json
            END
    """))

    # If we upgraded manifests.filters_json to JSONB on upgrade, downgrade it back to JSON
    # to match the historical schema.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    manifest_cols = {c["name"]: c for c in inspector.get_columns("manifests")}
    if "filters_json" in manifest_cols:
        existing_type = manifest_cols["filters_json"]["type"]
        if isinstance(existing_type, pg.JSONB):
            op.alter_column(
                "manifests",
                "filters_json",
                type_=sa.JSON(),
                postgresql_using="filters_json::json",
                existing_type=existing_type,
                existing_nullable=False,
            )
            op.alter_column(
                "manifests",
                "filters_json",
                server_default=sa.text("'{}'"),
                existing_nullable=False,
            )

    # --- reverse data: permission codes ---
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'component.write' WHERE code = 'project.write'"""
        )
    )
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'component.question' WHERE code = 'project.question'"""
        )
    )
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'component.answer' WHERE code = 'project.answer'"""
        )
    )
    op.execute(
        sa.text(
            """UPDATE permissions SET code = 'component.diff' WHERE code = 'project.diff'"""
        )
    )

    # --- reverse column renames ---
    op.alter_column(
        "project_question_threads",
        "project_id",
        new_column_name="component_id",
        existing_type=sa.Integer(),
    )

    op.alter_column(
        "manifest_project_framework_nodes",
        "manifest_project_id",
        new_column_name="manifest_component_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "manifest_projects",
        "project_type",
        new_column_name="component_type",
        existing_type=sa.String(length=160),
    )
    op.alter_column(
        "manifest_projects",
        "project_version_id",
        new_column_name="component_version_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "manifest_projects",
        "project_id",
        new_column_name="component_id",
        existing_type=sa.Integer(),
    )

    op.alter_column(
        "project_version_framework_nodes",
        "project_version_id",
        new_column_name="component_version_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "project_versions",
        "project_base_name",
        new_column_name="component_base_name",
        existing_type=sa.String(length=200),
    )
    op.alter_column(
        "project_versions",
        "project_id",
        new_column_name="component_id",
        existing_type=sa.Integer(),
    )
    op.alter_column(
        "project_owner_groups",
        "project_id",
        new_column_name="component_id",
        existing_type=sa.Integer(),
    )

    # --- reverse table renames ---
    op.rename_table("project_question_posts", "component_question_posts")
    op.rename_table("project_question_threads", "component_question_threads")
    op.rename_table(
        "manifest_project_framework_nodes", "manifest_component_framework_nodes"
    )
    op.rename_table("manifest_projects", "manifest_components")
    op.rename_table(
        "project_version_framework_nodes", "component_version_framework_nodes"
    )
    op.rename_table("project_owner_groups", "component_owner_groups")
    op.rename_table("project_versions", "component_versions")
    op.rename_table("projects", "components")
