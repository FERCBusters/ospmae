"""Add manifest storage and component ownership controls

Revision ID: 0003_manifests_and_component
Revises: 0002_component_version_latest
Create Date: 2026-02-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_manifests_and_component"
down_revision = "0002_component_version_latest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    component_columns = {c["name"] for c in inspector.get_columns("components")}
    if "created_by_user_id" not in component_columns:
        op.add_column(
            "components", sa.Column("created_by_user_id", sa.Integer(), nullable=True)
        )
        op.create_foreign_key(
            "fk_components_created_by_user_id_users",
            "components",
            "users",
            ["created_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_index(
            "ix_components_created_by_user_id",
            "components",
            ["created_by_user_id"],
            unique=False,
        )

    if "component_owner_groups" not in inspector.get_table_names():
        op.create_table(
            "component_owner_groups",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column(
                "component_id",
                sa.Integer(),
                sa.ForeignKey("components.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "group_id",
                sa.Integer(),
                sa.ForeignKey("groups.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.UniqueConstraint(
                "component_id", "group_id", name="uq_component_owner_group"
            ),
        )
        op.create_index(
            "ix_component_owner_groups_component_id",
            "component_owner_groups",
            ["component_id"],
            unique=False,
        )
        op.create_index(
            "ix_component_owner_groups_group_id",
            "component_owner_groups",
            ["group_id"],
            unique=False,
        )

    if "manifests" not in inspector.get_table_names():
        op.create_table(
            "manifests",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column(
                "created_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "owner_group_id",
                sa.Integer(),
                sa.ForeignKey("groups.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("query_text", sa.String(length=500), nullable=True),
            sa.Column(
                "filters_json",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=False),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=False),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )
        op.create_index(
            "ix_manifests_created_by_user_id",
            "manifests",
            ["created_by_user_id"],
            unique=False,
        )
        op.create_index(
            "ix_manifests_owner_group_id", "manifests", ["owner_group_id"], unique=False
        )

    if "manifest_components" not in inspector.get_table_names():
        op.create_table(
            "manifest_components",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column(
                "manifest_id",
                sa.Integer(),
                sa.ForeignKey("manifests.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "component_id",
                sa.Integer(),
                sa.ForeignKey("components.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "component_version_id",
                sa.Integer(),
                sa.ForeignKey("component_versions.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("machine_name", sa.String(length=160), nullable=False),
            sa.Column("display_name", sa.String(length=200), nullable=False),
            sa.Column("organisation", sa.String(length=200), nullable=True),
            sa.Column("component_type", sa.String(length=160), nullable=True),
            sa.Column(
                "open_source", sa.Boolean(), nullable=False, server_default=sa.true()
            ),
            sa.Column("license", sa.String(length=120), nullable=True),
            sa.Column("latest_version", sa.String(length=64), nullable=True),
            sa.Column(
                "latest_release_date", sa.DateTime(timezone=False), nullable=True
            ),
            sa.Column(
                "dependencies",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            ),
            sa.Column(
                "supported_profiles",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            ),
            sa.Column(
                "supported_formats",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            ),
            sa.Column("link_to_app", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=False),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )
        op.create_index(
            "ix_manifest_components_manifest_id",
            "manifest_components",
            ["manifest_id"],
            unique=False,
        )
        op.create_index(
            "ix_manifest_components_component_id",
            "manifest_components",
            ["component_id"],
            unique=False,
        )
        op.create_index(
            "ix_manifest_components_component_version_id",
            "manifest_components",
            ["component_version_id"],
            unique=False,
        )

    if "manifest_component_capabilities" not in inspector.get_table_names():
        op.create_table(
            "manifest_component_capabilities",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column(
                "manifest_component_id",
                sa.Integer(),
                sa.ForeignKey("manifest_components.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "capability_node_id",
                sa.Integer(),
                sa.ForeignKey("capability_nodes.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("capability_path", sa.Text(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=False),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.UniqueConstraint(
                "manifest_component_id",
                "capability_node_id",
                name="uq_manifest_component_capability",
            ),
        )
        op.create_index(
            "ix_manifest_component_capabilities_manifest_component_id",
            "manifest_component_capabilities",
            ["manifest_component_id"],
            unique=False,
        )
        op.create_index(
            "ix_manifest_component_capabilities_capability_node_id",
            "manifest_component_capabilities",
            ["capability_node_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "manifest_component_capabilities" in inspector.get_table_names():
        op.drop_index(
            "ix_manifest_component_capabilities_capability_node_id",
            table_name="manifest_component_capabilities",
        )
        op.drop_index(
            "ix_manifest_component_capabilities_manifest_component_id",
            table_name="manifest_component_capabilities",
        )
        op.drop_table("manifest_component_capabilities")

    if "manifest_components" in inspector.get_table_names():
        op.drop_index(
            "ix_manifest_components_component_version_id",
            table_name="manifest_components",
        )
        op.drop_index(
            "ix_manifest_components_component_id", table_name="manifest_components"
        )
        op.drop_index(
            "ix_manifest_components_manifest_id", table_name="manifest_components"
        )
        op.drop_table("manifest_components")

    if "manifests" in inspector.get_table_names():
        op.drop_index("ix_manifests_owner_group_id", table_name="manifests")
        op.drop_index("ix_manifests_created_by_user_id", table_name="manifests")
        op.drop_table("manifests")

    if "component_owner_groups" in inspector.get_table_names():
        op.drop_index(
            "ix_component_owner_groups_group_id", table_name="component_owner_groups"
        )
        op.drop_index(
            "ix_component_owner_groups_component_id",
            table_name="component_owner_groups",
        )
        op.drop_table("component_owner_groups")

    component_columns = {c["name"] for c in inspector.get_columns("components")}
    if "created_by_user_id" in component_columns:
        op.drop_index("ix_components_created_by_user_id", table_name="components")
        op.drop_constraint(
            "fk_components_created_by_user_id_users", "components", type_="foreignkey"
        )
        op.drop_column("components", "created_by_user_id")
