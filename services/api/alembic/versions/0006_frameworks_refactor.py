"""introduce frameworks + dynamic taxonomy

Revision ID: 0006_frameworks_refactor
Revises: 0005_component_questions
Create Date: 2026-02-20 00:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0006_frameworks_refactor"
down_revision = "0005_component_questions"
branch_labels = None
depends_on = None


def _table_exists(name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return name in set(insp.get_table_names())


def _column_names(table: str) -> set[str]:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    # ------------------------------------------------------------------
    # Frameworks
    # ------------------------------------------------------------------

    op.create_table(
        "frameworks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("machine_name", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("machine_name", name="uq_frameworks_machine_name"),
    )

    op.create_table(
        "framework_nodes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("framework_id", sa.Integer(), nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("key", sa.String(length=80), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("level", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["framework_id"], ["frameworks.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"], ["framework_nodes.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "framework_id", "key", name="uq_framework_nodes_framework_key"
        ),
    )

    op.create_index(
        "ix_framework_nodes_framework_id",
        "framework_nodes",
        ["framework_id"],
        unique=False,
    )
    op.create_index(
        "ix_framework_nodes_parent_id", "framework_nodes", ["parent_id"], unique=False
    )

    # ------------------------------------------------------------------
    # Component version -> framework node mapping
    # ------------------------------------------------------------------

    op.create_table(
        "component_version_framework_nodes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("component_version_id", sa.Integer(), nullable=False),
        sa.Column("framework_node_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["component_version_id"], ["component_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["framework_node_id"], ["framework_nodes.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "component_version_id",
            "framework_node_id",
            name="uq_component_version_framework_nodes_pair",
        ),
    )

    op.create_index(
        "ix_component_version_framework_nodes_component_version_id",
        "component_version_framework_nodes",
        ["component_version_id"],
        unique=False,
    )
    op.create_index(
        "ix_component_version_framework_nodes_framework_node_id",
        "component_version_framework_nodes",
        ["framework_node_id"],
        unique=False,
    )

    # ------------------------------------------------------------------
    # Manifest snapshot mapping
    # ------------------------------------------------------------------

    op.create_table(
        "manifest_component_framework_nodes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("manifest_component_id", sa.Integer(), nullable=False),
        sa.Column("framework_node_id", sa.Integer(), nullable=True),
        sa.Column("node_path", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["manifest_component_id"], ["manifest_components.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["framework_node_id"], ["framework_nodes.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_manifest_component_framework_nodes_manifest_component_id",
        "manifest_component_framework_nodes",
        ["manifest_component_id"],
        unique=False,
    )

    # ------------------------------------------------------------------
    # Manifests: associate to a framework
    # ------------------------------------------------------------------

    if _table_exists("manifests") and "framework_id" not in _column_names("manifests"):
        with op.batch_alter_table("manifests") as batch:
            batch.add_column(sa.Column("framework_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_manifests_framework_id_frameworks",
                "frameworks",
                ["framework_id"],
                ["id"],
                ondelete="SET NULL",
            )

    # ------------------------------------------------------------------
    # User preferences: rename capability_colors -> node_colors
    # ------------------------------------------------------------------

    if _table_exists("user_preferences"):
        cols = _column_names("user_preferences")
        if "capability_colors" in cols and "node_colors" not in cols:
            with op.batch_alter_table("user_preferences") as batch:
                batch.alter_column("capability_colors", new_column_name="node_colors")

    # ------------------------------------------------------------------
    # Remove legacy UWRA-specific taxonomy tables.
    # (Not required for correctness, but keeps the schema clean.)
    # ------------------------------------------------------------------
    for tname in [
        "manifest_component_capabilities",
        "component_version_capabilities",
        "capability_nodes",
    ]:
        if _table_exists(tname):
            op.drop_table(tname)


def downgrade() -> None:
    # NOTE: downgrade recreates legacy taxonomy tables is intentionally omitted.
    if _table_exists("manifests") and "framework_id" in _column_names("manifests"):
        with op.batch_alter_table("manifests") as batch:
            batch.drop_constraint(
                "fk_manifests_framework_id_frameworks", type_="foreignkey"
            )
            batch.drop_column("framework_id")

    if _table_exists("user_preferences"):
        cols = _column_names("user_preferences")
        if "node_colors" in cols and "capability_colors" not in cols:
            with op.batch_alter_table("user_preferences") as batch:
                batch.alter_column("node_colors", new_column_name="capability_colors")

    for tname in [
        "manifest_component_framework_nodes",
        "component_version_framework_nodes",
        "framework_nodes",
        "frameworks",
    ]:
        if _table_exists(tname):
            op.drop_table(tname)
