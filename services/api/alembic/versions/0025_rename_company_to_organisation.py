"""Rename company fields to organisation.

Revision ID: 0025_company_to_organisation
Revises: 0024_purge_auth_callback
Create Date: 2026-06-23
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0025_company_to_organisation"
down_revision = "0024_purge_auth_callback"
branch_labels = None
depends_on = None


def _rename_column_if_present(table_name: str, old_name: str, new_name: str) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table_name not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns(table_name)}
    if old_name in columns and new_name not in columns:
        op.alter_column(
            table_name,
            old_name,
            new_column_name=new_name,
            existing_type=sa.String(length=200),
            existing_nullable=True,
        )


def _has_table(table_name: str) -> bool:
    bind = op.get_bind()
    return table_name in sa.inspect(bind).get_table_names()


def _rename_jsonb_key(
    table_name: str, column_name: str, old_name: str, new_name: str
) -> None:
    if not _has_table(table_name):
        return
    op.execute(sa.text(f"""
            UPDATE {table_name}
            SET {column_name} = ({column_name} - :old_name)
                || jsonb_build_object(:new_name, {column_name}->:old_name)
            WHERE {column_name} IS NOT NULL
              AND {column_name} ? :old_name
              AND NOT ({column_name} ? :new_name)
            """).bindparams(old_name=old_name, new_name=new_name))


def _rename_changelog_change_field(
    old_name: str, new_name: str, new_label: str
) -> None:
    if not _has_table("entity_changelogs"):
        return
    op.execute(sa.text("""
            UPDATE entity_changelogs
            SET changes = COALESCE((
                SELECT jsonb_agg(
                    CASE
                        WHEN change_item->>'field' = :old_name THEN
                            change_item || jsonb_build_object(
                                'field', :new_name, 'label', :new_label
                            )
                        ELSE change_item
                    END
                    ORDER BY ordinality
                )
                FROM jsonb_array_elements(changes) WITH ORDINALITY
                    AS items(change_item, ordinality)
            ), '[]'::jsonb)
            WHERE changes @> jsonb_build_array(jsonb_build_object('field', :old_name))
            """).bindparams(old_name=old_name, new_name=new_name, new_label=new_label))


def _replace_changelog_summary(old_label: str, new_label: str) -> None:
    if not _has_table("entity_changelogs"):
        return
    op.execute(sa.text("""
            UPDATE entity_changelogs
            SET summary = replace(summary, :old_label, :new_label)
            WHERE summary LIKE ('%' || :old_label || '%')
            """).bindparams(old_label=old_label, new_label=new_label))


def upgrade() -> None:
    _rename_column_if_present("projects", "company", "organisation")
    _rename_column_if_present("manifest_projects", "company", "organisation")
    _rename_jsonb_key("entity_changelogs", "before_state", "company", "organisation")
    _rename_jsonb_key("entity_changelogs", "after_state", "company", "organisation")
    _rename_changelog_change_field("company", "organisation", "Organisation")
    _replace_changelog_summary("Company", "Organisation")


def downgrade() -> None:
    _replace_changelog_summary("Organisation", "Company")
    _rename_changelog_change_field("organisation", "company", "Company")
    _rename_jsonb_key("entity_changelogs", "before_state", "organisation", "company")
    _rename_jsonb_key("entity_changelogs", "after_state", "organisation", "company")
    _rename_column_if_present("projects", "organisation", "company")
    _rename_column_if_present("manifest_projects", "organisation", "company")
