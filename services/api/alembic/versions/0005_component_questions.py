"""add component questions

Revision ID: 0005_component_questions
Revises: 0004_user_preferences
Create Date: 2026-02-19 00:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0005_component_questions"
down_revision = "0004_user_preferences"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "component_question_threads",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("component_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="open"
        ),
        sa.Column("last_answer_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["component_id"], ["components.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_component_question_threads_component_id",
        "component_question_threads",
        ["component_id"],
        unique=False,
    )
    op.create_index(
        "ix_component_question_threads_created_by_user_id",
        "component_question_threads",
        ["created_by_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_component_question_threads_status",
        "component_question_threads",
        ["status"],
        unique=False,
    )

    op.create_table(
        "component_question_posts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("thread_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["thread_id"], ["component_question_threads.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_component_question_posts_thread_id",
        "component_question_posts",
        ["thread_id"],
        unique=False,
    )
    op.create_index(
        "ix_component_question_posts_created_by_user_id",
        "component_question_posts",
        ["created_by_user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_component_question_posts_created_by_user_id",
        table_name="component_question_posts",
    )
    op.drop_index(
        "ix_component_question_posts_thread_id", table_name="component_question_posts"
    )
    op.drop_table("component_question_posts")

    op.drop_index(
        "ix_component_question_threads_status", table_name="component_question_threads"
    )
    op.drop_index(
        "ix_component_question_threads_created_by_user_id",
        table_name="component_question_threads",
    )
    op.drop_index(
        "ix_component_question_threads_component_id",
        table_name="component_question_threads",
    )
    op.drop_table("component_question_threads")
