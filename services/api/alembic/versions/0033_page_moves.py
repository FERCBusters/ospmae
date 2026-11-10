"""Stored start pages and shortcuts follow the reorganised pages

Revision ID: 0033_page_moves
Revises: 0032_project_branch_tracking
Create Date: 2026-11-11

The Projects dashboard is the entry page (/index.html), the Manifest Builder
and Saved Manifests share /manifests.html, My Questions is a tab of the
Account page, and project editing lives at /project-edit.html. Saved start
pages and shortcuts that named the old pages are rewritten to their new homes:

- /index.html or / carrying a query string held Manifest Builder filters and
  moves to /manifests.html with the same query; the bare entry page stays.
- /saved-manifests.html moves to /manifests.html (a ?id= deep link survives).
- /dashboard.html becomes /index.html.
- /my-questions.html becomes /account.html#questions.
- /project-manage.html?id=... becomes /project-edit.html?id=...; the old
  project list (no id) becomes the Projects page.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0033_page_moves"
down_revision = "0032_project_branch_tracking"
branch_labels = None
depends_on = None


def _move_shortcut_prefix(bind, old: str, new: str) -> None:
    """Rewrite shortcut URLs on page ``old`` (bare, ?query or #hash) to ``new``."""

    bind.execute(
        sa.text(
            "UPDATE user_shortcuts "
            "SET url = CAST(:new AS TEXT) || substr(url, :cut) "
            "WHERE url = :old OR url LIKE :old_query OR url LIKE :old_hash"
        ),
        {
            "new": new,
            "cut": len(old) + 1,
            "old": old,
            "old_query": f"{old}?%",
            "old_hash": f"{old}#%",
        },
    )


def _move_shortcuts(bind) -> None:
    # Builder filters first, before /dashboard.html takes over /index.html.
    for old in ("/index.html?", "/?"):
        bind.execute(
            sa.text(
                "UPDATE user_shortcuts "
                "SET url = '/manifests.html?' || substr(url, :cut) "
                "WHERE url LIKE :pattern"
            ),
            {"cut": len(old) + 1, "pattern": f"{old}%"},
        )
    _move_shortcut_prefix(bind, "/saved-manifests.html", "/manifests.html")
    _move_shortcut_prefix(bind, "/dashboard.html", "/index.html")
    bind.execute(
        sa.text(
            "UPDATE user_shortcuts SET url = '/account.html#questions' "
            "WHERE url = '/my-questions.html' "
            "OR url LIKE '/my-questions.html?%' OR url LIKE '/my-questions.html#%'"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE user_shortcuts "
            "SET url = '/project-edit.html' || substr(url, :cut) "
            "WHERE url LIKE '/project-manage.html?%id=%'"
        ),
        {"cut": len("/project-manage.html") + 1},
    )
    bind.execute(
        sa.text(
            "UPDATE user_shortcuts SET url = '/index.html' "
            "WHERE url = '/project-manage.html' "
            "OR url LIKE '/project-manage.html?%' OR url LIKE '/project-manage.html#%'"
        )
    )


def _move_start_pages(bind) -> None:
    bind.execute(
        sa.text(
            "UPDATE user_preferences SET default_start_page = '/manifests.html' "
            "WHERE default_start_page = '/saved-manifests.html'"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE user_preferences SET default_start_page = '/index.html' "
            "WHERE default_start_page IN ('/project-manage.html', '/dashboard.html')"
        )
    )


def upgrade() -> None:
    bind = op.get_bind()
    _move_shortcuts(bind)
    _move_start_pages(bind)


def downgrade() -> None:
    # The old pages no longer exist; rewritten rows keep their new targets.
    pass
