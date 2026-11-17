"""Private-repository tokens bound to one repository

Revision ID: 0041_repo_token_repository
Revises: 0040_session_digests
Create Date: 2026-11-18

A project's access token was bound to a host. It is now bound to the one
repository it is for: no clone of anything else carries it, and a private
project's versions, tracked branch and feed releases live there.

Existing private projects are given the repository they already point at
where that is plain: the tracked repository, else the repository every one
of the project's versions links to. Where it is not plain (no link, or links
to more than one repository) the column stays empty and the project's scans
stop until someone who can edit it enters the repository and the token again.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import sqlalchemy as sa
from alembic import op

revision = "0041_repo_token_repository"
down_revision = "0040_session_digests"
branch_labels = None
depends_on = None

# Kept here, not imported: a migration describes the data as it was read at
# this revision, whatever the application's helpers later become.
_INSIDE_REPOSITORY = {
    "-",
    "releases",
    "releases.atom",
    "releases.rss",
    "tags",
    "tags.atom",
    "tags.rss",
    "tree",
    "blob",
    "archive",
    "commit",
    "commits",
}


def _repository_of(url: str | None, host: str | None) -> str | None:
    try:
        parts = urlsplit((url or "").strip())
        port = parts.port
    except ValueError:
        return None
    name = (parts.hostname or "").lower().rstrip(".")
    if (
        parts.scheme != "https"
        or not name
        or name != (host or "").lower()
        or port not in (None, 443)
        or parts.username
        or parts.password
    ):
        return None
    segments: list[str] = []
    for segment in parts.path.split("/"):
        if not segment:
            continue
        if segment in _INSIDE_REPOSITORY and segments:
            break
        segments.append(segment)
    if segments and segments[-1].lower().endswith(".git"):
        segments[-1] = segments[-1][:-4]
    if len(segments) < 2 or any(s in {".", ".."} for s in segments):
        return None
    repository = f"https://{name}/{'/'.join(segments)}"
    return repository if len(repository) <= 600 else None


def _bind_saved_tokens(bind) -> None:
    """Give each saved token the repository its project already points at."""
    projects = bind.execute(
        sa.text(
            "SELECT id, repo_token_host, track_branch, tracked_repo_url "
            "FROM projects WHERE repo_private AND repo_token_encrypted IS NOT NULL"
        )
    ).fetchall()
    for project_id, host, track_branch, tracked_repo_url in projects:
        if track_branch and tracked_repo_url:
            found = {_repository_of(tracked_repo_url, host)}
        else:
            links = bind.execute(
                sa.text(
                    "SELECT DISTINCT link_to_source_code FROM project_versions "
                    "WHERE project_id = :id AND link_to_source_code IS NOT NULL "
                    "AND link_to_source_code <> ''"
                ),
                {"id": project_id},
            ).fetchall()
            found = {_repository_of(link, host) for (link,) in links}
        # One repository, and nothing that is not one.
        named = {r.casefold() for r in found if r}
        if len(named) == 1 and None not in found:
            bind.execute(
                sa.text(
                    "UPDATE projects SET repo_token_repository = :repository "
                    "WHERE id = :id"
                ),
                {"repository": min(r for r in found if r), "id": project_id},
            )


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("repo_token_repository", sa.String(length=600), nullable=True),
    )
    _bind_saved_tokens(op.get_bind())


def downgrade() -> None:
    op.drop_column("projects", "repo_token_repository")
