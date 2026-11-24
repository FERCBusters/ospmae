"""Navbar shortcuts keep to this installation's own pages."""

from __future__ import annotations

import pytest

from tests.conftest import auth_client
from tests.support import csrf


def test_shortcut_urls_must_be_same_origin(client):
    from app.api.routes.me import _normalize_shortcut_url
    from fastapi import HTTPException

    assert _normalize_shortcut_url("/project.html?id=1") == "/project.html?id=1"
    for bad in ("//evil.example.com", "/\\evil", "javascript:alert(1)", "", "http://x"):
        try:
            _normalize_shortcut_url(bad)
        except HTTPException:
            continue
        raise AssertionError(f"accepted unsafe shortcut: {bad!r}")


@pytest.mark.parametrize(
    "path",
    [
        "/.//evil.example/x",
        "/..//evil.example",
        "/a/..//evil.example",
        "/%2e//evil.example",
        "/%2E%2e//evil.example",
        "/a/./b",
        "/a/..",
        "/.",
    ],
)
def test_a_shortcut_with_a_dot_segment_is_refused(path):
    """A browser resolves the segment first, and "/.//host" becomes "//host"."""
    client, _ = auth_client(role="viewer")
    response = client.post(
        "/v1/me/shortcuts", json={"name": "s", "url": path}, headers=csrf(client)
    )
    assert response.status_code in (400, 422), response.text


@pytest.mark.parametrize(
    "path",
    [
        "/project.html?id=3&tab=../x",
        "/dependencies.html#./section",
        "/a.b/c..d/.hidden",
        "/files/v1.2.3/notes...txt",
    ],
)
def test_dots_that_are_not_segments_are_kept(path):
    client, _ = auth_client(role="viewer")
    response = client.post(
        "/v1/me/shortcuts", json={"name": "s", "url": path}, headers=csrf(client)
    )
    assert response.status_code == 200, response.text
    assert response.json()["url"] == path
