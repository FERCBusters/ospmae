"""Navbar shortcuts keep to this installation's own pages."""

from __future__ import annotations


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
