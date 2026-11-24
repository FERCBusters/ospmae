"""Addresses OSPMAE fetches: release feeds and repositories users name."""

from __future__ import annotations

import pytest
from app.security.url_safety import (
    _is_private_ip,
    _resolve_host_ips,
    validate_public_http_url,
    validate_public_https_url,
)


def test_a_fetched_address_is_a_public_server():
    assert validate_public_http_url("https://example.com/x") == "https://example.com/x"
    assert validate_public_http_url("") == ""
    for refused in (
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://10.1.2.3",
        "javascript:alert(1)",
        "//evil.example",
        "ftp://example.com",
        "https://a:b@example.com",
        "https://example.com\\@evil.example",
    ):
        with pytest.raises(ValueError):
            validate_public_http_url(refused)


def test_a_fetched_address_uses_https():
    assert validate_public_https_url("https://example.com/feed") == (
        "https://example.com/feed"
    )
    with pytest.raises(ValueError, match="Only https"):
        validate_public_https_url("http://example.com/feed")


def test_private_ip_check():
    assert _is_private_ip("10.0.0.1")
    assert _is_private_ip("::1")
    assert _is_private_ip("100.64.0.1")
    assert not _is_private_ip("8.8.8.8")
    assert not _is_private_ip("not-an-address")
    with pytest.raises(ValueError):
        _resolve_host_ips("nonexistent-host-ospmae.invalid")
