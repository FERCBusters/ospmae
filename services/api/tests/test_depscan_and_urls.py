"""URL/scan validation: repo URLs, parsers, XML, release feeds, redaction."""

from __future__ import annotations

import pytest
from app.depscan.parsers import (
    _bounded_read,
    is_supported_lockfile,
    parse_lockfile,
    redact_url,
)
from app.depscan.scan import (
    _candidate_refs,
    _extract_repo_and_tag,
    validate_repo_url,
)
from app.security.url_safety import contains_xml_dtd_or_entity, safe_relative_route_path


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://github.com/owner/repo", True),
        ("https://gitlab.com/owner/repo.git", True),
        ("git@github.com:owner/repo.git", True),
        ("https:/evil.example.com/x", False),
        ("https://user:tok@github.com/owner/repo", False),
        ("https://attacker.example.com/owner/repo", False),
        ("", False),
        ("file:///etc/passwd", False),
        ("https://github.com/owner/repo\\..\\evil", False),
        ("ssh://git@host/org/repo", False),
    ],
)
def test_validate_repo_url_matrix(url, ok):
    if ok:
        validate_repo_url(url)
    else:
        with pytest.raises(ValueError):
            validate_repo_url(url)


def test_redact_url_masks_credentials():
    out = redact_url("git clone https://user:secretpw@github.com/o/r")
    assert "secretpw" not in out
    assert "user:secretpw" not in out
    assert "github.com/o/r" in out


def test_extract_repo_and_tag():
    url, tag = _extract_repo_and_tag(
        "https://github.com/owner/repo/releases/tag/v1.2.3"
    )
    assert tag == "v1.2.3"
    assert url == "https://github.com/owner/repo"


def test_candidate_ref_variants():
    refs = _candidate_refs("v1.2.3")
    assert "v1.2.3" in refs and "1.2.3" in refs


def test_safe_relative_route_path_rejects_hosts():
    assert safe_relative_route_path("/index.html") == "/index.html"
    for bad in ("//evil", "/\\evil", None, "", "x:/y", "/a\nb"):
        assert safe_relative_route_path(bad) is None


def test_xml_dtd_scan_covers_the_whole_payload():
    head = b"<feed>" + b"<entry>ok</entry>" * 9000
    dtd = b"<!DOCTYPE feed [<!ENTITY x SYSTEM 'x'>]>"
    hidden = head + dtd  # entity declaration far beyond any head window
    assert contains_xml_dtd_or_entity(hidden)
    assert contains_xml_dtd_or_entity(b"<!doctype html><rss/>")
    assert not contains_xml_dtd_or_entity(b"<rss><entry>plain</entry></rss>")


def _write(tmp_path, name: str, content: bytes):
    p = tmp_path / name
    p.write_bytes(content)
    return p


def test_bounded_read_skips_oversize_files(tmp_path):
    p = _write(tmp_path, "package-lock.json", b"{}\n" * (3_000_000 // 4))
    assert _bounded_read(p, 1_000_000) is None
    small = _write(tmp_path, "small.json", b'{"a": 1}')
    assert _bounded_read(small, 1_000_000) == b'{"a": 1}'


def test_parsers_reject_oversize_and_symlinked_lockfiles(tmp_path):
    big = _write(tmp_path, "oversize-package-lock.json", b"0" * 5_200_000)
    assert parse_lockfile(big, max_bytes=5_000_000) == []
    target = _write(tmp_path, "package-lock-target.json", b"{}\n")
    link = tmp_path / "package-lock.json"  # the scanner should not follow it
    link.symlink_to(target)
    assert link.is_symlink()
    assert is_supported_lockfile(link)
    assert parse_lockfile(link, max_bytes=5_000_000) == []


def test_package_lock_parsing(tmp_path):
    import json

    lock = {
        "packages": {
            "node_modules/react": {"version": "18.2.0"},
            "node_modules/react-dom": {"version": "18.2.0"},
        },
        "dependencies": {"react": {"version": "18.2.0"}},
    }
    p = _write(tmp_path, "package-lock.json", json.dumps(lock).encode())
    deps = parse_lockfile(p, max_bytes=1_000_000)
    names = {d.name for d in deps}
    assert "react" in names and "react-dom" in names


def test_requirements_parsing(tmp_path):
    p = _write(tmp_path, "requirements.txt", b"flask==3.0.0\n# comment\n-r other.txt\n")
    deps = parse_lockfile(p, max_bytes=100_000)
    assert any(d.name == "flask" for d in deps)


def test_cargo_and_poetry_parsing(tmp_path):
    p = _write(
        tmp_path,
        "Cargo.lock",
        b'[[package]]\nname = "serde"\nversion = "1.0.210"\n',
    )
    deps = parse_lockfile(p, max_bytes=100_000)
    assert any(d.name == "serde" and d.ecosystem == "cargo" for d in deps)
    p2 = _write(
        tmp_path,
        "poetry.lock",
        b'[[package]]\nname = "httpx"\nversion = "0.27.0"\n',
    )
    deps = parse_lockfile(p2, max_bytes=100_000)
    assert any(d.name == "httpx" for d in deps)


def test_go_mod_and_sum_parsing(tmp_path):
    p = _write(
        tmp_path,
        "go.mod",
        b"module example.com/m\n\nrequire golang.org/x/text v0.14.0\n",
    )
    deps = parse_lockfile(p, max_bytes=100_000)
    assert any(d.name.startswith("golang.org") for d in deps)
    p2 = _write(tmp_path, "go.sum", b"golang.org/x/text v0.14.0 h1:abc=\n")
    deps = parse_lockfile(p2, max_bytes=100_000)
    assert any(d.name.startswith("golang.org") for d in deps)
