"""URL/scan validation: repo URLs, parsers, XML, release feeds, redaction."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

import app.depscan.scan as scan_mod
import pytest
from app.depscan.parsers import (
    _bounded_read,
    is_supported_lockfile,
    parse_lockfile,
)
from app.depscan.scan import (
    _candidate_refs,
    _extract_repo_and_tag,
    validate_repo_url,
)
from app.tasks.release_feed import _parse_feed_entries


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
        # git reads a leading "-" as an option; --upload-pack names a command
        # it runs, so a value shaped like one is never a repository.
        ("--upload-pack=touch${IFS}/tmp/x;@github.com:x", False),
        ("-uid@github.com:owner/repo", False),
        ("-c@github.com:owner/repo", False),
        # The same for the path, which git hands to the remote command line.
        ("git@github.com:-oProxyCommand=x", False),
        # A transport prefix ("ext::" runs a command) is not an account name.
        ("ext::sh${IFS}-c${IFS}id@github.com:x", False),
        ("fd::3@github.com:x", False),
        # The host of the SCP-like form is the whole host, as allowlisted.
        ("git@evil.example:owner/repo", False),
        ("git@github.com.evil.example:owner/repo", False),
        ("git@:owner/repo", False),
        ("git@github.com:", False),
        ("git@gitlab.com:group/sub/project.git", True),
        ("org-123@github.com:owner/repo.git", True),
    ],
)
def test_validate_repo_url_matrix(url, ok):
    if ok:
        validate_repo_url(url)
    else:
        with pytest.raises(ValueError):
            validate_repo_url(url)


def _recorded_git(monkeypatch):
    commands: list[list[str]] = []

    def fake_run(cmd, **_kwargs):
        commands.append(list(cmd))
        # Every ref asked about exists, as ls-remote would report it.
        out = f"abc {cmd[-1]}\n" if "ls-remote" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=out)

    monkeypatch.setattr(scan_mod.subprocess, "run", fake_run)
    return commands


def test_git_reads_the_repository_after_its_options_end(monkeypatch):
    """Every git command places ``--`` before the URL: what follows it is a
    repository, never an option, whatever a stored value holds."""
    commands = _recorded_git(monkeypatch)
    url = "https://github.com/owner/repo"
    scan_mod._remote_has_ref(url, "v1.0.0", kind="tag")
    scan_mod._remote_has_ref(url, "main", kind="branch")
    for branch in ("main", None):
        repo_dir, _ = scan_mod.clone_repo(url, branch=branch)
        shutil.rmtree(repo_dir, ignore_errors=True)
    remote = [cmd for cmd in commands if "ls-remote" in cmd or "clone" in cmd]
    assert {cmd[3] for cmd in remote} == {"ls-remote", "clone"}
    for cmd in remote:
        marker = cmd.index("--")
        assert cmd[marker + 1] == url, cmd
        # Nothing after the marker is one of git's options.
        assert not any(arg.startswith("-") for arg in cmd[marker + 1 :]), cmd


def test_a_clone_refuses_an_option_shaped_url_before_git_runs(monkeypatch):
    commands = _recorded_git(monkeypatch)
    for url in (
        "--upload-pack=touch${IFS}/tmp/x;@github.com:x",
        "-uid@github.com:owner/repo",
    ):
        with pytest.raises(ValueError):
            scan_mod.clone_repo(url, version_hint="1.0.0")
        with pytest.raises(ValueError):
            scan_mod.clone_repo(url, branch="main")
    assert commands == []


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_git_itself_runs_no_command_named_by_a_url(tmp_path):
    """The real git, given the value that once reached it as an option: the
    command it names does not run, because the value follows ``--``."""
    marker = tmp_path / "ran"
    url = f"--upload-pack=touch${{IFS}}{marker};@github.com:x"
    # Only local repositories are allowed here, so nothing leaves the machine
    # when git reads the value as an SSH address.
    env = {**scan_mod._git_env(), "GIT_ALLOW_PROTOCOL": "file"}
    for kind in ("tag", "branch"):
        assert scan_mod._remote_has_ref(url, "v1.0.0", kind=kind, env=env) is False
    assert not marker.exists()
    # Without the marker the same value is an option, and git runs it: the
    # check above would fail if ``--`` were dropped.
    subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", url, "refs/tags/v1.0.0"],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert marker.exists()


def test_extract_repo_and_tag():
    url, tag = _extract_repo_and_tag(
        "https://github.com/owner/repo/releases/tag/v1.2.3"
    )
    assert tag == "v1.2.3"
    assert url == "https://github.com/owner/repo"


def test_candidate_ref_variants():
    refs = _candidate_refs("v1.2.3")
    assert "v1.2.3" in refs and "1.2.3" in refs


def test_a_declaration_anywhere_in_a_feed_is_refused():
    head = b"<rss><channel>" + b"<item><title>ok</title></item>" * 9000
    with pytest.raises(ET.ParseError):
        # A declaration may only precede the root; this one cannot even parse.
        _parse_feed_entries(head + b"<!DOCTYPE rss [<!ENTITY x 'x'>]></channel></rss>")
    with pytest.raises(ET.ParseError):
        _parse_feed_entries(b"<!doctype html><rss/>")
    with pytest.raises(ET.ParseError):
        # Processing instructions are refused too.
        _parse_feed_entries(b"<?xml-stylesheet href='x'?><rss/>")


def _write(tmp_path, name: str, content: bytes):
    p = tmp_path / name
    p.write_bytes(content)
    return p


_FEED = (
    '<?xml version="1.0" encoding="{encoding}"?>{declarations}'
    "<rss><channel><item><title>v1.0.0{entity}</title>"
    "<link>https://github.com/owner/repo/releases/tag/v1.0.0</link>"
    "</item></channel></rss>"
)
_DECLARATIONS = '<!DOCTYPE rss [<!ENTITY a "AAAAAAAAAA">]>'


def _feed(encoding: str, *, declared: bool) -> bytes:
    """The feed as a server would send it. A single-byte encoding keeps its
    XML declaration in ASCII, which is how a parser learns the encoding."""
    text = _FEED.format(
        encoding=encoding,
        declarations=_DECLARATIONS if declared else "",
        entity=" &a;" if declared else "",
    )
    if encoding == "utf-16":
        return text.encode("utf-16")
    head, _, body = text.partition("?>")
    return (head + "?>").encode("ascii") + body.encode(encoding)


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "utf-16"])
def test_a_declaration_is_refused_in_every_encoding_the_parser_reads(encoding):
    raw = _feed(encoding, declared=True)
    # Unguarded, the standard parser reads the declaration and expands it.
    expanded = ET.fromstring(raw).find(".//title").text  # noqa: S314 - the unsafe baseline
    assert expanded == "v1.0.0 AAAAAAAAAA"
    with pytest.raises(ET.ParseError, match="document type declaration"):
        _parse_feed_entries(raw)


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "utf-16"])
def test_a_feed_without_declarations_parses_in_any_encoding(encoding):
    raw = _feed(encoding, declared=False)
    entries = _parse_feed_entries(raw)
    assert [entry["title"] for entry in entries] == ["v1.0.0"]
    assert entries[0]["link"] == "https://github.com/owner/repo/releases/tag/v1.0.0"


def test_an_encoding_the_parser_cannot_read_is_a_parse_error():
    # EBCDIC shares no bytes with ASCII; the parser refuses the document
    # outright, so nothing in it is read, declarations included.
    with pytest.raises(ET.ParseError):
        _parse_feed_entries(_feed("cp037", declared=True))


def test_malformed_xml_is_still_a_parse_error():
    with pytest.raises(ET.ParseError):
        _parse_feed_entries(b"<rss><channel>")


def test_a_feed_over_the_size_limit_is_refused_before_parsing(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "release_feed_max_bytes", 64)
    with pytest.raises(ET.ParseError, match="are refused"):
        _parse_feed_entries(_feed("utf-8", declared=False))


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
