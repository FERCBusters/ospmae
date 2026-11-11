"""Release feeds end to end: real Atom and RSS documents fetched over a
stubbed HTTP transport, parsed, filtered and imported by the Celery tasks."""

from __future__ import annotations

import socket
from datetime import datetime

import httpx
import pytest
from app.core.config import settings
from app.db.models import Project, ProjectVersion
from app.db.session import SessionLocal
from app.depscan.scan import repository_url_for_release_link
from app.tasks import release_feed as rf

from tests.support import (
    csrf,
    make_framework,
    make_group,
    make_node,
    make_project,
    make_version,
    map_nodes,
    ok,
    signed_in,
)

FEED = "https://feeds.example.org/releases.atom"
REPO = "https://github.com/example/repo"


def atom(*entries: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<feed xmlns="http://www.w3.org/2005/Atom"><title>Releases</title>'
        + "".join(entries)
        + "</feed>"
    ).encode()


def atom_entry(
    tag: str, day: int, *, title: str | None = None, repo: str = REPO
) -> str:
    return (
        f"<entry><id>tag:github.com,2008:Repository/1/{tag}</id>"
        f"<updated>2026-03-{day:02d}T10:00:00Z</updated>"
        f'<link rel="alternate" type="text/html" href="{repo}/releases/tag/{tag}"/>'
        f"<title>{title if title is not None else 'Release ' + tag + ' · example/repo'}</title>"
        "</entry>"
    )


def rss(*items: str) -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>Releases</title>'
        + "".join(items)
        + "</channel></rss>"
    ).encode()


class Upstream:
    """The feed host: answers per URL, recording each request it receives."""

    def __init__(self) -> None:
        self.routes: dict[str, object] = {}
        self.requests: list[httpx.Request] = []

    def serve(self, url: str, body: bytes = b"", status: int = 200, headers=None):
        self.routes[url] = httpx.Response(status, content=body, headers=headers or {})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get(str(request.url))
        if answer is None:
            return httpx.Response(404)
        if isinstance(answer, Exception):
            raise answer
        return httpx.Response(
            answer.status_code, content=answer.content, headers=dict(answer.headers)
        )


@pytest.fixture()
def upstream(monkeypatch):
    server = Upstream()
    real_client = httpx.Client

    def client(**kwargs):
        return real_client(transport=httpx.MockTransport(server.handler), **kwargs)

    monkeypatch.setattr(rf.httpx, "Client", client)
    # Every feed host resolves to one public address; the internal ones below
    # resolve where their names say.
    addresses = {"internal.example.org": "10.0.0.5"}

    def resolve(host, *_args, **_kwargs):
        if host == "unresolvable.example.org":
            raise socket.gaierror("no such host")
        ip = addresses.get(host, "93.184.216.34")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    return server


class _Task:
    def __init__(self) -> None:
        self.calls: list[int] = []

    def apply_async(self, args=(), **_options):
        self.calls.append(int(args[0]))


@pytest.fixture()
def scans(monkeypatch):
    from app.tasks import dependency_discovery

    task = _Task()
    monkeypatch.setattr(
        dependency_discovery, "discover_project_version_dependencies", task
    )
    return task.calls


@pytest.fixture(autouse=True)
def discoveries(monkeypatch):
    """Attaching a feed hands the whole-feed import to the workers; the
    hand-offs are recorded here and each test runs the import itself."""
    task = _Task()
    real = rf.discover_project_release_feed
    monkeypatch.setattr(rf, "discover_project_release_feed", task)
    task.run = real.run
    return task


@pytest.fixture()
def owner():
    client, user_id = signed_in("maintainer", email="owner@x.test")
    return client, user_id


def versions(project_id: int) -> dict[str, ProjectVersion]:
    with SessionLocal() as s:
        rows = s.query(ProjectVersion).filter_by(project_id=project_id).all()
        s.expunge_all()
        return {row.version: row for row in rows}


def feed_state(project_id: int) -> Project:
    with SessionLocal() as s:
        project = s.get(Project, project_id)
        s.expunge(project)
        return project


# ---------------------------------------------------------------------------
# First discovery.
# ---------------------------------------------------------------------------


def test_attaching_a_feed_imports_every_release_and_scans_the_newest(
    upstream, scans, discoveries, owner
):
    client, _ = owner
    upstream.serve(
        FEED,
        atom(
            atom_entry("v1.10.0", 20),
            atom_entry("v1.2.0", 5),
            atom_entry("v1.9.0", 12),
        ),
        headers={"ETag": '"abc"', "Last-Modified": "Fri, 20 Mar 2026 10:00:00 GMT"},
    )
    project = make_project(client, "feeder", release_rss_feed_url=FEED)
    pid = project["id"]
    assert discoveries.calls == [pid]
    assert versions(pid) == {}

    result = discoveries.run(pid)
    assert (result["created"], result["skipped"], result["ignored"]) == (3, 0, 0)
    rows = versions(pid)
    assert set(rows) == {"v1.2.0", "v1.9.0", "v1.10.0"}
    # Everything is published; the greatest version is Latest, not the last listed.
    assert {label: (v.is_draft, v.is_latest) for label, v in rows.items()} == {
        "v1.2.0": (False, False),
        "v1.9.0": (False, False),
        "v1.10.0": (False, True),
    }
    newest = rows["v1.10.0"]
    assert newest.link_to_source_code == REPO
    assert newest.release_date == datetime(2026, 3, 20, 10, 0)
    assert (
        newest.notes == f"Auto-imported from release feed: {REPO}/releases/tag/v1.10.0"
    )
    assert newest.dependency_discovery_status == "queued"
    assert result["latest_version_id"] == newest.id
    assert scans == [newest.id]

    state = feed_state(pid)
    assert state.release_rss_last_etag == '"abc"'
    assert state.release_rss_last_modified == "Fri, 20 Mar 2026 10:00:00 GMT"
    assert state.release_rss_last_entry_id.endswith("/v1.10.0")
    assert state.release_rss_last_checked_at is not None

    # A second run finds nothing new and starts no second scan.
    again = discoveries.run(pid)
    assert (again["created"], again["skipped"]) == (0, 3)
    assert len(versions(pid)) == 3
    assert scans == [newest.id]


def test_discovery_honours_ignore_patterns_and_inherits_mappings(
    upstream, scans, discoveries, owner
):
    client, _ = owner
    admin, _ = signed_in("admin")
    fw = make_framework(admin)
    node = make_node(admin, fw["id"], "wallet")
    pid = make_project(client, "feeder")["id"]
    base = make_version(
        client, pid, "0.9.0", link_to_source_code="https://github.com/example/old"
    )
    map_nodes(client, base["id"], fw["id"], [node["id"]])
    upstream.serve(
        FEED,
        atom(
            atom_entry("v1.0.0-rc1", 1),
            atom_entry("v1.0.0", 2),
            atom_entry("nightly-2026", 3),
            atom_entry("V1.0.1-BETA", 4),
            # Not a GitHub release link: the source comes from the last version.
            atom_entry("v1.1.0", 5, repo="https://gitlab.example/x/y/-"),
        ),
    )
    ok(
        client.put(
            f"/v1/projects/{pid}",
            json={
                "release_rss_feed_url": FEED,
                "release_rss_ignore_patterns": [
                    {"pattern": "nightly", "match_type": "contains"},
                    {"pattern": r"^v?\d+\.\d+\.\d+-rc\d+$", "match_type": "regex"},
                    {
                        "pattern": "BETA",
                        "match_type": "contains",
                        "case_sensitive": True,
                    },
                ],
            },
            headers=csrf(client),
        )
    )
    assert discoveries.calls == [pid]
    result = discoveries.run(pid)
    assert (result["created"], result["ignored"]) == (2, 3)
    rows = versions(pid)
    assert set(rows) == {"0.9.0", "v1.0.0", "v1.1.0"}
    assert rows["v1.0.0"].link_to_source_code == REPO
    assert rows["v1.1.0"].link_to_source_code == REPO  # inherited from v1.0.0
    assert rows["v1.1.0"].is_latest is True
    with SessionLocal() as s:
        from app.db.models import ProjectVersionFrameworkNode

        mapped = {
            row.project_version_id
            for row in s.query(ProjectVersionFrameworkNode).filter_by(
                framework_node_id=node["id"]
            )
        }
    assert mapped == {base["id"], rows["v1.0.0"].id, rows["v1.1.0"].id}


def test_discovery_reports_what_stopped_it(
    upstream, scans, discoveries, owner, monkeypatch
):
    client, _ = owner
    pid = make_project(client, "feeder", release_rss_feed_url=FEED)["id"]

    assert discoveries.run(999999)["reason"] == "no feed"
    plain = make_project(client, "plain")["id"]
    assert discoveries.run(plain)["reason"] == "no feed"

    upstream.serve(FEED, status=503)
    result = discoveries.run(pid)
    assert (result["created"], result["status_code"]) == (0, 503)
    assert feed_state(pid).release_rss_last_checked_at is not None

    upstream.serve(FEED, b"<feed><unclosed></feed>")
    assert discoveries.run(pid)["error"] == "parse"
    # An entity declaration is refused before the parser sees it.
    upstream.serve(
        FEED,
        b'<?xml version="1.0"?><!DOCTYPE feed [<!ENTITY a "aaaa">]><feed>&a;</feed>',
    )
    assert discoveries.run(pid)["error"] == "parse"
    upstream.serve(FEED, atom())
    assert discoveries.run(pid)["reason"] == "empty"
    assert versions(pid) == {}

    monkeypatch.setattr(settings, "feature_release_feed", False)
    assert discoveries.run(pid) == {
        "enabled": False,
        "reason": "release_feed feature disabled",
    }


def test_discovery_without_scanning_still_marks_the_latest(
    upstream, scans, discoveries, owner, monkeypatch
):
    client, _ = owner
    upstream.serve(FEED, atom(atom_entry("v1.0.0", 1), atom_entry("v2.0.0", 2)))
    pid = make_project(client, "feeder", release_rss_feed_url=FEED)["id"]
    monkeypatch.setattr(settings, "feature_dependency_scans", False)
    result = discoveries.run(pid)
    assert (result["created"], result["latest_version_id"]) == (2, None)
    rows = versions(pid)
    assert rows["v2.0.0"].is_latest is True
    assert rows["v2.0.0"].dependency_discovery_status == "not_run"
    assert scans == []


def test_releases_without_a_source_link_are_imported_unscanned(
    upstream, scans, discoveries, owner
):
    client, _ = owner
    upstream.serve(
        FEED,
        rss(
            "<item><title>2.0</title><link>https://example.org/news/2</link>"
            "<pubDate>Tue, 03 Mar 2026 09:00:00 +0100</pubDate></item>",
            "<item><guid>one</guid><title>1.0</title>"
            "<pubDate>Mon, 02 Mar 2026 09:00:00 GMT</pubDate></item>",
            "<item><description>no title, link or guid</description></item>",
        ),
    )
    pid = make_project(client, "rss", release_rss_feed_url=FEED)["id"]
    result = discoveries.run(pid)
    assert (result["created"], result["latest_version_id"]) == (2, None)
    rows = versions(pid)
    assert set(rows) == {"1.0", "2.0"}
    assert rows["2.0"].link_to_source_code is None
    assert rows["2.0"].is_latest is True
    # Dates are stored in UTC whatever offset the feed used.
    assert rows["2.0"].release_date == datetime(2026, 3, 3, 8, 0)
    assert rows["1.0"].notes is None
    assert (
        rows["2.0"].notes
        == "Auto-imported from release feed: https://example.org/news/2"
    )
    assert scans == []


# ---------------------------------------------------------------------------
# The regular poll.
# ---------------------------------------------------------------------------


def _polled_project(client, upstream, *entries, **fields) -> int:
    """A project whose feed discovery has run once on the given entries."""
    upstream.serve(FEED, atom(*entries))
    pid = make_project(client, "feeder", release_rss_feed_url=FEED, **fields)["id"]
    rf.discover_project_release_feed.run(pid)
    return pid


def test_the_poll_stages_new_releases_as_drafts_and_tells_the_owners(
    upstream, scans, owner, outbox
):
    client, owner_id = owner
    colleague, colleague_id = signed_in("viewer", email="colleague@x.test")
    make_group("Team", members=[owner_id, colleague_id])
    pid = _polled_project(client, upstream, atom_entry("v1.0.0", 1))
    assert len(scans) == 1

    upstream.serve(
        FEED,
        atom(atom_entry("v1.0.0", 1), atom_entry("v1.1.0", 2), atom_entry("v1.2.0", 3)),
        headers={"ETag": '"v2"'},
    )
    result = rf.poll_release_feeds.run()
    assert result == {"enabled": True, "checked": 1, "created": 2, "ignored": 0}
    rows = versions(pid)
    assert {label: (v.is_draft, v.is_latest) for label, v in rows.items()} == {
        "v1.0.0": (False, True),
        "v1.1.0": (True, False),
        "v1.2.0": (True, False),
    }
    assert rows["v1.2.0"].link_to_source_code == REPO
    assert len(scans) == 1  # drafts are not scanned
    mails = sorted((m.recipient, m.subject) for m in outbox.messages())
    assert [recipient for recipient, _ in mails] == [
        "colleague@x.test",
        "colleague@x.test",
        "owner@x.test",
        "owner@x.test",
    ]
    assert all("Feeder" in subject for _, subject in mails)
    assert {
        subject.count("v1.1.0") + subject.count("v1.2.0") for _, subject in mails
    } == {1}
    assert "https://ospmae.example.com/project.html?id=" in outbox.messages()[0].body

    # The next poll sends the validators and a 304 changes nothing.
    upstream.serve(FEED, status=304)
    assert rf.poll_release_feeds.run()["created"] == 0
    conditional = upstream.requests[-1]
    assert conditional.headers["if-none-match"] == '"v2"'
    assert len(versions(pid)) == 3


def test_the_poll_skips_what_it_should_not_stage(upstream, scans, owner):
    client, _ = owner
    pid = _polled_project(
        client,
        upstream,
        atom_entry("v2.0.0", 10),
        release_rss_ignore_patterns=[{"pattern": "beta", "match_type": "contains"}],
    )
    upstream.serve(
        FEED,
        atom(
            atom_entry("v2.0.0", 10),
            atom_entry("v1.9.9", 11),  # a maintenance release below Latest
            atom_entry("v2.1.0-beta", 12),
            atom_entry("v2.0.0", 13, title="Release v2.0.0 · re-published"),
            atom_entry("v2.1.0", 15),
        ),
    )
    result = rf.poll_release_feeds.run()
    assert (result["created"], result["ignored"]) == (1, 1)
    assert set(versions(pid)) == {"v2.0.0", "v2.1.0"}


def test_a_rotated_feed_only_offers_its_newest_entry(upstream, scans, owner):
    client, _ = owner
    pid = _polled_project(client, upstream, atom_entry("v1.0.0", 1))
    # None of the remembered entries is left in the feed.
    upstream.serve(FEED, atom(atom_entry("v1.5.0", 5), atom_entry("v1.6.0", 6)))
    assert rf.poll_release_feeds.run()["created"] == 1
    assert set(versions(pid)) == {"v1.0.0", "v1.6.0"}


def test_a_noisy_feed_cannot_stage_more_than_ten_releases_in_one_poll(
    upstream, scans, owner
):
    client, _ = owner
    pid = _polled_project(client, upstream, atom_entry("v1.0.0", 1))
    upstream.serve(
        FEED,
        atom(
            atom_entry("v1.0.0", 1),
            *[atom_entry(f"v2.{n}.0", 2 + n) for n in range(25)],
        ),
    )
    assert rf.poll_release_feeds.run()["created"] == 10
    staged = set(versions(pid)) - {"v1.0.0"}
    # The ten newest; the feed's newest entry is remembered so none repeats.
    assert staged == {f"v2.{n}.0" for n in range(15, 25)}
    assert rf.poll_release_feeds.run()["created"] == 0


def test_upstream_trouble_leaves_the_catalogue_alone_and_is_retried(
    upstream, scans, owner
):
    client, _ = owner
    pid = _polled_project(client, upstream, atom_entry("v1.0.0", 1))
    newer = atom(atom_entry("v1.0.0", 1), atom_entry("v1.1.0", 2))

    for trouble in (
        lambda: upstream.serve(FEED, status=500),
        lambda: upstream.serve(FEED, b""),
        lambda: upstream.serve(FEED, b"   "),
        lambda: upstream.serve(FEED, b"<rss><channel></rss>"),
        lambda: upstream.serve(FEED, atom()),
        lambda: upstream.routes.__setitem__(FEED, httpx.ConnectError("refused")),
    ):
        trouble()
        before = feed_state(pid).release_rss_last_checked_at
        assert rf.poll_release_feeds.run()["created"] == 0
        assert set(versions(pid)) == {"v1.0.0"}
        assert feed_state(pid).release_rss_last_checked_at >= before

    upstream.serve(FEED, newer)
    assert rf.poll_release_feeds.run()["created"] == 1
    assert versions(pid)["v1.1.0"].is_draft is True


def test_the_poll_can_be_switched_off_and_skips_tracked_branches(
    upstream, scans, owner, monkeypatch
):
    client, _ = owner
    _polled_project(client, upstream, atom_entry("v1.0.0", 1))
    upstream.serve(FEED, atom(atom_entry("v1.0.0", 1), atom_entry("v1.1.0", 2)))
    off = {"enabled": False, "checked": 0, "created": 0, "ignored": 0}
    monkeypatch.setattr(settings, "release_feed_poll_enabled", False)
    assert rf.poll_release_feeds.run() == off
    monkeypatch.setattr(settings, "release_feed_poll_enabled", True)
    monkeypatch.setattr(settings, "feature_release_feed", False)
    assert rf.poll_release_feeds.run() == off
    monkeypatch.setattr(settings, "feature_release_feed", True)

    with SessionLocal() as s:
        project = s.query(Project).one()
        project.track_branch = True
        project.tracked_branch = "main"
        project.tracked_repo_url = REPO
        s.commit()
        pid = project.id
    assert rf.poll_release_feeds.run()["checked"] == 0
    assert (
        rf.discover_project_release_feed.run(pid)["reason"] == "project tracks a branch"
    )


def test_owners_are_not_mailed_without_a_mail_server(
    upstream, scans, owner, outbox, monkeypatch
):
    client, _ = owner
    pid = _polled_project(client, upstream, atom_entry("v1.0.0", 1))
    upstream.serve(FEED, atom(atom_entry("v1.0.0", 1), atom_entry("v1.1.0", 2)))
    monkeypatch.setattr(settings, "smtp_host", "")
    assert rf.poll_release_feeds.run()["created"] == 1
    assert outbox.messages() == []
    assert versions(pid)["v1.1.0"].is_draft is True


def test_a_project_nobody_can_be_mailed_for_still_gets_its_draft(
    upstream, scans, outbox
):
    client, _ = signed_in("maintainer")  # no e-mail address on the account
    with SessionLocal() as s:
        from app.db.models import User

        s.query(User).update({User.email: None})
        s.commit()
    pid = _polled_project(client, upstream, atom_entry("v1.0.0", 1))
    upstream.serve(FEED, atom(atom_entry("v1.0.0", 1), atom_entry("v1.1.0", 2)))
    assert rf.poll_release_feeds.run()["created"] == 1
    assert outbox.messages() == []
    assert versions(pid)["v1.1.0"].is_draft is True


# ---------------------------------------------------------------------------
# Fetching safely.
# ---------------------------------------------------------------------------


def test_redirects_are_followed_only_to_public_hosts_and_only_so_far(
    upstream, scans, owner, monkeypatch
):
    client, _ = owner
    pid = make_project(client, "feeder", release_rss_feed_url=FEED)["id"]
    moved = "https://cdn.example.org/releases.atom"
    upstream.serve(
        FEED, status=302, headers={"Location": "//cdn.example.org/releases.atom"}
    )
    upstream.serve(moved, atom(atom_entry("v1.0.0", 1)))
    assert rf.discover_project_release_feed.run(pid)["created"] == 1
    assert [str(r.url) for r in upstream.requests] == [FEED, moved]

    # A redirect towards an internal address is never requested.
    upstream.requests.clear()
    upstream.serve(
        FEED, status=301, headers={"Location": "https://internal.example.org/x"}
    )
    with pytest.raises(ValueError, match="private"):
        rf.discover_project_release_feed.run(pid)
    assert [str(r.url) for r in upstream.requests] == [FEED]

    # A redirect without a target ends the fetch with that answer.
    upstream.serve(FEED, status=307)
    assert rf.discover_project_release_feed.run(pid)["status_code"] == 307

    # A loop stops after the configured number of hops.
    monkeypatch.setattr(settings, "release_feed_max_redirects", 2)
    upstream.requests.clear()
    upstream.serve(FEED, status=302, headers={"Location": FEED})
    with pytest.raises(ValueError, match="Too many redirects"):
        rf.discover_project_release_feed.run(pid)
    assert len(upstream.requests) == 3


def test_feeds_on_internal_or_unknown_hosts_are_never_fetched(upstream, scans, owner):
    client, _ = owner
    for host in ("internal.example.org", "unresolvable.example.org"):
        with SessionLocal() as s:
            s.query(Project).delete()
            s.commit()
        pid = make_project(
            client, "feeder", release_rss_feed_url=f"https://{host}/feed.atom"
        )["id"]
        with pytest.raises(ValueError):
            rf.discover_project_release_feed.run(pid)
        # The poll records the attempt and moves on to other projects.
        assert rf.poll_release_feeds.run() == {
            "enabled": True,
            "checked": 1,
            "created": 0,
            "ignored": 0,
        }
        assert feed_state(pid).release_rss_last_checked_at is not None
    assert upstream.requests == []


def test_an_oversized_feed_is_abandoned(upstream, scans, owner, monkeypatch):
    client, _ = owner
    pid = make_project(client, "feeder", release_rss_feed_url=FEED)["id"]
    body = atom(*[atom_entry(f"v1.{n}.0", 1) for n in range(30)])
    monkeypatch.setattr(settings, "release_feed_max_bytes", len(body) - 1)
    upstream.serve(FEED, body)
    with pytest.raises(ValueError, match="too large"):
        rf.discover_project_release_feed.run(pid)
    assert rf.poll_release_feeds.run()["created"] == 0
    assert versions(pid) == {}
    monkeypatch.setattr(settings, "release_feed_max_bytes", len(body))
    assert rf.discover_project_release_feed.run(pid)["created"] == 30


# ---------------------------------------------------------------------------
# Reading entries.
# ---------------------------------------------------------------------------


def test_atom_and_rss_entries_are_read_oldest_first():
    entries = rf._parse_feed_entries(
        atom(
            "<entry><id>b</id><title>Second</title><published>2026-03-02T00:00:00+02:00</published>"
            '<link rel="self" href="https://x.example/self"/>'
            '<link href="https://x.example/b"/></entry>',
            "<entry><title>Undated</title><link>https://x.example/text-link</link></entry>",
            "<entry><id>a</id><updated>2026-03-01T00:00:00Z</updated></entry>",
            "<entry><summary>nothing to key on</summary></entry>",
        )
    )
    assert [(e["id"], e["title"], e["link"]) for e in entries] == [
        ("https://x.example/text-link", "Undated", "https://x.example/text-link"),
        ("a", "a", None),
        ("b", "Second", "https://x.example/b"),
    ]
    assert entries[2]["published_dt"].utcoffset().total_seconds() == 7200
    assert entries[0]["published_dt"] is None

    items = rf._parse_feed_entries(
        rss(
            "<item><guid>g2</guid><title>Two</title><pubDate>not a date</pubDate></item>",
            "<item><title>One</title><link>https://x.example/1</link>"
            "<pubDate>Sun, 01 Mar 2026 00:00:00 GMT</pubDate></item>",
        )
    )
    assert [(e["id"], e["link"], e["published_dt"] is None) for e in items] == [
        ("g2", None, True),
        ("https://x.example/1", "https://x.example/1", False),
    ]
    # A document that is neither feed shape has no entries.
    assert rf._parse_feed_entries(b"<rss><other/></rss>") == []
    assert rf._parse_feed_entries(b"<html><body/></html>") == []


@pytest.mark.parametrize(
    ("title", "link", "expected"),
    [
        ("Release v1.2.3 · owner/repo", None, "v1.2.3"),
        ("release 4.0", None, "4.0"),
        ("Release ", "https://github.com/o/r/releases/tag/v9", "v9"),
        ("Spring update", "https://github.com/o/r/releases/tag/v2.0", "v2.0"),
        ("Spring update", "https://example.org/news/spring", "Spring update"),
        ("1.0", None, "1.0"),
        ("  ", "https://github.com/o/r/releases/tag/v1", None),
    ],
)
def test_the_version_label_comes_from_the_title_or_the_tag_link(title, link, expected):
    assert rf._guess_version_from_entry(title, link) == expected


@pytest.mark.parametrize(
    ("link", "expected"),
    [
        (
            "https://github.com/owner/repo/releases/tag/v1",
            "https://github.com/owner/repo",
        ),
        ("https://GitHub.com/owner/repo", "https://github.com/owner/repo"),
        ("https://github.com/owner", None),
        # Forgejo, Gitea and Codeberg share GitHub's release paths.
        (
            "https://codeberg.org/owner/repo/releases/tag/v1",
            "https://codeberg.org/owner/repo",
        ),
        (
            "https://codeberg.org/owner/repo/releases.rss",
            "https://codeberg.org/owner/repo",
        ),
        # GitLab nests groups and separates routes with "/-/".
        (
            "https://gitlab.com/group/sub/project/-/releases/v1",
            "https://gitlab.com/group/sub/project",
        ),
        (
            "https://gitlab.com/group/project/-/tags?format=atom",
            "https://gitlab.com/group/project",
        ),
        # Not a release path, or no repository before it.
        ("https://codeberg.org/owner/repo", None),
        ("https://codeberg.org/releases/tag/v1", None),
        ("https://codeberg.org/owner/releases", None),
        # A host outside the allowlist is never turned into a clone URL.
        ("https://git.unlisted.example/owner/repo/releases/tag/v1", None),
        ("https://github.com.evil.example/owner/repo/releases/tag/v1", None),
        # Credentials in the link's authority never reach a clone URL.
        ("https://user:pass@github.com/owner/repo/releases/tag/v1", None),
        ("ftp://github.com/owner/repo/releases/tag/v1", None),
        ("https:///owner/repo/releases", None),
        ("", None),
        (None, None),
    ],
)
def test_a_release_link_yields_its_repository_on_an_allowed_host(link, expected):
    assert repository_url_for_release_link(link) == expected


# A Forgejo releases feed, in the shape git.mig5.net serves.
FORGEJO_FEED_URL = "https://git.mig5.net/mig5/heckle/releases.rss"
FORGEJO_FEED = b"""<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>Releases for mig5/heckle</title>
    <link>https://git.mig5.net/mig5/heckle/releases</link>
    <description>Generate HCL</description>
    <pubDate>Wed, 11 Nov 2026 14:29:23 -0600</pubDate>
    <item>
      <title>0.1.3</title>
      <link>https://git.mig5.net/mig5/heckle/releases/tag/0.1.3</link>
      <description></description>
      <content:encoded><![CDATA[<ul dir="auto"><li>Notes</li></ul>]]></content:encoded>
      <author>mig5</author>
      <guid>121: https://git.mig5.net/mig5/heckle/releases/tag/0.1.3</guid>
      <pubDate>Wed, 30 Sep 2026 19:47:56 -0500</pubDate>
    </item>
    <item>
      <title>0.1.2</title>
      <link>https://git.mig5.net/mig5/heckle/releases/tag/0.1.2</link>
      <description></description>
      <author>mig5</author>
      <guid>112: https://git.mig5.net/mig5/heckle/releases/tag/0.1.2</guid>
      <pubDate>Mon, 21 Sep 2026 18:56:35 -0500</pubDate>
    </item>
  </channel>
</rss>
"""
FORGEJO_REPO = "https://git.mig5.net/mig5/heckle"


def test_a_self_hosted_forge_feed_is_scanned_once_its_host_is_allowed(
    upstream, scans, discoveries, owner, monkeypatch
):
    client, _ = owner
    upstream.serve(FORGEJO_FEED_URL, FORGEJO_FEED)
    pid = make_project(client, "heckle", release_rss_feed_url=FORGEJO_FEED_URL)["id"]

    # With the default allowlist the releases arrive, but nothing may be cloned.
    result = discoveries.run(pid)
    assert (result["created"], result["latest_version_id"]) == (2, None)
    rows = versions(pid)
    assert {label: v.link_to_source_code for label, v in rows.items()} == {
        "0.1.2": None,
        "0.1.3": None,
    }
    assert rows["0.1.3"].is_latest is True
    assert scans == []

    # Allowing the host and running discovery again repairs what was imported
    # and scans the Latest release.
    monkeypatch.setattr(
        settings,
        "dependency_discovery_allowed_hosts",
        "github.com,gitlab.com,codeberg.org,git.mig5.net",
    )
    result = discoveries.run(pid)
    assert (result["created"], result["skipped"]) == (0, 2)
    rows = versions(pid)
    assert {label: v.link_to_source_code for label, v in rows.items()} == {
        "0.1.2": FORGEJO_REPO,
        "0.1.3": FORGEJO_REPO,
    }
    latest = rows["0.1.3"]
    assert latest.dependency_discovery_status == "queued"
    assert latest.release_date == datetime(2026, 10, 1, 0, 47, 56)
    assert result["latest_version_id"] == latest.id
    assert scans == [latest.id]
    # The manual scan the project page offers is accepted now too.
    ok(
        client.post(
            f"/v1/project-versions/{rows['0.1.2'].id}/dependency-discovery",
            headers=csrf(client),
        )
    )
    assert scans == [latest.id, rows["0.1.2"].id]


def test_asking_for_a_scan_repairs_a_release_imported_before_its_host_was_allowed(
    upstream, scans, discoveries, owner, monkeypatch
):
    client, _ = owner
    upstream.serve(FORGEJO_FEED_URL, FORGEJO_FEED)
    pid = make_project(client, "heckle", release_rss_feed_url=FORGEJO_FEED_URL)["id"]
    discoveries.run(pid)
    version = versions(pid)["0.1.3"]
    assert version.link_to_source_code is None
    path = f"/v1/project-versions/{version.id}/dependency-discovery"

    # While the host is not allowed the scan is refused, and says what to check.
    refused = client.post(path, headers=csrf(client))
    assert refused.status_code == 400
    assert "OSPMAE_DEPENDENCY_DISCOVERY_ALLOWED_HOSTS" in refused.json()["detail"]
    assert versions(pid)["0.1.3"].link_to_source_code is None
    assert scans == []

    # Once it is, the Run scan button works without importing the feed again.
    monkeypatch.setattr(
        settings, "dependency_discovery_allowed_hosts", "github.com,git.mig5.net"
    )
    assert ok(client.post(path, headers=csrf(client)))["launched"] is True
    repaired = versions(pid)["0.1.3"]
    assert repaired.link_to_source_code == FORGEJO_REPO
    assert repaired.dependency_discovery_status == "queued"
    assert scans == [version.id]


def test_an_allowed_forge_feed_is_scanned_on_first_discovery(
    upstream, scans, discoveries, owner, monkeypatch
):
    monkeypatch.setattr(
        settings, "dependency_discovery_allowed_hosts", "github.com,git.mig5.net"
    )
    client, _ = owner
    upstream.serve(FORGEJO_FEED_URL, FORGEJO_FEED)
    pid = make_project(client, "heckle", release_rss_feed_url=FORGEJO_FEED_URL)["id"]
    discoveries.run(pid)
    latest = versions(pid)["0.1.3"]
    assert (latest.link_to_source_code, latest.is_latest) == (FORGEJO_REPO, True)
    assert scans == [latest.id]


def test_the_feed_address_names_the_repository_when_an_entry_has_no_link(
    upstream, scans, discoveries, owner
):
    client, _ = owner
    feed = "https://codeberg.org/owner/repo/releases.rss"
    upstream.serve(feed, rss("<item><guid>1</guid><title>1.0.0</title></item>"))
    pid = make_project(client, "linkless", release_rss_feed_url=feed)["id"]
    discoveries.run(pid)
    only = versions(pid)["1.0.0"]
    assert only.link_to_source_code == "https://codeberg.org/owner/repo"
    assert scans == [only.id]


def test_stored_ignore_patterns_of_every_older_shape_still_apply():
    project = Project(machine_name="p", display_name="P")
    project.release_rss_ignore_patterns = [
        "nightly",
        "regex:^rc",
        "contains:alpha",
        "  ",
        7,
        {"pattern": ""},
        {"pattern": "beta", "type": "substring"},
        {"pattern": "^dev", "match_type": "regexp"},
        {"pattern": "x", "match_type": "glob"},
        {"pattern": "(a+)+$", "match_type": "regex"},
    ]
    ignored = lambda label, **entry: rf._release_feed_entry_is_ignored(  # noqa: E731
        project, entry, label
    )
    assert ignored("1.0-NIGHTLY") is True
    assert ignored("RC1") is True
    assert ignored("1.0-alpha") is True
    assert ignored("1.0-beta.2") is True
    assert ignored("dev-main") is True
    assert (
        ignored("1.0", title="Release 1.0", link="https://x.example/nightly/1.0")
        is True
    )
    # The unknown match type and the unsafe expression are skipped, not run.
    assert ignored("x-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!") is False
    assert ignored("1.0") is False
    project.release_rss_ignore_patterns = "nightly"
    assert ignored("nightly") is False
    project.release_rss_ignore_patterns = [{"pattern": "RC", "case_sensitive": True}]
    assert (ignored("1.0-rc1"), ignored("1.0-RC1")) == (False, True)
