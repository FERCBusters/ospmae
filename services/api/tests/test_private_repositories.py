"""Private repositories: a write-only, host-bound access token per project."""

from __future__ import annotations

import base64
import json
import subprocess

import pytest
from app.core.config import settings
from app.db.models import EntityChangelog, Project, ProjectVersion
from app.db.session import SessionLocal
from app.depscan import scan as scan_mod
from app.security import mfa
from app.security.repo_credentials import (
    RepoCredential,
    RepoTokenUnavailable,
    decrypt_token,
    encrypt_token,
    git_auth_env,
    project_credential,
)
from cryptography.fernet import Fernet

from tests.conftest import auth_client

TOKEN = "github_pat_11ABCDEFG0123456789_secretvalue"
REPO = "https://github.com/example/private-repo"


@pytest.fixture(autouse=True)
def encryption_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "mfa_encryption_key", key)
    return key


def _csrf(client):
    return {"X-CSRF-Token": client.cookies.get("__Host-ospmae_csrf")}


def _body(**overrides):
    body = {
        "machine_name": "private",
        "display_name": "Private",
        "repo_private": True,
        "repo_token_repository": REPO,
        "repo_token": TOKEN,
    }
    body.update(overrides)
    return body


def _stored(project_id):
    with SessionLocal() as db:
        project = db.get(Project, project_id)
        db.expunge(project)
        return project


def _create(c, **overrides):
    response = c.post("/v1/projects", json=_body(**overrides), headers=_csrf(c))
    assert response.status_code == 200, response.text
    return response.json()


# --- The API never returns the token ----------------------------------------


def test_a_saved_token_is_encrypted_and_never_returned():
    c, _ = auth_client(role="admin")
    created = _create(c)
    assert created["repo_private"] is True
    assert created["repo_token_set"] is True
    assert created["repo_token_host"] == "github.com"
    assert "repo_token" not in created

    stored = _stored(created["id"])
    assert TOKEN not in stored.repo_token_encrypted
    assert decrypt_token(stored.repo_token_encrypted) == TOKEN
    assert stored.repo_token_updated_at is not None

    for path in (f"/v1/projects/{created['id']}", "/v1/projects"):
        response = c.get(path)
        assert response.status_code == 200
        assert TOKEN not in response.text
        assert stored.repo_token_encrypted not in response.text
    changelog = c.get(f"/v1/projects/{created['id']}/changelog")
    assert changelog.status_code == 200
    assert TOKEN not in changelog.text
    with SessionLocal() as db:
        rows = db.query(EntityChangelog).all()
        assert rows
        for row in rows:
            dumped = json.dumps([row.before_state, row.after_state, row.changes])
            assert TOKEN not in dumped
            assert stored.repo_token_encrypted not in dumped


def test_an_empty_token_keeps_the_saved_one_and_a_new_one_replaces_it():
    c, _ = auth_client(role="admin")
    created = _create(c)
    first = _stored(created["id"])

    response = c.put(
        f"/v1/projects/{created['id']}",
        json={"repo_private": True, "repo_token_host": "github.com", "repo_token": ""},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert _stored(created["id"]).repo_token_encrypted == first.repo_token_encrypted

    response = c.put(
        f"/v1/projects/{created['id']}",
        json={"repo_private": True, "repo_token": "replacement-token"},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert decrypt_token(_stored(created["id"]).repo_token_encrypted) == (
        "replacement-token"
    )
    with SessionLocal() as db:
        labels = [
            change["field"]
            for row in db.query(EntityChangelog).filter_by(action="updated")
            for change in row.changes
        ]
    assert "repo_token_updated_at" in labels


def test_a_token_does_not_follow_a_new_repository_unless_entered_again():
    c, _ = auth_client(role="admin")
    created = _create(c)
    assert created["repo_token_repository"] == REPO
    assert created["repo_token_host"] == "github.com"
    other = "https://github.com/example/other-private-repo"
    response = c.put(
        f"/v1/projects/{created['id']}",
        json={"repo_private": True, "repo_token_repository": other},
        headers=_csrf(c),
    )
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Enter the access token again for this repository"
    }
    assert _stored(created["id"]).repo_token_repository == REPO

    # The same repository written another way is the same repository.
    response = c.put(
        f"/v1/projects/{created['id']}",
        json={
            "repo_private": True,
            "repo_token_repository": REPO.replace("example", "Example") + ".git/",
        },
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text

    response = c.put(
        f"/v1/projects/{created['id']}",
        json={
            "repo_private": True,
            "repo_token_repository": "https://gitlab.com/group/sub/project",
            "repo_token": "glpat-new",
        },
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    stored = _stored(created["id"])
    assert (
        stored.repo_token_repository,
        stored.repo_token_host,
        decrypt_token(stored.repo_token_encrypted),
    ) == ("https://gitlab.com/group/sub/project", "gitlab.com", "glpat-new")

    # A host named beside the repository has to be the repository's own.
    response = c.put(
        f"/v1/projects/{created['id']}",
        json={"repo_private": True, "repo_token_host": "github.com"},
        headers=_csrf(c),
    )
    assert response.status_code == 422
    assert response.json() == {
        "detail": "The repository is on gitlab.com, not github.com"
    }


def test_making_the_repository_public_deletes_the_token():
    c, _ = auth_client(role="admin")
    created = _create(c, repo_token_username="someone")
    response = c.put(
        f"/v1/projects/{created['id']}",
        json={"repo_private": False},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert response.json()["repo_token_set"] is False
    stored = _stored(created["id"])
    assert (
        stored.repo_private,
        stored.repo_token_host,
        stored.repo_token_username,
        stored.repo_token_encrypted,
        stored.repo_token_updated_at,
    ) == (False, None, None, None, None)


def test_an_update_without_repository_fields_leaves_them_alone():
    c, _ = auth_client(role="admin")
    created = _create(c)
    before = _stored(created["id"]).repo_token_encrypted
    response = c.put(
        f"/v1/projects/{created['id']}",
        json={"display_name": "Renamed", "repo_private": None},
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    assert _stored(created["id"]).repo_token_encrypted == before


@pytest.mark.parametrize(
    ("overrides", "detail"),
    [
        ({"repo_token": None}, "Enter an access token for the private repository"),
        (
            {"repo_token_repository": None},
            "Enter the repository the access token is for",
        ),
        (
            {"repo_token_repository": "https://codeberg.org/example/private-repo"},
            "Enter the account name the token belongs to on codeberg.org",
        ),
    ],
)
def test_incomplete_private_settings_are_refused(overrides, detail):
    c, _ = auth_client(role="admin")
    response = c.post("/v1/projects", json=_body(**overrides), headers=_csrf(c))
    assert response.json() == {"detail": detail}
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.query(Project).count() == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"repo_token_host": "evil.example"},
        {"repo_token_host": "github.com/x"},
        # Not a repository on an allowed host, over HTTPS.
        {"repo_token_repository": "https://evil.example/owner/repo"},
        {"repo_token_repository": "http://github.com/owner/repo"},
        {"repo_token_repository": "https://github.com/only-an-owner"},
        {"repo_token_repository": "https://github.com:8443/owner/repo"},
        {"repo_token_repository": "https://bot:pw@github.com/owner/repo"},
        {"repo_token_repository": "https://github.com/owner/repo?x=1"},
        {"repo_token_repository": "https://github.com/owner/../repo"},
        {"repo_token_repository": "git@github.com:owner/repo.git"},
        {"repo_token": "has a space"},
        {"repo_token_username": "a:b"},
        {"repo_token": "x" * 1025},
    ],
)
def test_malformed_private_settings_are_refused_without_echo(overrides):
    c, _ = auth_client(role="admin")
    response = c.post("/v1/projects", json=_body(**overrides), headers=_csrf(c))
    assert response.status_code == 422
    for key, value in overrides.items():
        if key in {"repo_token", "repo_token_username"}:
            assert value not in response.text


def test_a_token_is_refused_without_an_encryption_key(monkeypatch):
    monkeypatch.setattr(settings, "mfa_encryption_key", "")
    c, _ = auth_client(role="admin")
    response = c.post("/v1/projects", json=_body(), headers=_csrf(c))
    assert response.status_code == 503
    assert "OSPMAE_MFA_ENCRYPTION_KEY" in response.json()["detail"]


# --- Encryption --------------------------------------------------------------


def test_tokens_use_a_key_derived_for_tokens_alone(encryption_key):
    # A TOTP secret's ciphertext cannot stand in for a token, or the reverse.
    totp_ciphertext = mfa.cipher().encrypt(b"totp-secret").decode()
    with pytest.raises(RepoTokenUnavailable):
        decrypt_token(totp_ciphertext)
    token_ciphertext = encrypt_token(TOKEN)
    with pytest.raises(Exception):
        Fernet(encryption_key.encode()).decrypt(token_ciphertext.encode())


def test_a_changed_key_asks_for_the_token_again(monkeypatch):
    ciphertext = encrypt_token(TOKEN)
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    with pytest.raises(RepoTokenUnavailable, match="enter it again"):
        decrypt_token(ciphertext)


def test_credentials_never_print_their_token():
    credential = RepoCredential(host="github.com", username="x", token=TOKEN)
    assert TOKEN not in repr(credential)


@pytest.mark.parametrize(
    ("host", "username", "expected"),
    [
        ("github.com", None, "x-access-token"),
        ("gitlab.com", None, "oauth2"),
        ("gitlab.example.org", None, "oauth2"),
        ("codeberg.org", "alice", "alice"),
        ("github.com", "bot", "bot"),
    ],
)
def test_account_names_default_per_host(host, username, expected):
    project = Project(
        repo_private=True,
        repo_token_host=host,
        repo_token_repository=f"https://{host}/example/private-repo",
        repo_token_username=username,
        repo_token_encrypted=encrypt_token(TOKEN),
    )
    credential = project_credential(project)
    assert (
        credential.host,
        credential.username,
        credential.token,
        credential.repository,
    ) == (host, expected, TOKEN, f"https://{host}/example/private-repo")


def test_public_projects_have_no_credential():
    assert project_credential(Project(repo_private=False)) is None


# --- Git ---------------------------------------------------------------------


CREDENTIAL = RepoCredential(
    host="github.com", username="x-access-token", token=TOKEN, repository=REPO
)


def test_the_token_is_a_header_scoped_to_the_repository_being_cloned():
    env = git_auth_env(CREDENTIAL, REPO)
    basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    assert env == {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.{REPO}.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }

    def header_for(address: str) -> str:
        # git reads the scoped header from its environment.
        shown = subprocess.run(
            ["git", "config", "--get-urlmatch", "http.extraHeader", address],
            env={**scan_mod._git_env(), **env},
            capture_output=True,
            text=True,
        )
        return shown.stdout.strip()

    # The requests a clone of this repository makes carry it.
    assert header_for(REPO) == f"Authorization: Basic {basic}"
    assert header_for(f"{REPO}/info/refs?service=git-upload-pack") == (
        f"Authorization: Basic {basic}"
    )
    # Nothing else does: another repository on the host, one whose name
    # begins the same way, the host itself, or another host.
    owner = REPO.rsplit("/", 1)[0]
    for elsewhere in (
        f"{owner}/other-private-repo",
        f"{REPO}-internal",
        "https://github.com/",
        "https://gitlab.com/x",
    ):
        assert header_for(elsewhere) == "", elsewhere
    # A clone address written with .git is scoped as written.
    dotted = git_auth_env(CREDENTIAL, f"{REPO}.git/")
    assert dotted["GIT_CONFIG_KEY_0"] == f"http.{REPO}.git.extraHeader"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/private-repo",
        "https://gitlab.com/example/private-repo",
        "https://github.com.evil.example/x",
        "git@github.com:example/private-repo.git",
        "ssh://git@github.com/example/private-repo",
    ],
)
def test_the_token_is_never_sent_elsewhere_or_unencrypted(url):
    with pytest.raises(ValueError, match="only over HTTPS with github.com"):
        git_auth_env(CREDENTIAL, url)


def test_a_private_project_names_its_repository_in_what_it_returns_and_records():
    c, _ = auth_client(role="admin")
    created = _create(c)
    assert created["repo_token_repository"] == REPO
    fetched = c.get(f"/v1/projects/{created['id']}").json()
    assert fetched["repo_token_repository"] == REPO
    with SessionLocal() as db:
        states = [
            row.after_state
            for row in db.query(EntityChangelog).filter_by(entity_type="project")
        ]
    assert [state["repo_token_repository"] for state in states] == [REPO]
    assert TOKEN not in str(states)


def test_clones_carry_the_token_only_in_their_environment(monkeypatch):
    seen: list[tuple[list[str], dict]] = []

    def fake_run(cmd, **kwargs):
        seen.append((cmd, kwargs.get("env") or {}))
        out = "abc refs/heads/main\n" if "ls-remote" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=out)

    monkeypatch.setattr(scan_mod.subprocess, "run", fake_run)
    repo_dir, _ = scan_mod.clone_repo(REPO, branch="main", credential=CREDENTIAL)
    try:
        commands = [cmd for cmd, _ in seen]
        assert any("ls-remote" in cmd for cmd in commands)
        assert any("clone" in cmd for cmd in commands)
        basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
        for cmd, env in seen:
            assert TOKEN not in " ".join(cmd)
            assert basic not in " ".join(cmd)
            if "rev-parse" in cmd:
                # A local command needs no credential.
                assert "GIT_CONFIG_COUNT" not in env
            else:
                assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {basic}"
                assert env["GIT_TERMINAL_PROMPT"] == "0"
    finally:
        import shutil

        shutil.rmtree(repo_dir, ignore_errors=True)


def test_a_public_clone_carries_no_credential(monkeypatch):
    seen: list[dict] = []

    def fake_run(cmd, **kwargs):
        seen.append(kwargs.get("env") or {})
        return subprocess.CompletedProcess(cmd, 0, stdout="")

    monkeypatch.setattr(scan_mod.subprocess, "run", fake_run)
    repo_dir, _ = scan_mod.clone_repo(REPO)
    import shutil

    shutil.rmtree(repo_dir, ignore_errors=True)
    assert seen and all("GIT_CONFIG_COUNT" not in env for env in seen)


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/example/x",
        # Another repository the same token may well be able to read.
        "https://github.com/example/other-private-repo",
        "https://github.com/example/private-repo-internal",
        "https://github.com/example",
        "https://github.com/example/other-private-repo/releases/tag/v1.0.0",
    ],
)
def test_a_clone_of_anything_but_the_tokens_repository_fails_before_any_git(
    monkeypatch, url
):
    def fake_run(cmd, **kwargs):
        raise AssertionError("git must not run")

    monkeypatch.setattr(scan_mod.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="is for|only over HTTPS"):
        scan_mod.clone_repo(url, credential=CREDENTIAL)


@pytest.mark.parametrize(
    "url",
    [
        REPO,
        f"{REPO}.git",
        f"{REPO}/",
        REPO.replace("example", "Example"),
        f"{REPO}/releases/tag/v1.0.0",
    ],
)
def test_the_tokens_repository_is_recognised_however_it_is_written(url):
    clone_url, _tag = scan_mod._extract_repo_and_tag(url)
    env = git_auth_env(CREDENTIAL, clone_url)
    assert env["GIT_CONFIG_KEY_0"].startswith("http.https://github.com/")


def test_a_credential_without_a_repository_authenticates_nothing():
    unbound = RepoCredential(host="github.com", username="x", token=TOKEN)
    with pytest.raises(ValueError, match="the repository URL is elsewhere"):
        git_auth_env(unbound, REPO)


def test_a_token_saved_before_tokens_were_bound_is_not_used(monkeypatch):
    """A project migrated without a repository for its token: its scan stops
    with what to do, and git never runs."""
    import app.tasks.dependency_discovery as dd

    monkeypatch.setattr(
        dd, "clone_repo", lambda *a, **k: (_ for _ in ()).throw(AssertionError)
    )
    with SessionLocal() as db:
        project = Project(
            machine_name="legacy",
            display_name="Legacy",
            repo_private=True,
            repo_token_host="github.com",
            repo_token_encrypted=encrypt_token(TOKEN),
        )
        db.add(project)
        db.flush()
        version = ProjectVersion(
            project_id=project.id,
            version="1.0.0",
            link_to_source_code=REPO,
            dependency_discovery_status="queued",
        )
        db.add(version)
        db.commit()
        version_id = version.id
    assert dd.discover_project_version_dependencies.run(version_id)["ok"] is False
    with SessionLocal() as db:
        stored = db.get(ProjectVersion, version_id)
        assert stored.dependency_discovery_error == (
            "Say which repository the access token is for on the project, "
            "and enter the token again"
        )


def test_a_private_projects_versions_and_branch_live_in_its_repository():
    c, _ = auth_client(role="admin")
    created = _create(c)
    pid = created["id"]
    other = "https://github.com/example/other-private-repo"
    detail = (
        f"must be in {REPO}, the repository this private project's access token is for"
    )

    def new_version(label, link):
        return c.post(
            f"/v1/projects/{pid}/versions",
            json={"version": label, "link_to_source_code": link},
            headers=_csrf(c),
        )

    refused = new_version("1.0.0", other)
    assert refused.status_code == 422
    assert refused.json() == {"detail": f"A version's source code link {detail}"}
    # In the repository, as a plain address, a release page, or with no link.
    kept = [
        new_version("1.0.0", REPO),
        new_version("1.1.0", f"{REPO}/releases/tag/v1.1.0"),
        new_version("1.2.0", None),
    ]
    assert [r.status_code for r in kept] == [200, 200, 200], [r.text for r in kept]
    vid = kept[0].json()["id"]
    moved = c.put(
        f"/v1/project-versions/{vid}",
        json={"link_to_source_code": f"{other}/releases/tag/v9"},
        headers=_csrf(c),
    )
    assert moved.status_code == 422
    assert moved.json() == {"detail": f"A version's source code link {detail}"}
    # Other edits to a version are unaffected.
    noted = c.put(
        f"/v1/project-versions/{vid}", json={"notes": "checked"}, headers=_csrf(c)
    )
    assert noted.status_code == 200, noted.text

    tracking = {"track_branch": True, "tracked_branch": "main"}
    elsewhere = c.put(
        f"/v1/projects/{pid}",
        json={**tracking, "tracked_repo_url": other},
        headers=_csrf(c),
    )
    assert elsewhere.status_code == 422
    assert elsewhere.json() == {"detail": f"The tracked repository {detail}"}
    assert _stored(pid).track_branch is False


def test_a_public_projects_versions_may_link_anywhere_allowed():
    c, _ = auth_client(role="admin")
    created = _create(c, repo_private=False, repo_token=None)
    response = c.post(
        f"/v1/projects/{created['id']}/versions",
        json={
            "version": "1.0.0",
            "link_to_source_code": "https://github.com/example/anything",
        },
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    ("url", "repository"),
    [
        ("https://github.com/Owner/Repo", "https://github.com/Owner/Repo"),
        ("https://GitHub.com./owner/repo.git/", "https://github.com/owner/repo"),
        ("https://github.com:443/owner/repo", "https://github.com/owner/repo"),
        (
            "https://github.com/owner/repo/releases/tag/v1",
            "https://github.com/owner/repo",
        ),
        (
            "https://github.com/owner/repo/tree/main/src",
            "https://github.com/owner/repo",
        ),
        (
            "https://gitlab.com/group/sub/project/-/tags/v1",
            "https://gitlab.com/group/sub/project",
        ),
        (
            "https://github.com/owner/repo/releases.atom",
            "https://github.com/owner/repo",
        ),
        ("https://github.com/owner", None),
        ("https://github.com/", None),
        ("http://github.com/owner/repo", None),
        ("https://github.com:8443/owner/repo", None),
        ("https://github.com:x/owner/repo", None),
        ("https://bot@github.com/owner/repo", None),
        ("https://github.com/owner/repo?ref=main", None),
        ("https://github.com/owner/repo#readme", None),
        ("https://github.com/owner/../repo", None),
        ("git@github.com:owner/repo.git", None),
        ("", None),
        (None, None),
    ],
)
def test_a_repository_is_read_one_way_from_the_addresses_inside_it(url, repository):
    from app.security.repo_credentials import repository_of, same_repository

    assert repository_of(url) == repository
    if repository:
        assert same_repository(url, repository.upper().replace("HTTPS", "https"))
        assert not same_repository(url, repository + "-other")
    else:
        assert not same_repository(url, url)


def test_discovery_passes_the_projects_credential(monkeypatch, tmp_path):
    import app.tasks.dependency_discovery as dd

    seen: list[RepoCredential | None] = []

    def fake_clone(url, version_hint=None, *, branch=None, credential=None):
        seen.append(credential)
        repo = tmp_path / f"repo{len(seen)}"
        repo.mkdir()
        return repo, "c0ffee"

    monkeypatch.setattr(dd, "clone_repo", fake_clone)
    monkeypatch.setattr(dd, "scan_syft", lambda root: None)
    monkeypatch.setattr(dd, "scan_grype", lambda root: None)
    with SessionLocal() as db:
        project = Project(
            machine_name="p",
            display_name="P",
            repo_private=True,
            repo_token_host="github.com",
            repo_token_repository=REPO,
            repo_token_encrypted=encrypt_token(TOKEN),
        )
        db.add(project)
        db.flush()
        version = ProjectVersion(
            project_id=project.id,
            version="1.0.0",
            link_to_source_code=REPO,
            dependency_discovery_status="queued",
        )
        db.add(version)
        db.commit()
        version_id = version.id

    assert dd.discover_project_version_dependencies.run(version_id)["ok"] is True
    assert seen == [CREDENTIAL]


def test_an_unreadable_token_is_reported_without_the_ciphertext(monkeypatch):
    import app.tasks.dependency_discovery as dd

    monkeypatch.setattr(
        dd, "clone_repo", lambda *a, **k: (_ for _ in ()).throw(AssertionError)
    )
    with SessionLocal() as db:
        project = Project(
            machine_name="p",
            display_name="P",
            repo_private=True,
            repo_token_host="github.com",
            repo_token_repository=REPO,
            repo_token_encrypted=encrypt_token(TOKEN),
        )
        db.add(project)
        db.flush()
        version = ProjectVersion(
            project_id=project.id,
            version="1.0.0",
            link_to_source_code=REPO,
            dependency_discovery_status="queued",
        )
        db.add(version)
        db.commit()
        version_id = version.id
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    dd.discover_project_version_dependencies.run(version_id)
    with SessionLocal() as db:
        stored = db.get(ProjectVersion, version_id)
        assert stored.dependency_discovery_status == "error"
        assert stored.dependency_discovery_error == (
            "The private repository's access token cannot be read; enter it again"
        )


def test_a_version_without_a_link_is_scanned_in_the_projects_repository(monkeypatch):
    """A scan asked for on a version with no source link repairs the link
    first: for a private project, with the repository its token is for."""
    from app.services import scan_queue

    monkeypatch.setattr(scan_queue, "launch_dependency_scan", lambda _id: False)
    c, _ = auth_client(role="admin")
    created = _create(
        c,
        release_rss_feed_url="https://github.com/example/somewhere-else/releases.atom",
    )
    version = c.post(
        f"/v1/projects/{created['id']}/versions",
        json={"version": "1.0.0"},
        headers=_csrf(c),
    ).json()
    queued = c.post(
        f"/v1/project-versions/{version['id']}/dependency-discovery",
        params={"run_now": "false"},
        headers=_csrf(c),
    )
    assert queued.status_code == 200, queued.text
    with SessionLocal() as db:
        assert db.get(ProjectVersion, version["id"]).link_to_source_code == REPO
