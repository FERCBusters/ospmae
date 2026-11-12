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
        "repo_token_host": "github.com",
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


def test_a_token_does_not_follow_a_new_host_unless_entered_again():
    c, _ = auth_client(role="admin")
    created = _create(c)
    response = c.put(
        f"/v1/projects/{created['id']}",
        json={"repo_private": True, "repo_token_host": "gitlab.com"},
        headers=_csrf(c),
    )
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Enter the access token again for the new host"
    }
    assert _stored(created["id"]).repo_token_host == "github.com"

    response = c.put(
        f"/v1/projects/{created['id']}",
        json={
            "repo_private": True,
            "repo_token_host": "gitlab.com",
            "repo_token": "glpat-new",
        },
        headers=_csrf(c),
    )
    assert response.status_code == 200, response.text
    stored = _stored(created["id"])
    assert (stored.repo_token_host, decrypt_token(stored.repo_token_encrypted)) == (
        "gitlab.com",
        "glpat-new",
    )


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
        ({"repo_token_host": None}, "Enter the host the access token is for"),
        (
            {"repo_token_host": "codeberg.org"},
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
        {"repo_token": "has a space"},
        {"repo_token_username": "a:b"},
        {"repo_token": "x" * 1025},
    ],
)
def test_malformed_private_settings_are_refused_without_echo(overrides):
    c, _ = auth_client(role="admin")
    response = c.post("/v1/projects", json=_body(**overrides), headers=_csrf(c))
    assert response.status_code == 422
    for value in overrides.values():
        if value not in {"github.com/x", "evil.example"}:
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
        repo_token_username=username,
        repo_token_encrypted=encrypt_token(TOKEN),
    )
    credential = project_credential(project)
    assert (credential.host, credential.username, credential.token) == (
        host,
        expected,
        TOKEN,
    )


def test_public_projects_have_no_credential():
    assert project_credential(Project(repo_private=False)) is None


# --- Git ---------------------------------------------------------------------


CREDENTIAL = RepoCredential(host="github.com", username="x-access-token", token=TOKEN)


def test_the_token_is_a_header_scoped_to_its_host():
    env = git_auth_env(CREDENTIAL, REPO)
    basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    assert env == {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }
    # git reads the scoped header from its environment.
    shown = subprocess.run(
        ["git", "config", "--get-urlmatch", "http.extraHeader", f"{REPO}.git"],
        env={**scan_mod._git_env(), **env},
        capture_output=True,
        text=True,
        check=True,
    )
    assert shown.stdout.strip() == f"Authorization: Basic {basic}"
    elsewhere = subprocess.run(
        ["git", "config", "--get-urlmatch", "http.extraHeader", "https://gitlab.com/x"],
        env={**scan_mod._git_env(), **env},
        capture_output=True,
        text=True,
    )
    assert elsewhere.stdout == ""


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


def test_a_mismatched_source_url_fails_before_any_git(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise AssertionError("git must not run")

    monkeypatch.setattr(scan_mod.subprocess, "run", fake_run)
    with pytest.raises(ValueError):
        scan_mod.clone_repo("https://gitlab.com/example/x", credential=CREDENTIAL)


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
    assert seen == [
        RepoCredential(host="github.com", username="x-access-token", token=TOKEN)
    ]


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
