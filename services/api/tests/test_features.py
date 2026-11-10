"""Feature switches gate every surface (routes, tasks, seeding)."""

from __future__ import annotations

import pytest
from app.core.config import settings
from app.core.features import FEATURE_KEYS, is_enabled, public_dict

from tests.conftest import auth_client


@pytest.mark.parametrize("key", FEATURE_KEYS)
def test_public_dict_and_is_enabled(key):
    assert public_dict()[key] is True
    assert is_enabled(key) is True
    saved = getattr(settings, f"feature_{key}")
    try:
        setattr(settings, f"feature_{key}", False)
        assert is_enabled(key) is False
    finally:
        setattr(settings, f"feature_{key}", saved)


def _toggle(monkeypatch, key, value):

    monkeypatch.setenv(f"OSPMAE_FEATURE_{key.upper()}", str(value).lower())
    # Settings are frozen at import; flip the live object like the env would.
    saved = getattr(settings, f"feature_{key}")
    setattr(settings, f"feature_{key}", value)
    return saved


def test_frameworks_off_404s_framework_routes(client):
    saved = _toggle_off("frameworks")
    try:
        c, _u = auth_client("FeatF")
        assert c.get("/v1/frameworks").status_code == 404
        csrf = c.cookies.get("ospmae_csrf")
        assert (
            c.post(
                "/v1/frameworks", json={}, headers={"X-CSRF-Token": csrf or ""}
            ).status_code
            == 404
        )
        assert c.get("/v1/frameworks/1").status_code == 404
        # projects stay alive
        assert c.get("/v1/projects").status_code == 200
    finally:
        _restore("frameworks", saved)


def test_manifests_off_404s_manifest_routes(client):
    saved = _toggle_off("manifests")
    try:
        c, _u = auth_client("FeatM")
        csrf = c.cookies.get("ospmae_csrf")
        assert c.get("/v1/manifests").status_code == 404
        assert (
            c.post(
                "/v1/projects/1/manifest/save",
                json={},
                headers={"X-CSRF-Token": csrf or ""},
            ).status_code
            == 404
        )
        assert c.get("/v1/projects").status_code == 200
    finally:
        _restore("manifests", saved)


def test_dependency_scans_off_404s_dependency_routes(client):
    saved = _toggle_off("dependency_scans")
    try:
        c, _u = auth_client("FeatD")
        assert (
            c.get(
                "/v1/dependencies/graph",
                params={"project_id": 1},
            ).status_code
            == 404
        )
        assert c.get("/v1/capabilities/1").status_code == 404
    finally:
        _restore("dependency_scans", saved)


def test_questions_off_404s_question_routes(client):
    saved = _toggle_off("questions")
    try:
        c, _u = auth_client("FeatQ")
        csrf = c.cookies.get("ospmae_csrf")
        assert c.get("/v1/questions/unanswered").status_code == 404
        assert (
            c.post(
                "/v1/projects/1/questions",
                json={"body": "x"},
                headers={"X-CSRF-Token": csrf or ""},
            ).status_code
            == 404
        )
    finally:
        _restore("questions", saved)


def test_comparisons_off_404s_compare(client):
    saved = _toggle_off("comparisons")
    try:
        c, _u = auth_client("FeatC")
        r = c.get("/v1/projects/compare?left_project_id=1&right_project_id=1")
        assert r.status_code in (404, 422), r.status_code
        assert "feature" not in r.text.lower() or "comparisons" not in r.text
    finally:
        _restore("comparisons", saved)


def _toggle_off(key: str):
    saved = getattr(settings, f"feature_{key}")
    setattr(settings, f"feature_{key}", False)
    return saved


def _restore(key: str, saved) -> None:
    setattr(settings, f"feature_{key}", saved)
