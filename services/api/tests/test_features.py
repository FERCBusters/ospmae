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


# --- Administrator-managed switches (ported from KEEN) ----------------------


def _admin_put(c, version, changes):
    return c.put(
        "/v1/admin/features",
        json={"version": version, "changes": changes},
        headers={"X-CSRF-Token": c.cookies.get("ospmae_csrf") or ""},
    )


def test_administrators_read_every_switch(client):
    c, _ = auth_client("FeatAdminRead", role="admin")
    body = c.get("/v1/admin/features").json()
    assert body["version"] == 0
    assert [item["key"] for item in body["items"]] == list(FEATURE_KEYS)
    assert body["enabled"] == {key: True for key in FEATURE_KEYS}
    assert body["configured"] == body["enabled"] == body["deployment"]


@pytest.mark.parametrize("role", ["viewer", "architect"])
def test_only_administrators_see_or_change_switches(client, role):
    c, _ = auth_client(f"FeatNonAdmin{role}", role=role)
    assert c.get("/v1/admin/features").status_code == 403
    assert _admin_put(c, 0, {"frameworks": False}).status_code == 403
    assert is_enabled("frameworks") is True


def test_an_administrator_switches_a_feature_off_and_on(client, db):
    from app.db.models import ManagedConfigurationRevision

    c, admin = auth_client("FeatAdminSave", role="admin")
    response = _admin_put(c, 0, {"frameworks": False})
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 1
    assert response.json()["enabled"]["frameworks"] is False
    # Every process sees the change straight away: routes, the UI's switches
    # and checks made outside any request.
    assert c.get("/v1/frameworks").status_code == 404
    assert c.get("/v1/system/features").json()["frameworks"] is False
    assert is_enabled("frameworks") is False
    assert c.get("/v1/projects").status_code == 200

    assert _admin_put(c, 1, {"frameworks": True}).status_code == 200
    assert c.get("/v1/frameworks").status_code == 200
    revisions = (
        db.query(ManagedConfigurationRevision)
        .order_by(ManagedConfigurationRevision.version)
        .all()
    )
    assert [(r.version, r.document["frameworks"], r.updated_by) for r in revisions] == [
        (1, False, admin.id),
        (2, True, admin.id),
    ]


def test_a_stale_save_is_refused(client):
    c, _ = auth_client("FeatAdminStale", role="admin")
    assert _admin_put(c, 0, {"questions": False}).status_code == 200
    stale = _admin_put(c, 0, {"manifests": False})
    assert stale.status_code == 409
    assert stale.json() == {
        "detail": "Features changed in another session. Reload before saving."
    }
    assert is_enabled("manifests") is True


@pytest.mark.parametrize(
    "body",
    [
        {"version": 0, "changes": {"unknown": False}},
        {"version": 0, "changes": {"frameworks": "false"}},
        {"version": 0, "changes": {"frameworks": 0}},
        {"version": True, "changes": {"frameworks": False}},
        {"version": -1, "changes": {"frameworks": False}},
        {"version": 0, "changes": {}},
        {"version": 0},
    ],
)
def test_malformed_saves_are_refused(client, body):
    c, _ = auth_client("FeatAdminBad", role="admin")
    response = c.put(
        "/v1/admin/features",
        json=body,
        headers={"X-CSRF-Token": c.cookies.get("ospmae_csrf") or ""},
    )
    assert response.status_code == 422
    assert c.get("/v1/admin/features").json()["version"] == 0


def test_the_deployment_setting_is_a_ceiling(client, monkeypatch):
    monkeypatch.setattr(settings, "feature_manifests", False)
    c, _ = auth_client("FeatCeiling", role="admin")
    body = c.get("/v1/admin/features").json()
    assert body["deployment"]["manifests"] is False
    assert body["configured"]["manifests"] is True
    assert body["enabled"]["manifests"] is False
    refused = _admin_put(c, 0, {"manifests": True})
    assert refused.status_code == 409
    assert "OSPMAE_FEATURE_MANIFESTS=false" in refused.json()["detail"]
    assert c.get("/v1/manifests").status_code == 404
    # Other switches still save.
    assert _admin_put(c, 0, {"comparisons": False}).status_code == 200


def test_a_change_saved_elsewhere_is_seen_without_a_restart(client, db):
    from app.db.models import ManagedConfiguration

    assert is_enabled("questions") is True
    db.add(
        ManagedConfiguration(name="features", document={"questions": False}, version=7)
    )
    db.commit()
    assert is_enabled("questions") is False
    assert public_dict()["questions"] is False


def test_switched_off_background_work_is_skipped(client):
    from app.tasks.dependency_queue import dispatch_queued_dependency_discoveries
    from app.tasks.release_feed import poll_release_feeds

    c, _ = auth_client("FeatTasks", role="admin")
    assert (
        _admin_put(c, 0, {"release_feed": False, "dependency_scans": False}).status_code
        == 200
    )
    assert poll_release_feeds.run()["enabled"] is False
    assert dispatch_queued_dependency_discoveries.run() == {
        "ok": False,
        "reason": "dependency_scans feature disabled",
    }


def test_beat_keeps_schedules_the_deployment_allows():
    # Administrator switches decide at run time; only the ceiling removes a
    # schedule, so switching a feature back on needs no beat restart.
    from app.celery_app import celery_app

    schedule = celery_app.conf.beat_schedule
    assert "poll-project-release-feeds" in schedule
    assert "dispatch-queued-dependency-discoveries" in schedule


def test_unknown_feature_names_are_programming_errors():
    with pytest.raises(ValueError):
        is_enabled("nonsense")


def test_the_navbar_learns_the_features_with_the_account(client):
    c, _ = auth_client("FeatNavbar", role="admin")
    assert c.get("/v1/me").json()["features"] == {key: True for key in FEATURE_KEYS}
    assert _admin_put(c, 0, {"manifests": False}).status_code == 200
    features = c.get("/v1/me").json()["features"]
    assert features["manifests"] is False
    assert features["frameworks"] is True
