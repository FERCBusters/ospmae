"""mosp's request screening in front of OSPMAE's own routes.

mosp's suite covers the screening itself; these check that OSPMAE's routes sit
behind it and that OSPMAE's validation handler does not echo what was sent.
"""

from __future__ import annotations

import pytest
from app.db.models import AuditLog, Organisation
from app.db.session import SessionLocal

from tests.conftest import auth_client
from tests.support import csrf

TARGET_REFUSED = (400, {"detail": "Invalid request target"})
TOO_LARGE = (413, {"detail": "Request body too large"})


def outcome(response):
    return response.status_code, response.json()


def test_an_oversized_write_changes_nothing():
    c, _ = auth_client(role="admin")
    big = {"name": "huge", "description": "x" * (2 * 1024 * 1024)}
    response = c.post("/v1/admin/organisations", json=big, headers=csrf(c))
    assert outcome(response) == TOO_LARGE
    with SessionLocal() as db:
        assert db.query(Organisation).count() == 0


def test_a_nul_character_is_stored_as_a_replacement():
    """PostgreSQL text cannot hold NUL: mosp's routes read it as U+FFFD."""
    c, _ = auth_client(role="admin")
    response = c.post(
        "/v1/admin/organisations",
        content=b'{"name": "a\\u0000b"}',
        headers={**csrf(c), "Content-Type": "application/json"},
    )
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert [o.name for o in db.query(Organisation)] == ["a\ufffdb"]


@pytest.mark.parametrize(
    "target",
    [
        "/v1/projects/a%2Fb",
        "/v1/projects/a%5Cb",
        "/v1/projects/a%2fb",
        "/v1/projects?q=a%00b",
    ],
)
def test_misleading_request_targets_are_refused(client, target):
    assert outcome(client.get(target)) == TARGET_REFUSED


def test_validation_errors_do_not_echo_submitted_values():
    c, _ = auth_client(role="admin")
    secret = "correct-horse-battery-staple"
    response = c.post(
        "/v1/admin/organisations",
        json={"name": ["not", "text"], "description": secret},
        headers=csrf(c),
    )
    assert response.status_code == 422
    assert secret not in response.text
    for item in response.json()["detail"]:
        assert set(item) == {"type", "loc", "msg"}
    assert response.json()["detail"][0]["loc"] == ["body", "name"]


def test_health_polls_are_not_recorded(client):
    assert client.get("/v1/system/health").status_code == 200
    with SessionLocal() as db:
        assert db.query(AuditLog).filter_by(path="/v1/system/health").count() == 0


def test_the_question_badge_poll_is_not_recorded():
    """The navigation bar polls the unanswered-question count on every page."""
    c, _ = auth_client(role="admin")
    assert c.get("/v1/questions/unanswered/summary").status_code == 200
    with SessionLocal() as db:
        recorded = db.query(AuditLog).filter_by(path="/v1/questions/unanswered/summary")
        assert recorded.count() == 0
