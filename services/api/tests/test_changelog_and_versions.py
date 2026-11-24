"""The catalogue changelog's record of an edit, and how version labels
compare."""

from __future__ import annotations

from app.db.session import SessionLocal
from app.services.entity_changelog import (
    _clean_scalar,
    _field_label,
    diff_states,
    list_entity_changelogs,
    record_entity_changelog,
)
from app.services.versioning import (
    compare_semanticish_versions,
    is_semantically_newer,
    parse_semanticish_version,
)


def test_an_edit_is_recorded_field_by_field(client):
    before = {"display_name": "A", "status": "draft"}
    after = {"display_name": "B", "status": "released"}
    assert len(diff_states(before, after)) == 2
    with SessionLocal() as s:
        record_entity_changelog(
            s,
            entity_type="project",
            entity_id=1,
            action="edited",
            before=before,
            after=after,
        )
        s.commit()
        rows = list_entity_changelogs(s, entity_type="project", entity_id=1)["items"]
    assert [row["entity_type"] for row in rows] == ["project"]
    assert _clean_scalar(None) is None
    assert _field_label("display_name")


def test_version_labels_compare_by_their_numbers():
    assert parse_semanticish_version("1.2.3") is not None
    assert compare_semanticish_versions("1.3.0", "1.2.3") == 1
    assert compare_semanticish_versions("1.10.0", "1.9.9") == 1
    assert is_semantically_newer("1.2.3", "1.2.3") is False
    assert is_semantically_newer("1.2.4", "1.2.3") is True
