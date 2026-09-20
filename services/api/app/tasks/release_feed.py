from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse, urljoin
import re
import xml.etree.ElementTree as ET

import httpx
from celery.utils.log import get_task_logger
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from app.celery_app import celery_app
from app.core.config import settings
from app.db.models import (
    Project,
    ProjectOwnerGroup,
    ProjectVersion,
    ProjectVersionFrameworkNode,
    User,
    UserGroup,
)
from app.db.session import SessionLocal
from app.services.mailer import send_project_version_draft_email
from app.services.notification_recipients import notification_emails_for_users
from app.services.entity_changelog import (
    project_version_changelog_state,
    record_entity_changelog,
)
from app.services.versioning import is_semantically_lower
from app.security.url_safety import (
    validate_public_http_url_resolved,
    contains_xml_dtd_or_entity,
)

log = get_task_logger(__name__)


def _safe_fetch_feed(
    client: httpx.Client, url: str, headers: dict[str, str]
) -> tuple[httpx.Response, bytes | None, str]:
    """Fetch a release feed safely.

    - Validates the URL (http/https only, blocks localhost/private IP literals).
    - Disables automatic redirects; follows a small, validated redirect chain.
    - Streams the response and enforces a maximum size.

    Returns (response, content_bytes_or_None, final_url).
    """
    max_bytes = int(getattr(settings, "release_feed_max_bytes", 2_000_000) or 2_000_000)
    max_redirects = int(getattr(settings, "release_feed_max_redirects", 3) or 3)

    current = validate_public_http_url_resolved(url)

    for _hop in range(max_redirects + 1):
        with client.stream(
            "GET", current, headers=headers, follow_redirects=False
        ) as resp:
            if resp.status_code in {301, 302, 303, 307, 308}:
                loc = (resp.headers.get("location") or "").strip()
                if not loc:
                    return resp, None, current
                current = validate_public_http_url_resolved(urljoin(current, loc))
                continue

            if resp.status_code in {304}:
                return resp, None, current

            if resp.status_code != 200:
                return resp, None, current

            buf = bytearray()
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise ValueError("Release feed response too large")
            return resp, bytes(buf), current

    raise ValueError("Too many redirects while fetching release feed")


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


def _to_naive_utc(dt: datetime | None) -> datetime | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _localname(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def _text_first(el: ET.Element | None, names: list[str]) -> str | None:
    if el is None:
        return None
    for child in list(el):
        if _localname(child.tag) in names:
            txt = (child.text or "").strip()
            if txt:
                return txt
    return None


def _find_children(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in list(el) if _localname(c.tag) == name]


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    # Atom (ISO 8601)
    try:
        if v.endswith("Z"):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return datetime.fromisoformat(v)
    except Exception:
        pass
    # RSS (RFC822)
    try:
        return parsedate_to_datetime(v)
    except Exception:
        return None


def _parse_feed_entries(xml_data: bytes) -> list[dict[str, Any]]:
    """Parse a minimal subset of RSS/Atom feeds.

    Input is raw XML bytes (size-limited by the fetcher).

    Returns list of entries, each with keys: id, title, link, published_dt.
    """

    if contains_xml_dtd_or_entity(xml_data):
        raise ValueError("DTD/ENTITY not allowed in release feeds")

    root = ET.fromstring(xml_data)
    root_name = _localname(root.tag).lower()

    entries: list[dict[str, Any]] = []

    if root_name == "feed":
        # Atom
        for entry in _find_children(root, "entry"):
            entry_id = _text_first(entry, ["id"]) or ""
            title = _text_first(entry, ["title"]) or ""
            published_raw = _text_first(entry, ["published", "updated"]) or ""
            published_dt = _parse_datetime(published_raw)

            link = ""
            for link_el in _find_children(entry, "link"):
                href = (link_el.attrib.get("href") or "").strip()
                rel = (link_el.attrib.get("rel") or "").strip().lower()
                if href and (not rel or rel == "alternate"):
                    link = href
                    break
            if not link:
                # Fallback to text content
                link = _text_first(entry, ["link"]) or ""

            key = (entry_id or link or title).strip()
            if not key:
                continue
            entries.append(
                {
                    "id": key,
                    "title": title.strip() or key,
                    "link": link.strip() or None,
                    "published_dt": published_dt,
                }
            )
    else:
        # RSS: <rss><channel><item>...
        channel = None
        for child in list(root):
            if _localname(child.tag) == "channel":
                channel = child
                break
        if channel is not None:
            for item in _find_children(channel, "item"):
                guid = _text_first(item, ["guid"]) or ""
                title = _text_first(item, ["title"]) or ""
                link = _text_first(item, ["link"]) or ""
                pub_raw = _text_first(item, ["pubDate", "date"]) or ""
                published_dt = _parse_datetime(pub_raw)
                key = (guid or link or title).strip()
                if not key:
                    continue
                entries.append(
                    {
                        "id": key,
                        "title": title.strip() or key,
                        "link": link.strip() or None,
                        "published_dt": published_dt,
                    }
                )

    # Sort oldest -> newest so we can process in order.
    def sort_key(e: dict[str, Any]):
        dt = e.get("published_dt")
        if isinstance(dt, datetime):
            return dt
        return datetime.min.replace(tzinfo=timezone.utc)

    entries.sort(key=sort_key)
    return entries


def _guess_version_from_entry(title: str, link: str | None) -> str | None:
    t = (title or "").strip()
    if not t:
        return None

    # GitHub releases Atom entries often look like: "Release v1.2.3 · owner/repo"
    lowered = t.lower()
    if lowered.startswith("release "):
        rest = t[len("release ") :].strip()
        # strip "· owner/repo" suffix
        if "·" in rest:
            rest = rest.split("·", 1)[0].strip()
        if rest:
            return rest

    # Try deriving from link like .../releases/tag/v1.2.3
    if link:
        try:
            p = urlparse(link)
            parts = [x for x in p.path.split("/") if x]
            for i in range(len(parts) - 1):
                if parts[i] == "tag" and i + 1 < len(parts):
                    return parts[i + 1]
        except Exception:
            pass

    return t


def _normalised_release_ignore_patterns(project: Project) -> list[dict[str, Any]]:
    raw_patterns = getattr(project, "release_rss_ignore_patterns", None) or []
    if not isinstance(raw_patterns, list):
        return []

    patterns: list[dict[str, Any]] = []
    for raw in raw_patterns:
        if isinstance(raw, str):
            text = raw.strip()
            if not text:
                continue
            if text.lower().startswith("regex:"):
                patterns.append({"match_type": "regex", "pattern": text[6:].strip()})
            elif text.lower().startswith("contains:"):
                patterns.append({"match_type": "contains", "pattern": text[9:].strip()})
            else:
                patterns.append({"match_type": "contains", "pattern": text})
            continue

        if not isinstance(raw, dict):
            continue
        pattern = str(raw.get("pattern") or "").strip()
        if not pattern:
            continue
        match_type = (
            str(raw.get("match_type") or raw.get("type") or "contains").strip().lower()
        )
        if match_type in {"simple", "string", "substring"}:
            match_type = "contains"
        if match_type in {"regexp", "regular_expression"}:
            match_type = "regex"
        if match_type not in {"contains", "regex"}:
            continue
        patterns.append(
            {
                "match_type": match_type,
                "pattern": pattern,
                "case_sensitive": bool(raw.get("case_sensitive", False)),
            }
        )
    return patterns


def _release_feed_entry_is_ignored(
    project: Project, entry: dict[str, Any], version_name: str
) -> bool:
    patterns = _normalised_release_ignore_patterns(project)
    if not patterns:
        return False

    candidates = [
        version_name,
        str(entry.get("title") or ""),
        str(entry.get("link") or ""),
        str(entry.get("id") or ""),
    ]
    candidates = [c for c in candidates if c]

    for rule in patterns:
        pattern = str(rule.get("pattern") or "").strip()
        if not pattern:
            continue
        match_type = str(rule.get("match_type") or "contains").strip().lower()
        case_sensitive = bool(rule.get("case_sensitive", False))

        if match_type == "regex":
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                compiled = re.compile(pattern, flags=flags)
            except re.error:
                log.warning(
                    "Skipping invalid release-feed ignore regex for project_id=%s",
                    project.id,
                )
                continue
            if any(compiled.search(candidate) for candidate in candidates):
                return True
            continue

        needle = pattern if case_sensitive else pattern.lower()
        for candidate in candidates:
            haystack = candidate if case_sensitive else candidate.lower()
            if needle in haystack:
                return True

    return False


def _guess_source_code_url_from_release_link(link: str | None) -> str | None:
    if not link:
        return None
    try:
        p = urlparse(link)
        host = (p.netloc or "").lower()
        parts = [x for x in p.path.split("/") if x]

        # GitHub: https://github.com/<owner>/<repo>/releases/tag/<tag>
        if host == "github.com" and len(parts) >= 2:
            return f"{p.scheme}://{p.netloc}/{parts[0]}/{parts[1]}"
    except Exception:
        return None
    return None


def _owner_emails(db, project: Project) -> list[str]:
    """Return canonical primary notification addresses for project owners."""

    users: dict[int, User] = {}

    if project.created_by_user_id:
        owner = (
            db.query(User)
            .filter(User.id == project.created_by_user_id)
            .filter(User.is_active.is_(True))
            .one_or_none()
        )
        if owner:
            users[owner.id] = owner

    owner_group_ids = {
        int(gid)
        for (gid,) in db.query(ProjectOwnerGroup.group_id)
        .filter(ProjectOwnerGroup.project_id == project.id)
        .all()
        if gid is not None
    }

    if owner_group_ids:
        group_users = (
            db.query(User)
            .join(UserGroup, UserGroup.user_id == User.id)
            .filter(UserGroup.group_id.in_(sorted(owner_group_ids)))
            .filter(User.is_active.is_(True))
            .all()
        )
        users.update({user.id: user for user in group_users})

    return notification_emails_for_users(db, users=list(users.values()))


def _public_project_url(project_id: int) -> str | None:
    base = str(getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
    if not base:
        return None
    return f"{base}/project.html?id={int(project_id)}"


def _latest_published_version(db, project_id: int) -> ProjectVersion | None:
    return (
        db.query(ProjectVersion)
        .filter(ProjectVersion.project_id == project_id)
        .filter(ProjectVersion.is_draft.is_(False))
        .order_by(
            ProjectVersion.is_latest.desc(),
            ProjectVersion.release_date.desc().nullslast(),
            ProjectVersion.updated_at.desc(),
            ProjectVersion.created_at.desc(),
        )
        .first()
    )


def _is_semantically_lower_than_current_latest(
    db, project_id: int, candidate_version: str
) -> bool:
    latest = _latest_published_version(db, project_id)
    if not latest:
        return False

    lower = is_semantically_lower(candidate_version, getattr(latest, "version", None))
    return lower is True


def _best_version_for_capability_inheritance(
    db, project_id: int
) -> ProjectVersion | None:
    """Pick a sensible version to inherit capability mappings from.

    We prefer inheriting from a version that already has capability selections.
    In practice, the best default is usually the most-recently updated published
    version.

    Preference order:
      1) Non-draft versions that have capability mappings.
      2) Any non-draft version.
      3) Draft versions that have capability mappings.
      4) Any version.

    Within each bucket, prefer is_latest, then most recently updated.
    """

    q = (
        db.query(
            ProjectVersion,
            func.count(ProjectVersionFrameworkNode.id).label("cap_count"),
        )
        .outerjoin(
            ProjectVersionFrameworkNode,
            ProjectVersionFrameworkNode.project_version_id == ProjectVersion.id,
        )
        .filter(ProjectVersion.project_id == project_id)
        .group_by(ProjectVersion.id)
        .order_by(
            ProjectVersion.is_draft.asc(),
            func.count(ProjectVersionFrameworkNode.id).desc(),
            ProjectVersion.is_latest.desc(),
            ProjectVersion.updated_at.desc(),
            ProjectVersion.created_at.desc(),
        )
    )

    row = q.first()
    return row[0] if row else None


@celery_app.task(name="app.tasks.release_feed.poll_release_feeds")
def poll_release_feeds(limit_projects: int = 50) -> dict[str, Any]:
    """Poll configured release feeds and create draft versions for new releases."""

    if not bool(getattr(settings, "release_feed_poll_enabled", True)):
        return {"enabled": False, "checked": 0, "created": 0, "ignored": 0}

    db = SessionLocal()
    checked = 0
    created = 0
    ignored = 0

    try:
        projects = (
            db.query(Project)
            .filter(Project.release_rss_feed_url.isnot(None))
            .order_by(Project.updated_at.desc())
            .limit(int(limit_projects or 50))
            .all()
        )

        with httpx.Client(timeout=20, follow_redirects=False) as client:
            for project in projects:
                url = str(project.release_rss_feed_url or "").strip()
                if not url:
                    continue

                checked += 1
                headers = {}
                if project.release_rss_last_etag:
                    headers["If-None-Match"] = str(project.release_rss_last_etag)
                if project.release_rss_last_modified:
                    headers["If-Modified-Since"] = str(
                        project.release_rss_last_modified
                    )

                try:
                    resp, content, final_url = _safe_fetch_feed(client, url, headers)
                except Exception:
                    log.exception("Release feed fetch failed")
                    project.release_rss_last_checked_at = _utcnow_naive()
                    db.add(project)
                    db.commit()
                    continue

                project.release_rss_last_checked_at = _utcnow_naive()
                if resp.status_code == 304:
                    db.add(project)
                    db.commit()
                    continue

                if resp.status_code != 200:
                    log.warning(
                        "Release feed HTTP %s for project_id=%s",
                        resp.status_code,
                        project.id,
                    )
                    db.add(project)
                    db.commit()
                    continue

                etag = resp.headers.get("etag")
                last_mod = resp.headers.get("last-modified")
                if etag:
                    project.release_rss_last_etag = etag
                if last_mod:
                    project.release_rss_last_modified = last_mod

                if not content or not content.strip():
                    db.add(project)
                    db.commit()
                    continue

                try:
                    entries = _parse_feed_entries(content)
                except Exception:
                    log.exception(
                        "Failed to parse release feed for project_id=%s", project.id
                    )
                    db.add(project)
                    db.commit()
                    continue

                if not entries:
                    db.add(project)
                    db.commit()
                    continue

                last_seen_id = (
                    str(project.release_rss_last_entry_id or "").strip() or None
                )
                newest_id = str(entries[-1].get("id") or "").strip() or None

                # Determine which entries are new.
                new_entries: list[dict[str, Any]] = []
                if last_seen_id:
                    idx = next(
                        (
                            i
                            for i, e in enumerate(entries)
                            if str(e.get("id") or "").strip() == last_seen_id
                        ),
                        None,
                    )
                    if idx is None:
                        # Feed rotated/truncated; only consider newest.
                        new_entries = [entries[-1]]
                    else:
                        new_entries = entries[idx + 1 :]
                else:
                    # First run: only consider newest entry, and only if it isn't already present.
                    new_entries = [entries[-1]]

                # Record newest entry id so we don't keep reprocessing.
                if newest_id:
                    project.release_rss_last_entry_id = newest_id

                # Create draft versions for new entries.
                created_versions: list[ProjectVersion] = []

                # Find a sensible inheritance source for capability mappings (and optionally
                # link_to_source_code). Prefer the most-recently updated published version
                # that already has capability selections.
                inheritance_source = _best_version_for_capability_inheritance(
                    db, project.id
                )

                for entry in new_entries:
                    title = str(entry.get("title") or "").strip()
                    link = entry.get("link")
                    version_name = _guess_version_from_entry(title, link)
                    if not version_name:
                        continue

                    if _release_feed_entry_is_ignored(project, entry, version_name):
                        ignored += 1
                        log.info(
                            "Ignoring release-feed entry for project_id=%s version=%s due to configured ignore pattern",
                            project.id,
                            version_name,
                        )
                        continue

                    exists = (
                        db.query(ProjectVersion.id)
                        .filter(ProjectVersion.project_id == project.id)
                        .filter(ProjectVersion.version == version_name)
                        .one_or_none()
                    )
                    if exists:
                        continue

                    if _is_semantically_lower_than_current_latest(
                        db, project.id, version_name
                    ):
                        log.info(
                            "Skipping release-feed draft for project_id=%s version=%s because it is lower than the current latest published version",
                            project.id,
                            version_name,
                        )
                        continue

                    release_dt = _to_naive_utc(entry.get("published_dt"))

                    # Prefer deriving the repository from the current release link.
                    # Falling back to the inheritance source is fine, but we must avoid
                    # copying an older tag/release URL onto a newer version.
                    link_to_source = _guess_source_code_url_from_release_link(link)
                    if not link_to_source and (
                        inheritance_source
                        and str(inheritance_source.link_to_source_code or "").strip()
                    ):
                        link_to_source = str(
                            inheritance_source.link_to_source_code
                        ).strip()

                    notes = None
                    if link:
                        notes = f"Auto-imported from release feed: {link}"

                    pv = ProjectVersion(
                        project_id=project.id,
                        version=version_name,
                        release_date=release_dt,
                        status=None,
                        link_to_source_code=link_to_source,
                        notes=notes,
                        is_latest=False,
                        is_draft=True,
                    )

                    db.add(pv)
                    db.flush()

                    # Inherit capability mappings from the previous version so maintainers
                    # don't need to re-select the same capabilities on every draft.
                    #
                    # NOTE: we intentionally copy *exactly* the node links; maintainers can
                    # still edit them on the draft before publishing.
                    if inheritance_source:
                        inherited_capability_ids = (
                            db.query(ProjectVersionFrameworkNode.framework_node_id)
                            .filter(
                                ProjectVersionFrameworkNode.project_version_id
                                == inheritance_source.id
                            )
                            .all()
                        )
                        for (framework_node_id,) in inherited_capability_ids:
                            db.add(
                                ProjectVersionFrameworkNode(
                                    project_version_id=pv.id,
                                    framework_node_id=framework_node_id,
                                )
                            )

                    db.flush()
                    db.refresh(pv)
                    record_entity_changelog(
                        db,
                        entity_type="project_version",
                        entity_id=pv.id,
                        action="created",
                        before=None,
                        after=project_version_changelog_state(db, pv),
                        user=None,
                        request_method="TASK",
                        request_path="release_feed.poll_release_feeds",
                    )

                    # Once we've created at least one draft, use the newest draft as the
                    # inheritance source for subsequent new entries in the same run. This
                    # keeps capability selection consistent when multiple new releases are
                    # created from one poll.
                    inheritance_source = pv

                    created_versions.append(pv)
                    created += 1

                try:
                    db.add(project)
                    db.commit()
                except IntegrityError:
                    db.rollback()
                    log.exception(
                        "Integrity error while creating release feed versions"
                    )
                    continue

                if created_versions:
                    # NOTE: email sending is intentionally best-effort, but we log when
                    # it is skipped or fails so operators can diagnose issues.
                    if not (
                        str(getattr(settings, "smtp_host", "") or "").strip()
                        and str(getattr(settings, "smtp_from_email", "") or "").strip()
                    ):
                        log.info(
                            "SMTP not configured; skipping draft release notifications for project_id=%s",
                            project.id,
                        )
                    else:
                        recipients = _owner_emails(db, project)
                        if not recipients:
                            log.info(
                                "No owner emails found; skipping draft release notifications for project_id=%s",
                                project.id,
                            )
                        else:
                            url_for_email = _public_project_url(project.id)
                            for pv in created_versions:
                                for email in recipients:
                                    try:
                                        send_project_version_draft_email(
                                            to_email=email,
                                            project_name=project.display_name,
                                            version=pv.version,
                                            project_url=url_for_email,
                                            source="release feed",
                                        )
                                        log.info(
                                            "Draft release notification sent to %s for project_id=%s version=%s",
                                            email,
                                            project.id,
                                            pv.version,
                                        )
                                    except Exception:
                                        log.exception(
                                            "Draft release notification failed to %s for project_id=%s version=%s",
                                            email,
                                            project.id,
                                            pv.version,
                                        )

        return {
            "enabled": True,
            "checked": checked,
            "created": created,
            "ignored": ignored,
        }
    finally:
        db.close()
