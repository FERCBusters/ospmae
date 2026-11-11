from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, StrictInt, field_validator, model_validator

from app.depscan.scan import validate_git_ref_name, validate_repo_url
from app.security.regex_shape import MAX_PATTERN_CHARS, compile_supplied_pattern
from app.security.repo_credentials import (
    MAX_TOKEN_CHARS,
    clean_host,
    clean_token,
    clean_username,
)
from app.security.url_safety import validate_public_http_url, validate_safe_href
from app.services.branch_tracking import (
    MAX_POLL_INTERVAL_HOURS,
    MIN_POLL_INTERVAL_HOURS,
)


def _optional_repo_url(value: Any) -> str | None:
    """A git repository URL the scanner may clone, or None when blank."""

    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Must be a supported git URL and on an allowed host.
    validate_repo_url(s)
    return s


def _clean_tag_list(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        s = str(raw or "").strip()
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


# -----------------------------------------------------------------------------
# Auth / admin
# -----------------------------------------------------------------------------


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=8, max_length=200)


class ChangePasswordPayload(BaseModel):
    current_password: str = Field(min_length=8, max_length=200)
    new_password: str = Field(min_length=8, max_length=200)
    confirm_password: str = Field(min_length=8, max_length=200)


class AdminSetPasswordPayload(BaseModel):
    new_password: str = Field(min_length=8, max_length=200)


class AdminUserCreatePayload(BaseModel):
    username: str = Field(min_length=1, max_length=160)
    email: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=8, max_length=200)
    role: str = Field(min_length=1, max_length=50)


class AdminUserUpdatePayload(BaseModel):
    role: str | None = Field(default=None, min_length=1, max_length=50)
    is_active: bool | None = None
    email: str | None = Field(default=None, max_length=255)


class AdminGroupCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    role: str | None = Field(default=None, max_length=50)


class AdminGroupUpdatePayload(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    role: str | None = Field(default=None, max_length=50)


# Identifier lists are JSON arrays of integers: a string such as "12" is
# refused rather than read character by character.
class AdminUserAccessUpdatePayload(BaseModel):
    group_ids: list[StrictInt] = Field(default_factory=list, max_length=500)
    permission_ids: list[StrictInt] = Field(default_factory=list, max_length=500)


class AdminGroupPermissionsUpdatePayload(BaseModel):
    permission_ids: list[StrictInt] = Field(default_factory=list, max_length=500)


# -----------------------------------------------------------------------------
# Frameworks
# -----------------------------------------------------------------------------


class FrameworkCreatePayload(BaseModel):
    machine_name: str = Field(min_length=1, max_length=160)
    display_name: str = Field(min_length=1, max_length=200)
    description: str | None = None


class FrameworkUpdatePayload(BaseModel):
    machine_name: str | None = Field(default=None, min_length=1, max_length=160)
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None


class FrameworkNodeCreatePayload(BaseModel):
    key: str = Field(min_length=1, max_length=160)
    display_name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    parent_id: int | None = None
    sort_order: int | None = 0


class FrameworkNodeUpdatePayload(BaseModel):
    key: str | None = Field(default=None, min_length=1, max_length=160)
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    parent_id: int | None = None
    sort_order: int | None = None


# -----------------------------------------------------------------------------
# Projects
# -----------------------------------------------------------------------------


class ReleaseFeedIgnorePatternPayload(BaseModel):
    """A per-project rule for suppressing release-feed draft creation."""

    match_type: str = Field(default="contains", max_length=20)
    pattern: str = Field(min_length=1, max_length=MAX_PATTERN_CHARS)
    case_sensitive: bool = False

    @model_validator(mode="before")
    @classmethod
    def _normalise_input(cls, value: Any):
        if isinstance(value, str):
            raw = value.strip()
            if raw.lower().startswith("regex:"):
                return {"match_type": "regex", "pattern": raw[6:].strip()}
            if raw.lower().startswith("contains:"):
                return {"match_type": "contains", "pattern": raw[9:].strip()}
            return {"match_type": "contains", "pattern": raw}
        if isinstance(value, dict):
            out = dict(value)
            if "match_type" not in out and "type" in out:
                out["match_type"] = out.get("type")
            return out
        return value

    @field_validator("match_type", mode="before")
    @classmethod
    def _normalise_match_type(cls, value):
        s = str(value or "contains").strip().lower()
        aliases = {
            "simple": "contains",
            "string": "contains",
            "substring": "contains",
            "contains": "contains",
            "regex": "regex",
            "regexp": "regex",
            "regular_expression": "regex",
        }
        if s not in aliases:
            raise ValueError("match_type must be 'contains' or 'regex'")
        return aliases[s]

    @field_validator("pattern", mode="before")
    @classmethod
    def _normalise_pattern(cls, value):
        s = str(value or "").strip()
        if not s:
            raise ValueError("pattern must not be empty")
        return s

    @model_validator(mode="after")
    def _validate_regex(self):
        if self.match_type == "regex":
            flags = 0 if self.case_sensitive else re.IGNORECASE
            try:
                compile_supplied_pattern(self.pattern, flags)
            except re.error as exc:
                raise ValueError(f"invalid regex pattern: {exc}") from exc
        return self


def clean_release_feed_ignore_patterns(
    values: list[ReleaseFeedIgnorePatternPayload | dict[str, Any] | str] | None,
) -> list[dict[str, Any]]:
    """Return canonical JSON-safe release-feed ignore pattern objects."""

    if not values:
        return []

    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, bool]] = set()
    for raw in values:
        item = (
            raw
            if isinstance(raw, ReleaseFeedIgnorePatternPayload)
            else ReleaseFeedIgnorePatternPayload.model_validate(raw)
        )
        dedupe_pattern = item.pattern if item.case_sensitive else item.pattern.lower()
        key = (item.match_type, dedupe_pattern, bool(item.case_sensitive))
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "match_type": item.match_type,
                "pattern": item.pattern,
                "case_sensitive": bool(item.case_sensitive),
            }
        )
    return out


class ProjectCreatePayload(BaseModel):
    machine_name: str = Field(min_length=1, max_length=160)
    display_name: str = Field(min_length=1, max_length=200)

    organisation: str | None = Field(default=None, max_length=200)
    organisation_id: int | None = None
    project_type: str | None = Field(default=None, max_length=120)
    license: str | None = Field(default=None, max_length=120)

    programming_languages: list[str] | None = None

    capability: str | None = Field(default=None, max_length=200)
    link_to_app: str | None = None

    # Optional RSS/Atom feed for releases (e.g. GitHub releases feed).
    release_rss_feed_url: str | None = None
    release_rss_ignore_patterns: list[ReleaseFeedIgnorePatternPayload] | None = None

    # Branch tracking: follow one branch head, re-scanned on an interval of
    # at least an hour, instead of following releases.
    track_branch: bool | None = None
    tracked_repo_url: str | None = Field(default=None, max_length=600)
    tracked_branch: str | None = Field(default=None, max_length=64)
    branch_poll_interval_hours: int | None = Field(
        default=None, ge=MIN_POLL_INTERVAL_HOURS, le=MAX_POLL_INTERVAL_HOURS
    )
    # A private repository: clones authenticate with this write-only token,
    # sent only over HTTPS to repo_token_host. An empty token keeps the saved
    # one; turning repo_private off deletes it.
    repo_private: bool | None = None
    repo_token: str | None = Field(default=None, max_length=MAX_TOKEN_CHARS, repr=False)
    repo_token_host: str | None = Field(default=None, max_length=255)
    repo_token_username: str | None = Field(default=None, max_length=100)
    supported_profiles: list[str] | None = None
    supported_formats: list[str] | None = None

    supported_issuance_protocols: list[str] | None = None
    supported_key_managements: list[str] | None = None
    supported_presentation_protocols: list[str] | None = None
    supported_signing_algorithms: list[str] | None = None

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_company_field(cls, data):
        # Accept pre-rename API clients during rollout, but store and emit
        # only the renamed organisation field.
        if isinstance(data, dict) and "organisation" not in data and "company" in data:
            data = dict(data)
            data["organisation"] = data.get("company")
        return data

    @field_validator("project_type", mode="before")
    @classmethod
    def _validate_project_type(cls, v):
        from app.services.catalog import PROJECT_TYPES

        candidate = (str(v or "") or "").strip().lower()
        if not candidate:
            return None
        if candidate not in PROJECT_TYPES:
            raise ValueError("project_type must be one of: " + ", ".join(PROJECT_TYPES))
        return candidate

    @field_validator("link_to_app", mode="before")
    @classmethod
    def _validate_link_to_app(cls, v):
        if v is None:
            return None
        s = str(v or "").strip()
        if not s:
            return None
        # Allow same-origin relative links; block javascript:/data: URLs.
        return validate_safe_href(s, allow_relative=True)

    @field_validator("release_rss_feed_url", mode="before")
    @classmethod
    def _validate_release_rss_feed_url(cls, v):
        if v is None:
            return None
        s = str(v or "").strip()
        if not s:
            return None
        # This URL is fetched server-side by the release feed poller; keep it public.
        return validate_public_http_url(s)

    @field_validator("tracked_repo_url", mode="before")
    @classmethod
    def _validate_tracked_repo_url(cls, v):
        return _optional_repo_url(v)

    @field_validator("repo_token", mode="before")
    @classmethod
    def _validate_repo_token(cls, v):
        return clean_token(v if v is None else str(v))

    @field_validator("repo_token_host", mode="before")
    @classmethod
    def _validate_repo_token_host(cls, v):
        host = clean_host(v if v is None else str(v))
        if host is not None:
            # The same host allowlist as every clone.
            validate_repo_url(f"https://{host}/")
        return host

    @field_validator("repo_token_username", mode="before")
    @classmethod
    def _validate_repo_token_username(cls, v):
        return clean_username(v if v is None else str(v))

    @field_validator("tracked_branch", mode="before")
    @classmethod
    def _validate_tracked_branch(cls, v):
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        return validate_git_ref_name(s)

    @field_validator("release_rss_ignore_patterns", mode="before")
    @classmethod
    def _validate_release_rss_ignore_patterns(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            return [line.strip() for line in v.splitlines() if line.strip()]
        return v

    @field_validator(
        "supported_profiles",
        "supported_formats",
        "supported_issuance_protocols",
        "supported_key_managements",
        "supported_presentation_protocols",
        "supported_signing_algorithms",
        "programming_languages",
        mode="before",
    )
    @classmethod
    def _normalize_list(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return _clean_tag_list(list(v))


class ProjectUpdatePayload(ProjectCreatePayload):
    machine_name: str | None = Field(  # type: ignore[assignment]
        default=None, min_length=1, max_length=160
    )
    display_name: str | None = Field(  # type: ignore[assignment]
        default=None, min_length=1, max_length=200
    )


class ProjectSubscriptionUpdatePayload(BaseModel):
    # Subscription preferences. If both are false, the subscription is removed.
    notify_new_versions: bool | None = None
    notify_questions: bool | None = None


class ProjectVersionCreatePayload(BaseModel):
    version: str = Field(min_length=1, max_length=64)
    release_date: datetime | None = None
    status: str | None = Field(default=None, max_length=120)
    link_to_source_code: str | None = None
    notes: str | None = Field(default=None, max_length=20000)
    is_latest: bool | None = None
    is_draft: bool | None = None

    @field_validator("link_to_source_code", mode="before")
    @classmethod
    def _validate_link_to_source_code(cls, v):
        return _optional_repo_url(v)


class ProjectVersionUpdatePayload(BaseModel):
    version: str | None = Field(default=None, min_length=1, max_length=64)
    release_date: datetime | None = None
    status: str | None = Field(default=None, max_length=120)
    link_to_source_code: str | None = None
    notes: str | None = Field(default=None, max_length=20000)
    is_latest: bool | None = None
    is_draft: bool | None = None

    @field_validator("link_to_source_code", mode="before")
    @classmethod
    def _validate_link_to_source_code(cls, v):
        return _optional_repo_url(v)


class ProjectVersionFrameworkNodesPayload(BaseModel):
    framework_id: int
    node_ids: list[int] = Field(default_factory=list)

    @field_validator("node_ids", mode="before")
    @classmethod
    def _normalize_ids(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [int(x) for x in v.split(",") if x.strip()]
        return [int(x) for x in v]


# -----------------------------------------------------------------------------
# Manifests
# -----------------------------------------------------------------------------


class ManifestCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    q: str | None = None
    framework_id: int | None = None
    node_ids: list[int] = Field(default_factory=list)
    project_ids: list[int] = Field(default_factory=list)
    owner_group_id: int | None = None


class ManifestSharingUpdatePayload(BaseModel):
    # If set to True, everyone with manifest access can view/export this manifest.
    is_public: bool | None = None
    # If set, share with a group the user is a member of. If explicitly null, unshare.
    owner_group_id: int | None = None


class ManifestClonePayload(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = None


class UserPreferencesUpdatePayload(BaseModel):
    node_colors: dict | None = None
    default_start_page: str | None = None
    sticky_enabled: bool | None = None
    auto_apply_enabled: bool | None = None
    theme: str | None = Field(default=None, max_length=16)


class UserShortcutCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=4000)

    @field_validator("url", mode="before")
    @classmethod
    def _validate_url(cls, v):
        s = str(v or "").strip()
        if not s:
            return s
        return validate_safe_href(s, allow_relative=True)


# -----------------------------------------------------------------------------
# Questions
# -----------------------------------------------------------------------------


class ProjectQuestionCreatePayload(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class ProjectQuestionReplyPayload(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class AdminProjectOwnershipPayload(BaseModel):
    owner_user_id: int | None = Field(default=None, ge=1)
    owner_group_ids: list[int] | None = None


class OrganisationPayload(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = None
    website: str | None = None


class OrganisationMemberPayload(BaseModel):
    user_id: int | None = None
    group_id: int | None = None
    role: str | None = Field(default=None, max_length=50)
