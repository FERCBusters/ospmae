from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.depscan.scan import validate_repo_url
from app.security.url_safety import validate_public_http_url, validate_safe_href


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


class PasswordResetRequestPayload(BaseModel):
    identifier: str = Field(min_length=1, max_length=255)


class PasswordResetConfirmPayload(BaseModel):
    token: str = Field(min_length=10, max_length=512)
    new_password: str = Field(min_length=8, max_length=200)
    confirm_password: str = Field(min_length=8, max_length=200)


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
    role: str | None = Field(default=None, max_length=50)


class AdminGroupUpdatePayload(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    role: str | None = Field(default=None, max_length=50)


class AdminUserAccessUpdatePayload(BaseModel):
    group_ids: list[int] | None = None
    permission_ids: list[int] | None = None


class AdminGroupPermissionsUpdatePayload(BaseModel):
    permission_ids: list[int] | None = None


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
    pattern: str = Field(min_length=1, max_length=800)
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
                re.compile(self.pattern, flags=flags)
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
        if v is None:
            return None
        s = str(v or "").strip()
        if not s:
            return None
        # Must be a supported git URL and on an allowed host.
        validate_repo_url(s)
        return s


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
        if v is None:
            return None
        s = str(v or "").strip()
        if not s:
            return None
        # Must be a supported git URL and on an allowed host.
        validate_repo_url(s)
        return s


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


class MeProfileUpdatePayload(BaseModel):
    email: str | None = Field(default=None, max_length=255)


class UserEmailCreatePayload(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    is_primary: bool = False


class EmailVerifyPayload(BaseModel):
    token: str = Field(default="", max_length=200)


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
