"""Catalog vocabulary: controlled project types and organisation types.

Free-text classification lets duplicates and stray spellings accumulate:
a filter "identity" never matches "Identity Infrastructure". Project types
are a server-controlled list, so the whole catalogue classifies the same
way even before organisations exist.
"""

from __future__ import annotations

from fastapi import HTTPException

PROJECT_TYPES = (
    "ledger",
    "identity",
    "wallet",
    "credentials",
    "interoperability",
    "privacy",
    "cryptography",
    "governance",
    "tooling",
    "library",
    "application",
    "service",
    "other",
)

PROJECT_TYPE_CHOICES = list(PROJECT_TYPES)


def normalize_project_type(value: str | None) -> str | None:
    """Normalise a project type, refusing values outside the catalogue list."""
    candidate = (value or "").strip().lower()
    if not candidate:
        return None
    if candidate in PROJECT_TYPES:
        return candidate
    raise HTTPException(
        status_code=400,
        detail="project_type must be one of: " + ", ".join(PROJECT_TYPES),
    )


def organisation_display_name(name: str | None) -> str | None:
    trimmed = (name or "").strip()
    return trimmed or None
