"""Catalog vocabulary: controlled project types and organisation types.

Free-text classification lets duplicates and stray spellings accumulate:
a filter "identity" never matches "Identity Infrastructure". Project types
are a server-controlled list, so the whole catalogue classifies the same
way even before organisations exist.
"""

from __future__ import annotations

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
