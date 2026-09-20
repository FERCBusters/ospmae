from __future__ import annotations

from typing import Any

try:
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover - packaging is normally available transitively
    InvalidVersion = ValueError
    Version = None


def _normalise_release_version(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""

    lowered = candidate.lower()
    if lowered.startswith("release "):
        candidate = candidate[8:].strip()
    if "·" in candidate:
        candidate = candidate.split("·", 1)[0].strip()
    if candidate.startswith(("v", "V")) and len(candidate) > 1:
        candidate = candidate[1:]
    return candidate.strip()


def parse_semanticish_version(value: Any):
    """Parse semver-like release labels used by Git release feeds and forms.

    Returns a comparable object when the value is parseable, otherwise None.
    This deliberately refuses fuzzy values rather than guessing, because an
    unsafe guess can incorrectly promote an older release to Latest.
    """

    candidate = _normalise_release_version(value)
    if not candidate:
        return None

    if Version is not None:
        try:
            return Version(candidate)
        except InvalidVersion:
            return None

    parts: list[int] = []
    for piece in candidate.replace("-", ".").split("."):
        piece = piece.strip()
        if not piece:
            continue
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    return tuple(parts) if parts else None


def compare_semanticish_versions(candidate: Any, current: Any) -> int | None:
    """Compare two semantic-ish versions.

    Returns 1 when candidate > current, 0 when equal, -1 when candidate < current,
    and None when either side cannot be parsed safely.
    """

    cand = parse_semanticish_version(candidate)
    cur = parse_semanticish_version(current)
    if cand is None or cur is None:
        return None
    if cand > cur:
        return 1
    if cand < cur:
        return -1
    return 0


def is_semantically_newer(candidate: Any, current: Any) -> bool | None:
    comparison = compare_semanticish_versions(candidate, current)
    if comparison is None:
        return None
    return comparison > 0


def is_semantically_lower(candidate: Any, current: Any) -> bool | None:
    comparison = compare_semanticish_versions(candidate, current)
    if comparison is None:
        return None
    return comparison < 0
