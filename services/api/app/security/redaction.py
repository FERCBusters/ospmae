from __future__ import annotations

from functools import lru_cache
from urllib.parse import parse_qsl, urlencode
import os

REDACTED = "REDACTED"

DEFAULT_SENSITIVE_KEYS: set[str] = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "client_secret",
    "signature",
    "auth",
    "authorization",
    "password",
    "cookie",
}


def _normalise_key(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _parse_env_keys(raw: str) -> set[str]:
    return {_normalise_key(part) for part in raw.replace(",", " ").split() if part}


@lru_cache(maxsize=1)
def _sensitive_keys() -> tuple[set[str], tuple[str, ...]]:
    mode = (os.getenv("OSPMAE_SENSITIVE_KEYS_MODE") or "extend").strip().lower()
    env_keys = _parse_env_keys(os.getenv("OSPMAE_SENSITIVE_KEYS") or "")
    if mode in {"replace", "override", "only"}:
        keys = env_keys
    else:
        keys = {_normalise_key(k) for k in DEFAULT_SENSITIVE_KEYS} | env_keys
    needles = tuple(sorted({k for k in keys if len(k) >= 5}, key=len, reverse=True))
    return keys, needles


def is_sensitive_key(value: str) -> bool:
    key = _normalise_key(value)
    keys, needles = _sensitive_keys()
    if key in keys:
        return True
    return any(needle in key for needle in needles)


def redact_query_string(qs: str | None) -> str | None:
    if not qs:
        return None
    try:
        parts: list[tuple[str, str]] = []
        changed = False
        for key, value in parse_qsl(qs, keep_blank_values=True):
            if isinstance(key, str) and value and is_sensitive_key(key):
                parts.append((key, REDACTED))
                changed = True
            else:
                parts.append((key, value))
        out = urlencode(parts, doseq=True)
        return out if changed or out != qs else qs
    except Exception:
        return qs
