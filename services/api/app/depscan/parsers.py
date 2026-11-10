from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


@dataclass(frozen=True)
class DiscoveredDependency:
    ecosystem: str
    name: str
    version: str
    is_indirect: bool
    source_file: str


_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")


def redact_url(value: str) -> str:
    """Mask userinfo credentials inside URL-shaped text for error output."""

    return _CRED_RE.sub(r"\1***:***@", str(value or ""))


def _bounded_read(path: Path, max_bytes: int) -> bytes | None:
    """Read at most ``max_bytes`` of a file, checking its size first.

    All parser cost grows with input size, so the byte cap is applied before
    anything is read: a multi-gigabyte file costs a stat call, not memory.
    """

    try:
        stat = path.stat()
    except OSError:
        return None
    if not stat.st_size or stat.st_size > max_bytes:
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _norm_name(name: Any) -> str:
    return str(name or "").strip()


def parse_package_lock(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    data = json.loads(raw.decode("utf-8", errors="replace") or "{}")
    out: list[DiscoveredDependency] = []

    root_direct = set()
    if isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
        root_direct = set(data["dependencies"].keys())

    # npm v7+: packages map has full transitive tree.
    packages = data.get("packages") if isinstance(data, dict) else None
    if isinstance(packages, dict) and packages:
        # Lockfiles 2 and 3 list the project's own dependencies on its root
        # package entry; everything else is installed for them.
        root = packages.get("")
        if isinstance(root, dict):
            root_direct = set()
            for field in ("dependencies", "devDependencies", "optionalDependencies"):
                if isinstance(root.get(field), dict):
                    root_direct.update(root[field])
        for k, v in packages.items():
            if k in ("", None):
                continue
            if not isinstance(k, str) or not k.startswith("node_modules/"):
                continue
            # A nested install ("node_modules/a/node_modules/b") is package b.
            name = k.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            version = ""
            if isinstance(v, dict):
                version = str(v.get("version") or "")
            if not version:
                continue
            is_indirect = name not in root_direct
            out.append(
                DiscoveredDependency("npm", name, version, is_indirect, str(path))
            )
        return out

    # Fallback: top-level dependencies only.
    deps = data.get("dependencies") if isinstance(data, dict) else None
    if isinstance(deps, dict):
        for name, meta in deps.items():
            version = ""
            if isinstance(meta, dict):
                version = str(meta.get("version") or "")
            if not version:
                continue
            out.append(
                DiscoveredDependency("npm", str(name), version, False, str(path))
            )
    return out


_YARN_KEY_RE = re.compile(r"^(?P<key>.+):\s*$")
# Yarn 1 writes `version "1.2.3"`; Yarn 2 and later write `version: 1.2.3`.
_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?(?P<ver>[^"\s]+)"?\s*$')
_YARN_NAME_RE = re.compile(r"^(?P<name>@[^/]+/[^@]+|[^@]+)@")


def parse_yarn_lock(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    text = raw.decode("utf-8", errors="replace")
    out: list[DiscoveredDependency] = []

    current_names: list[str] = []
    for line in text.splitlines():
        m = _YARN_KEY_RE.match(line)
        if m:
            key = m.group("key").strip().strip('"')
            parts = [p.strip().strip('"') for p in key.split(",")]
            names: set[str] = set()
            for p in parts:
                mm = _YARN_NAME_RE.match(p)
                if mm:
                    names.add(mm.group("name"))
            current_names = sorted(names)
            continue

        m = _YARN_VERSION_RE.match(line)
        if m and current_names:
            ver = m.group("ver").strip()
            for name in current_names:
                out.append(DiscoveredDependency("npm", name, ver, True, str(path)))
            current_names = []
    return out


def parse_pnpm_lock(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    if yaml is None:
        return []
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    data = yaml.safe_load(raw.decode("utf-8", errors="replace"))
    out: list[DiscoveredDependency] = []
    if not isinstance(data, dict):
        return out
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return out
    for key in packages:
        if not isinstance(key, str):
            continue
        parsed = _pnpm_package_key(key)
        if parsed:
            out.append(DiscoveredDependency("npm", *parsed, True, str(path)))
    return out


_PNPM_V5_KEY = re.compile(r"^(?P<name>(?:@[^/@]+/)?[^/@]+)/(?P<ver>[^/_]+)(?:_.*)?$")


def _pnpm_package_key(key: str) -> tuple[str, str] | None:
    """The name and version a pnpm lockfile package key names.

    Lockfile 5 writes "/react/18.2.0" (peer suffixes after "_"); lockfiles 6
    and 9 write "/react@18.2.0" and "react@18.2.0" (peer suffixes in brackets).
    Scoped names keep their leading "@".
    """
    key = key.lstrip("/")
    v5 = _PNPM_V5_KEY.match(key)
    if v5:
        return v5.group("name"), v5.group("ver")
    key = key.split("(", 1)[0]
    at = key.rfind("@")
    if at <= 0 or at == len(key) - 1:
        return None
    return key[:at], key[at + 1 :]


def parse_cargo_lock(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    data = tomllib.loads(raw.decode("utf-8", errors="replace"))
    out: list[DiscoveredDependency] = []
    pkgs = data.get("package")
    if isinstance(pkgs, list):
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = _norm_name(pkg.get("name"))
            ver = _norm_name(pkg.get("version"))
            if name and ver:
                out.append(DiscoveredDependency("cargo", name, ver, True, str(path)))
    return out


def parse_poetry_lock(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    data = tomllib.loads(raw.decode("utf-8", errors="replace"))
    out: list[DiscoveredDependency] = []
    pkgs = data.get("package")
    if isinstance(pkgs, list):
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = _norm_name(pkg.get("name"))
            ver = _norm_name(pkg.get("version"))
            if name and ver:
                out.append(DiscoveredDependency("python", name, ver, True, str(path)))
    return out


def parse_pipfile_lock(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    data = json.loads(raw.decode("utf-8", errors="replace") or "{}")
    out: list[DiscoveredDependency] = []
    for section_name in ("default", "develop"):
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        for name, meta in section.items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version") or "").strip()
            ver = ver.lstrip("=")
            if name and ver:
                out.append(
                    DiscoveredDependency(
                        "python", str(name), ver, section_name == "develop", str(path)
                    )
                )
    return out


_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.\-]+)(?P<spec>\[.*?\])?(?P<op>==|>=|<=|~=|!=|>|<)?(?P<ver>.*)?$"
)


def parse_requirements_txt(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    out: list[DiscoveredDependency] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            # -r, -e, --find-links, etc.
            continue
        if "git+" in s or "://" in s:
            continue
        m = _REQ_RE.match(s)
        if not m:
            continue
        name = _norm_name(m.group("name"))
        op = (m.group("op") or "").strip()
        ver = (m.group("ver") or "").strip()
        ver = ver.split(";")[0].strip()  # strip markers
        version = (op + ver).strip() if ver else ""
        if name:
            out.append(DiscoveredDependency("python", name, version, False, str(path)))
    return out


def parse_go_mod(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    text = raw.decode("utf-8", errors="replace")
    out: list[DiscoveredDependency] = []

    in_require_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or not stripped:
            continue
        if stripped.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and stripped == ")":
            in_require_block = False
            continue
        if stripped.startswith("require "):
            stripped = stripped[len("require ") :].strip()
        elif not in_require_block:
            continue

        # Now line should be: <module> <version> [// indirect]
        parts = stripped.split()
        if len(parts) < 2:
            continue
        mod = parts[0]
        ver = parts[1]
        is_indirect = "indirect" in stripped
        if mod and ver:
            out.append(DiscoveredDependency("go", mod, ver, is_indirect, str(path)))
    return out


def parse_go_sum(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    out: list[DiscoveredDependency] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        mod = parts[0]
        ver = parts[1]
        ver = ver.replace("/go.mod", "")
        if mod and ver:
            out.append(DiscoveredDependency("go", mod, ver, True, str(path)))
    return out


def parse_composer_lock(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    raw = _bounded_read(path, max_bytes)
    if raw is None:
        return []
    data = json.loads(raw.decode("utf-8", errors="replace") or "{}")
    out: list[DiscoveredDependency] = []
    for key in ("packages", "packages-dev"):
        pkgs = data.get(key)
        if not isinstance(pkgs, list):
            continue
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = _norm_name(pkg.get("name"))
            ver = _norm_name(pkg.get("version"))
            if name and ver:
                out.append(
                    DiscoveredDependency(
                        "composer", name, ver, key == "packages-dev", str(path)
                    )
                )
    return out


def parse_lockfile(path: Path, *, max_bytes: int) -> list[DiscoveredDependency]:
    name = path.name

    try:
        if name == "package-lock.json":
            return parse_package_lock(path, max_bytes=max_bytes)
        if name == "yarn.lock":
            return parse_yarn_lock(path, max_bytes=max_bytes)
        if name == "pnpm-lock.yaml":
            return parse_pnpm_lock(path, max_bytes=max_bytes)
        if name == "Cargo.lock":
            return parse_cargo_lock(path, max_bytes=max_bytes)
        if name == "poetry.lock":
            return parse_poetry_lock(path, max_bytes=max_bytes)
        if name == "Pipfile.lock":
            return parse_pipfile_lock(path, max_bytes=max_bytes)
        if name == "requirements.txt":
            return parse_requirements_txt(path, max_bytes=max_bytes)
        if name == "go.mod":
            return parse_go_mod(path, max_bytes=max_bytes)
        if name == "go.sum":
            return parse_go_sum(path, max_bytes=max_bytes)
        if name == "composer.lock":
            return parse_composer_lock(path, max_bytes=max_bytes)
    except Exception:
        # Best-effort parsing; skip if malformed.
        return []

    return []


SUPPORTED_LOCKFILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "go.mod",
    "go.sum",
    "composer.lock",
}


def is_supported_lockfile(path: Path) -> bool:
    return path.name in SUPPORTED_LOCKFILES
