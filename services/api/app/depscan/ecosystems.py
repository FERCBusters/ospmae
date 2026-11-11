"""Ecosystem names shared by the Syft inventory and Grype findings."""

from __future__ import annotations

ECOSYSTEM_MAP = {
    # Keep OSPMAE's previous ecosystem names for existing lockfile-backed data.
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "javascript": "npm",
    "node": "npm",
    "nodejs": "npm",
    "python": "python",
    "python-pkg": "python",
    "pypi": "python",
    "go": "go",
    "go-module": "go",
    "go-module-binary": "go",
    "golang": "go",
    "cargo": "cargo",
    "rust-crate": "cargo",
    "rust": "cargo",
    "composer": "composer",
    "php-composer": "composer",
    "php-composer-installed": "composer",
    "php": "composer",
}


def purl_type(purl: str) -> str:
    """The package type a package URL names ("pkg:npm/x@1" is "npm")."""
    package_url = str(purl or "").strip().lower()
    if not package_url.startswith("pkg:"):
        return ""
    rest = package_url[4:]
    return rest.split("/", 1)[0].split(":", 1)[0].strip()


def clean_ecosystem(value: str) -> str | None:
    clean = str(value or "").strip().lower().replace("_", "-")
    if not clean:
        return None
    clean = ECOSYSTEM_MAP.get(clean, clean)
    # dependency_packages.ecosystem is varchar(32). Keep raw Syft/Grype types
    # such as java-archive and gem, but guard against future verbose labels.
    return clean[:32]


def ecosystem(*candidates: str | None) -> str | None:
    """The first usable ecosystem among a package type, PURL type or language.

    Syft and Grype report the same package types, so preferring the concrete
    type lets vulnerability rows join back to the dependency inventory.
    """
    for value in candidates:
        eco = clean_ecosystem(str(value or ""))
        if eco:
            return eco
    return None
